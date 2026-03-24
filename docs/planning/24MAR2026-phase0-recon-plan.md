# Phase 0: Reconnaissance & Research Plan

## Objective

Map the GPU firmware attack surface without writing any exploit code. Produce a
comprehensive architecture document, identify writable regions, and determine
persistence characteristics. The end goal is to understand whether code can live
and persist inside GPU firmware — even a "hello world" — as proof that this
attack surface is real and needs vendor attention.

---

## Research Questions

1. **What is writable?** Which regions of GPU VRAM, firmware flash, or config
   space can be modified from the host, from the GPU's own execution context, or
   via DMA?
2. **What survives?** Do modifications persist across driver reload? Suspend/resume?
   Full reboot?
3. **What executes?** Can injected code achieve execution on the GPU's management
   processor (GSP/PMU/SEC2)?
4. **What detects it?** What forensic artifacts would a GPU firmware implant leave?

---

## Target Hardware

| Target | GPU | Architecture | GSP Processor | Priority |
|--------|-----|-------------|---------------|----------|
| Primary | RTX 4070/4080/4090 | Ada Lovelace (AD10x) | RISC-V based GSP | HIGH |
| Secondary | RTX 3060/3070/3080 | Ampere (GA10x) | Falcon-based GSP | MEDIUM |
| Tertiary | AMD RX 7000 series | RDNA 3 | AMD PSP equivalent | LOW |
| Tertiary | Intel Arc A-series | Alchemist | Intel GuC/HuC | LOW |

**Why NVIDIA first:** The Nouveau project and NVIDIA's open-source kernel modules
(released 2022+) provide the most public documentation. The GSP runs a full RTOS
(NVRM-based) handling power management, display, and security policy.

**Lab setup recommendation:** Use a secondary/cheap GPU (RTX 3050 ~$150 used) for
any destructive testing. Keep primary GPU for development/display.

---

## Required Tools & Dependencies

### Software Requirements

| Tool | Purpose | Install |
|------|---------|---------|
| **Ghidra** (≥11.0) | Firmware disassembly/RE | ghidra-sre.org |
| **rizin/radare2** | Binary triage, quick analysis | `apt install rizin` |
| **binwalk** | Firmware blob structure analysis | `apt install binwalk` |
| **envytools** | NVIDIA register docs, ISA docs, rnndb | Build from source (github) |
| **Python 3.10+** | Scripting, tooling | System package |
| **pciutils** | PCI BAR enumeration | `apt install pciutils` |
| **NVIDIA open-source kernel modules** | GSP RPC reference | Clone from GitHub |
| **Linux kernel source** | Nouveau driver reference | kernel.org |

### Python Dependencies

```
# requirements.txt
pycparser>=2.21          # C header parsing for RPC struct extraction
construct>=2.10          # Binary structure parsing
capstone>=5.0            # Disassembly engine
unicorn>=2.0             # CPU emulation (Falcon/RISC-V)
pyelftools>=0.29         # ELF parsing for firmware blobs
hexdump>=3.3             # Hex dump utilities
rich>=13.0               # Terminal output formatting
click>=8.0               # CLI framework
```

### Hardware Requirements

- NVIDIA GPU (Ada Lovelace preferred, Ampere acceptable)
- Linux system with root access
- Ability to load/unload NVIDIA kernel modules
- Secondary GPU or integrated graphics for display (so test GPU can be fully
  controlled)

---

## Task Breakdown

### Task 0.1: Source Code Study — NVIDIA Open-Source Kernel Modules

**Goal:** Understand how the host driver communicates with the GSP.

**Key directories to study:**
```
open-gpu-kernel-modules/
├── src/nvidia/
│   ├── inc/kernel/gpu/gsp/      # GSP interface definitions
│   │   ├── gsp_init_args.h      # GSP boot parameters
│   │   ├── gsp_fw_heap.h        # Firmware heap management
│   │   └── gsp_static_config.h  # Static configuration
│   ├── src/kernel/gpu/gsp/      # GSP implementation
│   │   ├── kernel_gsp.c         # Core GSP management
│   │   └── arch/               # Architecture-specific GSP code
│   ├── inc/kernel/gpu/falcon/   # Falcon microcontroller defs
│   └── inc/kernel/gpu/sec2/     # SEC2 engine definitions
├── src/nvidia/arch/nvalloc/unix/
│   └── src/os-interface.c       # OS abstraction layer
└── kernel-open/                 # Open-source kernel module
    └── nvidia/                  # GPL-compatible driver layer
```

**Deliverables:**
- [ ] GSP RPC message catalog (command IDs, parameter structures)
- [ ] GSP boot sequence documentation
- [ ] GSP memory map (shared memory regions, mailbox registers)
- [ ] Firmware authentication mechanism documentation

### Task 0.2: Source Code Study — Nouveau Driver (Linux Kernel)

**Goal:** Understand the open-source GSP interaction pathway.

**Key files:**
```
drivers/gpu/drm/nouveau/
├── nvkm/subdev/gsp/         # GSP subdevice implementation
│   ├── r535.c               # NVIDIA 535.x firmware interface
│   └── gsp.c                # Core GSP management
├── nvkm/subdev/pmu/         # PMU (Performance Monitoring Unit)
├── nvkm/engine/falcon.c     # Falcon microcontroller engine
├── nvkm/subdev/bar/         # BAR management
└── include/nvkm/subdev/gsp.h
```

**Deliverables:**
- [ ] Firmware blob loading sequence (how .bin → GSP)
- [ ] GSP messaging protocol documentation
- [ ] Comparison with NVIDIA proprietary driver GSP interface

### Task 0.3: Firmware Blob Extraction & Triage

**Goal:** Extract and characterize GSP firmware binaries.

**Firmware locations:**
```
# NVIDIA driver package
/lib/firmware/nvidia/<version>/gsp_ga10x.bin     # Ampere GSP firmware
/lib/firmware/nvidia/<version>/gsp_ad10x.bin     # Ada Lovelace GSP firmware

# Alternative locations
/usr/lib/firmware/nvidia/
nvidia-firmware-*-*.rpm (Fedora/RHEL)
```

**Analysis steps:**
1. `binwalk` for structure identification (headers, embedded files, crypto)
2. `strings` for string tables, version info, debug messages
3. Identify CPU architecture markers (RISC-V magic, Falcon opcodes)
4. Look for signature/hash verification structures
5. Load into Ghidra with appropriate processor module
6. Map code sections, data sections, BSS

**Deliverables:**
- [ ] Firmware blob format documentation
- [ ] Memory layout (load address, entry point, section map)
- [ ] Identified cryptographic constants (keys, hashes, signatures)
- [ ] Architecture confirmation (RISC-V vs Falcon per GPU generation)

### Task 0.4: PCI BAR Region Mapping

**Goal:** Document what host-accessible memory regions exist on the GPU.

**Methodology:**
```bash
# Enumerate BARs
lspci -vvv -s <GPU_BDF>

# Typical NVIDIA BAR layout:
# BAR0: Registers (MMIO) — GPU control registers, ~16-32MB
# BAR1: VRAM aperture — Direct VRAM access window, up to 256MB
# BAR2/3: Additional register space or I/O ports (varies by GPU)
```

**Specific investigations:**
- Which BAR0 register ranges are writable from userspace?
- Can BAR1 (VRAM) writes reach firmware-used memory regions?
- Are there undocumented register regions not covered by envytools?
- What protections exist (IOMMU, GPU MMU, access control)?

**Tool:** `tools/bar-mapper/` — Custom tool to systematically probe BAR regions

**Deliverables:**
- [ ] Complete BAR layout map with read/write characteristics
- [ ] Identified regions used by GSP firmware
- [ ] Documented access restrictions and bypass potential

### Task 0.5: VRAM Persistence Testing

**Goal:** Determine what survives across various state transitions.

**Test matrix:**

| Test | Write Pattern | Trigger | Check Survival |
|------|--------------|---------|----------------|
| Driver reload | Magic bytes to VRAM | `rmmod nvidia && modprobe nvidia` | Read back via BAR1 |
| D3 power state | Magic bytes to VRAM | `echo auto > /sys/bus/pci/devices/.../power/control` | Read back |
| Suspend/resume | Magic bytes to VRAM | `systemctl suspend` | Read back after resume |
| Warm reboot | Magic bytes to VRAM | `reboot` | Read back after boot |
| Cold boot | Magic bytes to VRAM | Power off, power on | Read back after boot |

**Tool:** `tools/vram-persistence/` — Automated persistence testing suite

**Deliverables:**
- [ ] Persistence matrix (what survives what)
- [ ] Identified "safe" VRAM regions not cleared by driver init
- [ ] Timing characteristics (when are regions cleared?)

### Task 0.6: Prior Art Survey

**Goal:** Catalog all existing GPU security research.

**Key references:**
1. Vasiliadis et al. (2010) — "GPU-Assisted Malware" — CUDA-based, host-side only
2. "Jellyfish" (2015) — VRAM-resident rootkit PoC, no firmware persistence
3. Zhu et al. — "GPU Security Vulnerabilities" — Survey paper
4. NVIDIA Confidential Computing whitepapers — What they protect, what they don't
5. AMD SEV-SNP with GPU passthrough research
6. Intel TDX GPU security model
7. Sangho Lee et al. — "Hacking in Darkness" — GPU-based keylogger
8. Any recent DEFCON/BlackHat/CCC talks on GPU security

**Deliverables:**
- [ ] Annotated bibliography
- [ ] Gap analysis: what's been done vs. what hasn't
- [ ] Key takeaways for our approach

---

## Project Requirements

### Development Environment

```bash
# Base system
Ubuntu 22.04+ or Fedora 38+ (recent kernel with good NVIDIA support)
Linux kernel 6.1+ (for Nouveau GSP support)

# NVIDIA driver versions to study
535.x series — First with significant open-source GSP code
545.x series — Current stable
550.x+ — Latest

# Build essentials
gcc, make, linux-headers (for kernel module development)
python3, pip, venv
```

### Safety Protocols

1. **Dedicated test GPU** — Never test destructive operations on your display GPU
2. **VM isolation** — Use VFIO GPU passthrough for initial testing where possible
3. **Firmware backups** — Dump VBIOS/firmware before any write experiments
4. **Recovery plan** — Know how to reflash GPU firmware via SPI if bricked
5. **Version control everything** — All scripts, tools, notes, findings

### Responsible Disclosure Plan

- All findings to be reported to NVIDIA PSIRT before publication
- 90-day disclosure window (standard)
- Coordinate with MITRE for CVE assignment if warranted
- Target venue: academic publication + conference presentation

---

## Timeline (Phase 0)

| Week | Focus | Deliverable |
|------|-------|-------------|
| 1 | Source code study (Tasks 0.1, 0.2) | GSP architecture notes |
| 2 | Firmware extraction & analysis (Task 0.3) | Firmware format docs |
| 2 | PCI BAR mapping (Task 0.4) | BAR layout map |
| 3 | VRAM persistence testing (Task 0.5) | Persistence matrix |
| 3 | Prior art survey (Task 0.6) | Annotated bibliography |
| 3 | Synthesis | Phase 0 report + Phase 1 plan |

---

## Decision Points After Phase 0

Based on Phase 0 findings, decide:

1. **Which GPU generation to focus on** — Older (Falcon-based, less crypto) vs.
   newer (RISC-V, better tooling but stronger signing)?
2. **Which persistence vector is most promising** — VRAM survival? Flash writes?
   Runtime hooking?
3. **What's the minimum viable PoC** — What's the simplest way to prove code
   execution on GSP? A register write? A DMA read?
4. **Detection feasibility** — Can we detect modifications from the host side, or
   do we need GPU-side cooperation?
