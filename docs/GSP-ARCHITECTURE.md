# GSP Architecture & Attack Surface Reference

## GSP Overview

The GPU System Processor (GSP) is a dedicated microprocessor on NVIDIA GPUs
(Turing and later) that runs the Resource Manager (RM) — previously CPU-side —
directly on the GPU. The GSP has **full access to everything in the GPU**:
memory controllers, display engines, all registers. The host driver communicates
with it via high-level RPC commands rather than direct register manipulation.

---

## CPU Architecture by GPU Generation

| Generation | GPU Series | GSP Processor | Notes |
|-----------|-----------|---------------|-------|
| Turing | RTX 2000, GTX 16xx | Falcon + crypto extensions | Transitional; RISC-V migration began ~2016 internally |
| Ampere | RTX 3000, A100 | Falcon-based GSP | Still Falcon for GSP, but RISC-V appearing in other engines |
| Ada Lovelace | RTX 4000, L40 | **RISC-V** (64-bit, "Peregrine") | Single/multi-hart. NVIDIA shipped >1B RISC-V cores in 2024 |
| Hopper | H100, H200 | **RISC-V** | Peregrine cores, multi-hart |
| Blackwell | B100, B200 | **RISC-V** | Latest generation |

**Key insight:** Falcon cores still exist on modern GPUs for legacy functions (SEC2,
PMU), coexisting with RISC-V. A modern Ada Lovelace GPU has 30-40 unique RISC-V
IP blocks.

---

## Falcon Security Modes

Falcon microcontrollers operate in three privilege levels:

| Mode | Level | Properties |
|------|-------|-----------|
| **Heavy Secure (HS)** | PL3 | Most trusted. Hardware-verified signature. DMEM/IMEM **protected from external reads/writes**. Only code signed with NVIDIA's fuse-burned keys can execute here. |
| **Light Secure (LS)** | PL2 | Elevated privileges. Can only be enabled from HS mode code. Some internal state leaks. |
| **Non-Secure (NS)** | PL0 | Any unsigned code can run. Restricted register access. May disable physical memory access. |

**Implication:** Code running in NS mode on a Falcon is restricted. The challenge
is either: (a) finding a way to run in HS/LS mode (requires defeating signature
verification), or (b) finding useful primitives available from NS mode, or (c)
targeting the RISC-V GSP where the security model may differ.

---

## GSP Boot Chain

The GSP boot sequence on Ampere/Ada Lovelace:

```
1. Host driver loads firmware ELF from /lib/firmware/nvidia/<version>/gsp_*.bin
                          │
2. FRTS firmware runs ────┤  Creates WPR (Write Protected Region) in GPU VRAM
                          │
3. Booter firmware ───────┤  Loaded onto SEC2 Falcon in Heavy Secure mode
                          │  Job: authenticate and load GSP bootloader
                          │
4. GSP Bootloader ────────┤  Loaded onto GSP RISC-V core by the Booter
                          │  Verifies and loads actual GSP firmware
                          │
5. GSP-RM firmware ───────┤  Runs in Light Secure mode
                          │  Full Resource Manager RTOS
                          │
6. Message queues init ───┘  TX/RX shared memory queues established
                             RPC communication begins
```

**WPR (Write Protected Region):** A hardware-enforced protected area in GPU VRAM
where GSP firmware code and data reside. Metadata described in
`gsp_fw_wpr_meta.h`. Once established, host-side writes to this region are
blocked by hardware.

**Attack implications:**
- The firmware blob is loaded from the host filesystem → interceptable before upload
- The boot chain has multiple stages → each is a potential injection point
- WPR protects the *final* firmware in VRAM, but not the *loading process*
- Firmware version must exactly match kernel module version (no downgrade mixing)

---

## RPC Communication (Host ↔ GSP)

### Message Queue Architecture

Communication uses **shared-memory message queues** with a lock-free, zero-copy
design:

```
┌──────────────┐                    ┌──────────────┐
│   CPU / RM   │                    │   GSP / RM   │
│              │                    │              │
│  OBJRPC      │◄── Status Queue ──│              │
│  structure   │                    │              │
│              │── Command Queue ──►│              │
└──────────────┘                    └──────────────┘
       ▲                                   ▲
       └────── Shared GPU Memory ──────────┘
```

- **Command Queue:** CPU writes commands, GSP reads and processes
- **Status Queue:** GSP writes responses/events, CPU reads
- Messages constructed directly in shared memory visible to both sides
- Max message queue element size: **16 pages**
- Large messages split using `NV_VGPU_MSG_FUNCTION_CONTINUATION_RECORD`

### RPC Reply Policies

| Policy | Behavior |
|--------|----------|
| `NVKM_GSP_RPC_REPLY_RECV` | Wait for full reply from GSP |
| `NVKM_GSP_RPC_REPLY_POLL` | Wait then discard reply |
| `NVKM_GSP_RPC_REPLY_NOWAIT` | Fire and forget |
| `NVKM_GSP_RPC_REPLY_NOSEQ` | No sequence number tracking |

### Message Structure (Nouveau)

```
┌─────────────────────────┐
│ struct r535_gsp_msg      │  Queuing metadata header
├─────────────────────────┤
│ struct nvfw_gsp_rpc      │  RPC function number + info
├─────────────────────────┤
│ Payload (variable)       │  Command-specific parameters
└─────────────────────────┘
```

### Confidential Computing Note

In GPU confidential computing mode, RPC payloads are encrypted using
`cpu_gsp_locked_rpc`/`gsp_cpu_locked_rpc` keys. However, **headers and the
physical address table remain plaintext**. This is a documented weakness
(IBM/Ohio State research).

---

## PCI BAR Layout

| BAR | Name | Type | Size | Maps To |
|-----|------|------|------|---------|
| **BAR0** | MMIO Registers | Non-prefetchable | 16 MB (fixed) | GPU control registers. Addresses masked to low 24 bits. |
| **BAR1** | Framebuffer | Prefetchable | Up to 64 GB | VRAM / GPU global memory. Direct or VM-translated. |
| **BAR2/3** | Instance Memory | Varies | 16 MB+ | Control structures, kernel-accessible memory. Independent VM from BAR1. |

### BAR0 Register Map (from envytools rnndb)

| Offset Range | Name | Purpose |
|-------------|------|---------|
| 0x000000-0x000FFF | PMC | Master control (GPU ID, engine switches, interrupts) |
| 0x001000-0x001FFF | PBUS | Bus interface control |
| 0x002000-0x003FFF | PFIFO | Command submission FIFO |
| 0x007000-0x007FFF | PME | Power management engine |
| 0x009000-0x009FFF | PTIMER | Timer/clock |
| 0x00E000-0x00FFFF | PFB | Framebuffer/memory controller |
| 0x020000-0x027FFF | PTHERM | Thermal management |
| 0x060000-0x067FFF | PDISPLAY | Display engine |
| 0x080000-0x081FFF | PPCI | PCI config mirror |
| 0x084000-0x087FFF | PNVIO | I/O pin control |
| 0x088000-0x08BFFF | PCLOCK | Clock management |
| 0x100000-0x1FFFFF | FALCON | Falcon engine registers (multiple) |
| **0x110000-0x11FFFF** | **GSP** | **GPU System Processor registers** |
| 0x800000-0x8FFFFF | GPU MMU | Page table management |
| 0xB00000-0xBFFFFF | SEC2 | Security engine 2 |

**Real-world sizes:** L40S: BAR0=16MB, BAR1=64GB, BAR3=32MB.
V100: BAR0=16MB, BAR1=32GB, BAR3=32MB.

**Endianness:** BAR0 has a selectable endianness switch in PMC (NV1A+).
Internal accesses are always little-endian.

---

## VRAM Persistence Characteristics

### What Survives What

| Event | VRAM Survives? | Notes |
|-------|---------------|-------|
| Process termination | **Partially** | Uninitialized memory may retain prior process data |
| Driver reload (with persistenced) | **Yes** | nvidia-persistenced keeps device files open, preserves state |
| Full driver unload/reload | **Partially** | VRAM not explicitly scrubbed, but allocations lost |
| Suspend/resume (default) | **No** | GPU loses power/refresh |
| Suspend/resume (PreserveVideoMemory=1) | **Yes** | Backed up to disk, restored on resume |
| GPU reset | **No** | Refresh stops, VRAM lost |
| Warm reboot | **Partially** | DRAM remanence — recoverable for seconds-minutes |
| Cold boot + cooling | **Yes (extended)** | Freeze spray → hours; LN2 → potentially a week |

### Key Details

- `nvidia-persistenced` daemon keeps GPU device files open to avoid cold-start
  reinitialization — this is a **performance optimization**, not security
- `NVreg_PreserveVideoMemoryAllocations=1` explicitly backs up VRAM to disk
  on suspend and restores on resume
- NVIDIA Hopper/Blackwell confidential computing does **NOT** encrypt VRAM at
  runtime — relies solely on access-control firewalls
- VRAM is not systematically zeroed between process contexts in all cases
- All VRAM types (GDDR5/6/6X, HBM2/3) are DRAM-based with identical remanence
  physics to system RAM

### Persistence Research Priority

The most promising persistence vector based on these findings:

1. **Driver reload with persistenced** — VRAM contents survive, no special tricks needed
2. **Driver reload without persistenced** — VRAM may not be scrubbed, needs testing
3. **Firmware blob interception** — Modify GSP firmware before upload (Vector B from project plan)
4. **WPR bypass** — If achievable, code in WPR is hardware-protected from host-side clearing

---

## Key Source Files Reference

### NVIDIA open-gpu-kernel-modules

| Path | What to Study |
|------|--------------|
| `src/nvidia/src/kernel/gpu/gsp/kernel_gsp.c` | Core GSP management (RPC, firmware loading, boot) |
| `src/nvidia/inc/kernel/gpu/gsp/message_queue_priv.h` | Message queue structs (`GSP_MSG_QUEUE_ELEMENT`) |
| `common/inc/gsp/gsp_fw_wpr_meta.h` | WPR metadata structures |
| `src/nvidia/src/kernel/gpu/gsp/arch/turing/kernel_gsp_tu102.c` | Turing-specific GSP |
| `src/nvidia/generated/g_kernel_gsp_nvoc.c` | Generated GSP class bindings |
| `kernel-open/nvidia/nv.c` | Kernel interface |

### Nouveau (Linux kernel)

| Path | What to Study |
|------|--------------|
| `nvkm/subdev/gsp/rm/r535/rpc.c` | RPC handling implementation |
| `nvkm/subdev/gsp/rm/r535/gsp.c` | GSP-RM r535 implementation |
| `nvkm/subdev/gsp/fwsec.c` | Firmware security handling |
| `nvkm/subdev/gsp/ga100.c`, `ga102.c`, `ad102.c` | Architecture-specific GSP |
| `include/nvkm/subdev/gsp.h` | GSP message policy definitions |

### Other

| Resource | What |
|----------|------|
| [falcon-tools](https://github.com/CAmadeus/falcon-tools) | Falcon v5 TSEC exploit tools: `requiem` (fake-signed HS payload template), `libfaucon` (Falcon stdlib) |
| envytools `rnndb/` | MMIO register database XML files |
| envytools `envydis` | Falcon disassembler/assembler |
| envytools `nva` | Direct GPU register access tools |
| envytools `nvbios` | VBIOS structure decoder |

---

## Prior Art Summary

| Work | Year | What Was Demonstrated |
|------|------|---------------------|
| Vasiliadis et al. "GPU-Assisted Malware" | 2010 | CUDA-based keylogger, host-side only |
| "Jellyfish" GPU rootkit | 2015 | VRAM-resident payload, no firmware persistence |
| UC Riverside GPU side channels | 2018 | Website fingerprinting, keystroke timing via OpenGL/CUDA |
| GPGPU 2017 "Security of Discrete GPUs" | 2017 | **IOMMU bypass, GPU microcode attack → full CPU physical memory access** |
| "Spy in the GPU-box" | 2023 | Cross-GPU covert channel via NVLink L2 cache, ~4 MB/s |
| "Veiled Pathways" (Penn State) | Recent | **Bypasses GPU MIG isolation** via DRAM freq scaling, NVENC/NVDEC |
| IBM/Ohio State GPU-CC analysis | Recent | GPU confidential computing doesn't encrypt VRAM at runtime |

**Gap in literature:** No published work demonstrates persistent code execution
on the GSP or other GPU management processor firmware. VRAM-resident malware
(Jellyfish) and GPU-assisted host-side malware exist, but firmware-level
persistence is unexplored. This is the gap SHADOWCORE aims to fill.

---

## Recommended Focus Areas for Phase 1

Based on these findings, the highest-value Phase 1 targets are:

1. **Firmware blob interception (Vector B):** The GSP firmware is loaded from a
   host filesystem path. Intercepting and patching it before upload to the GSP
   (via LD_PRELOAD or kernel module) bypasses all on-GPU signature verification
   because the verification hasn't happened yet. This is the **easiest path to
   PoC code execution**.

2. **VRAM persistence without WPR:** Test whether non-WPR VRAM regions can hold
   data across driver reloads. If so, combined with a GSP hook, this provides
   persistence without needing flash access.

3. **GSP register space (BAR0 0x110000-0x11FFFF):** What's readable/writable
   from the host in the GSP register range? Can we influence GSP behavior via
   register writes?

4. **RPC fuzzing:** The shared-memory RPC interface is the primary host→GSP
   attack surface. Input validation bugs in RPC handlers could yield GSP code
   execution from the host.

5. **falcon-tools as reference:** The `requiem` project (fake-signed HS mode
   payload for Falcon v5 TSEC) may provide a template for GSP payload development,
   even though GSP on Ada Lovelace is RISC-V.
