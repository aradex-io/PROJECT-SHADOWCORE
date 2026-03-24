# PROJECT SHADOWCORE — GPU Firmware Security Research

## Overview

Security research project investigating whether code can persist within GPU
firmware (specifically NVIDIA's GSP — GPU System Processor), surviving driver
reloads and potentially reboots, in a location invisible to host-side EDR,
antivirus, and forensic tooling.

**Goal:** Demonstrate the attack surface exists, then build the detection and
defense tooling that doesn't exist yet. All findings will be responsibly
disclosed to NVIDIA PSIRT and MITRE.

## Responsible Disclosure

This is authorized security research conducted for the purpose of:
1. Proving whether GPU firmware persistence is feasible (even a "hello world")
2. Building detection tooling for a currently unmonitored attack surface
3. Responsible disclosure to GPU vendors (NVIDIA, AMD, Intel)
4. Academic publication after vendor coordination

**No malicious use.** The PoC payload is a proof of execution (register write,
hello world), not a weaponized implant.

## Project Structure

```
PROJECT-SHADOWCORE/
├── docs/                          # Research documentation
│   └── PHASE0-RESEARCH-PLAN.md    # Detailed Phase 0 plan & requirements
├── tools/                         # Research tooling
│   ├── firmware-extract/          # GSP firmware blob extraction & triage
│   ├── bar-mapper/                # PCI BAR region mapping
│   ├── vram-persistence/          # VRAM persistence testing suite
│   └── gsp-rpc-monitor/          # GSP RPC interface cataloger
├── analysis/                      # Analysis outputs
│   ├── firmware-blobs/            # Extracted firmware binaries
│   ├── ghidra-projects/           # RE project files
│   └── notes/                     # Research notes
├── detection/                     # Defensive tooling (Phase 3)
│   ├── yara-rules/                # Detection signatures
│   ├── integrity-checker/         # Firmware integrity verification
│   └── forensics/                 # GPU memory forensics
├── scripts/                       # Utility scripts
├── tests/                         # Test suites
└── requirements.txt               # Python dependencies
```

## Phase 0 Tools

### Firmware Extraction & Triage
```bash
# Scan system for installed NVIDIA firmware blobs
python tools/firmware-extract/extract_gsp_firmware.py --scan-system

# Analyze a specific firmware blob
python tools/firmware-extract/extract_gsp_firmware.py /path/to/gsp_ad10x.bin -o analysis/firmware-blobs/
```

### PCI BAR Mapping
```bash
# Auto-detect NVIDIA GPUs and list BAR regions
sudo python tools/bar-mapper/map_gpu_bars.py

# Probe register ranges (requires root)
sudo python tools/bar-mapper/map_gpu_bars.py --probe

# Target specific GPU
sudo python tools/bar-mapper/map_gpu_bars.py --bdf 01:00.0 --probe
```

### VRAM Persistence Testing
```bash
# Write test patterns to VRAM
sudo python tools/vram-persistence/test_vram_persistence.py write --bdf 01:00.0

# After triggering a state transition (driver reload, suspend, etc.):
sudo python tools/vram-persistence/test_vram_persistence.py verify --bdf 01:00.0

# Automated driver-reload test
sudo python tools/vram-persistence/test_vram_persistence.py test-driver-reload --bdf 01:00.0
```

### GSP RPC Interface Cataloger
```bash
# Clone NVIDIA source first
git clone https://github.com/NVIDIA/open-gpu-kernel-modules /opt/nvidia-open

# Generate RPC catalog
python tools/gsp-rpc-monitor/gsp_rpc_catalog.py /opt/nvidia-open
python tools/gsp-rpc-monitor/gsp_rpc_catalog.py /opt/nvidia-open --format json -o analysis/notes/rpc_catalog.json
```

## Hardware Requirements

- **Test GPU:** NVIDIA RTX 3050+ (Ada Lovelace preferred for RISC-V GSP)
- **Display GPU:** Separate GPU or integrated graphics for display output
- **OS:** Linux (Ubuntu 22.04+ or Fedora 38+), kernel 6.1+
- **Access:** Root privileges for MMIO/BAR access and driver management

## Software Dependencies

```bash
# System packages
sudo apt install pciutils binwalk ghidra linux-headers-$(uname -r)

# Python environment
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt

# NVIDIA open-source kernel modules (for reference, not installation)
git clone https://github.com/NVIDIA/open-gpu-kernel-modules /opt/nvidia-open

# envytools (NVIDIA RE toolkit)
git clone https://github.com/envytools/envytools /opt/envytools
cd /opt/envytools && cmake . && make
```

## Research Phases

| Phase | Focus | Status |
|-------|-------|--------|
| **Phase 0** | Reconnaissance — map attack surface | **Active** |
| Phase 1 | Firmware RE — understand GSP internals | Planned |
| Phase 2 | PoC — prove code execution (hello world) | Planned |
| Phase 3 | Detection — build defensive tooling | Planned |

## Key References

- [NVIDIA Open-Source Kernel Modules](https://github.com/NVIDIA/open-gpu-kernel-modules)
- [envytools](https://github.com/envytools/envytools) — GPU RE toolkit
- [Nouveau Driver](https://nouveau.freedesktop.org/) — Open-source NVIDIA driver
- [Falcon ISA Docs](https://envytools.readthedocs.io/en/latest/hw/falcon/) — Microcontroller ISA
- Vasiliadis et al. (2010) — "GPU-Assisted Malware"
- "Jellyfish" (2015) — VRAM-resident rootkit PoC

## License

This research is conducted under responsible disclosure principles.
Tools in this repository are for authorized security research only.
