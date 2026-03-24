#!/usr/bin/env python3
"""
GPU PCI BAR Region Mapper

Enumerates and maps PCI Base Address Register (BAR) regions for NVIDIA GPUs.
Documents which regions are readable/writable from the host and what they
contain (registers, VRAM, firmware regions).

Requires: root privileges for MMIO access

Usage:
    sudo python map_gpu_bars.py                    # Auto-detect NVIDIA GPU
    sudo python map_gpu_bars.py --bdf 01:00.0      # Specific device
    sudo python map_gpu_bars.py --probe-write       # Test write access (CAUTION)
"""

import argparse
import mmap
import os
import re
import struct
import sys
from dataclasses import dataclass, field
from pathlib import Path


@dataclass
class BARRegion:
    """Represents a PCI BAR region."""
    index: int
    physical_addr: int
    size: int
    bar_type: str       # "memory" or "io"
    is_64bit: bool
    is_prefetchable: bool
    resource_path: str
    description: str = ""
    writable_ranges: list = field(default_factory=list)


@dataclass
class GPUDevice:
    """Represents a detected NVIDIA GPU."""
    bdf: str            # Bus:Device.Function (e.g., "01:00.0")
    vendor_id: int
    device_id: int
    device_name: str
    driver: str
    bars: list[BARRegion] = field(default_factory=list)


# Known NVIDIA BAR layout (typical, varies by GPU generation)
KNOWN_BAR_DESCRIPTIONS = {
    0: "GPU Registers (MMIO) — Control registers, PMC, PBUS, PTIMER, etc.",
    1: "VRAM Aperture — Direct access to video memory (framebuffer)",
    2: "NV_USER registers — Usermode register space (CUDA, graphics)",
    3: "I/O port space (legacy, often unused on modern GPUs)",
}

# Known MMIO register ranges within BAR0 (from envytools/rnndb)
KNOWN_REGISTER_RANGES = [
    (0x000000, 0x001000, "PMC — Master control"),
    (0x001000, 0x002000, "PBUS — Bus control"),
    (0x002000, 0x004000, "PFIFO — Command FIFO"),
    (0x007000, 0x008000, "PME — Power management"),
    (0x009000, 0x00a000, "PTIMER — Timer/clock"),
    (0x00e000, 0x010000, "PFB — Framebuffer/memory controller"),
    (0x020000, 0x028000, "PTHERM — Thermal management"),
    (0x060000, 0x068000, "PDISPLAY — Display engine"),
    (0x080000, 0x082000, "PPCI — PCI config mirror"),
    (0x084000, 0x088000, "PNVIO — I/O pin control"),
    (0x088000, 0x08c000, "PCLOCK — Clock management"),
    (0x100000, 0x200000, "FALCON engines (multiple)"),
    (0x110000, 0x120000, "GSP — GPU System Processor"),
    (0x800000, 0x900000, "GPU MMU / page tables"),
    (0xb00000, 0xc00000, "SEC2 — Security engine 2"),
]


def find_nvidia_gpus() -> list[GPUDevice]:
    """Find all NVIDIA GPUs in the system via sysfs."""
    gpus = []
    pci_devices = Path("/sys/bus/pci/devices")

    if not pci_devices.exists():
        print("Error: /sys/bus/pci/devices not found (not Linux?)", file=sys.stderr)
        return gpus

    for dev_path in sorted(pci_devices.iterdir()):
        vendor_path = dev_path / "vendor"
        if not vendor_path.exists():
            continue

        vendor_id = int(vendor_path.read_text().strip(), 16)
        if vendor_id != 0x10de:  # NVIDIA vendor ID
            continue

        device_id = int((dev_path / "device").read_text().strip(), 16)

        # Get device class — we want VGA (0x030000) or 3D controller (0x030200)
        class_id = int((dev_path / "class").read_text().strip(), 16)
        if (class_id >> 8) != 0x0302 and (class_id >> 8) != 0x0300:
            continue

        # Get BDF from directory name (strip domain prefix)
        bdf = dev_path.name.split(":")[-2] + ":" + dev_path.name.split(":")[-1]

        # Get driver
        driver_link = dev_path / "driver"
        driver = driver_link.resolve().name if driver_link.exists() else "none"

        # Get device name from lspci if available
        device_name = f"NVIDIA GPU (0x{device_id:04x})"
        try:
            import subprocess
            result = subprocess.run(
                ["lspci", "-s", dev_path.name, "-nn"],
                capture_output=True, text=True, timeout=5)
            if result.returncode == 0:
                device_name = result.stdout.strip()
        except (FileNotFoundError, subprocess.TimeoutExpired):
            pass

        gpu = GPUDevice(
            bdf=dev_path.name,
            vendor_id=vendor_id,
            device_id=device_id,
            device_name=device_name,
            driver=driver,
        )

        # Parse BAR resources
        resource_path = dev_path / "resource"
        if resource_path.exists():
            for i, line in enumerate(resource_path.read_text().strip().split("\n")):
                parts = line.split()
                if len(parts) < 3:
                    continue
                start = int(parts[0], 16)
                end = int(parts[1], 16)
                flags = int(parts[2], 16)

                if start == 0:
                    continue  # Unused BAR

                size = end - start + 1
                is_io = bool(flags & 0x1)
                is_64bit = bool(flags & 0x4)
                is_prefetch = bool(flags & 0x8)

                bar = BARRegion(
                    index=i,
                    physical_addr=start,
                    size=size,
                    bar_type="io" if is_io else "memory",
                    is_64bit=is_64bit,
                    is_prefetchable=is_prefetch,
                    resource_path=str(dev_path / f"resource{i}"),
                    description=KNOWN_BAR_DESCRIPTIONS.get(i, "Unknown"),
                )
                gpu.bars.append(bar)

        gpus.append(gpu)

    return gpus


def format_size(size: int) -> str:
    """Format byte size to human readable."""
    for unit in ["B", "KB", "MB", "GB"]:
        if size < 1024:
            return f"{size:.1f} {unit}"
        size /= 1024
    return f"{size:.1f} TB"


def probe_bar_read(bar: BARRegion, num_samples: int = 16) -> list[tuple[int, int]]:
    """Read sample values from a BAR region (requires root)."""
    samples = []

    if not os.path.exists(bar.resource_path):
        return samples

    try:
        fd = os.open(bar.resource_path, os.O_RDONLY | os.O_SYNC)
        try:
            mm = mmap.mmap(fd, min(bar.size, 0x100000),  # Map up to 1MB
                           mmap.MAP_SHARED, mmap.PROT_READ)
            # Sample at regular intervals
            step = min(bar.size, 0x100000) // num_samples
            for i in range(num_samples):
                offset = i * step
                mm.seek(offset)
                value = struct.unpack("<I", mm.read(4))[0]
                samples.append((offset, value))
            mm.close()
        finally:
            os.close(fd)
    except (PermissionError, OSError) as e:
        print(f"  Warning: Cannot read BAR{bar.index}: {e}")

    return samples


def probe_register_ranges(bar: BARRegion) -> list[dict]:
    """Probe known register ranges within BAR0."""
    results = []

    if bar.index != 0 or not os.path.exists(bar.resource_path):
        return results

    try:
        fd = os.open(bar.resource_path, os.O_RDONLY | os.O_SYNC)
        try:
            map_size = min(bar.size, 0x1000000)  # Map up to 16MB
            mm = mmap.mmap(fd, map_size, mmap.MAP_SHARED, mmap.PROT_READ)

            for start, end, name in KNOWN_REGISTER_RANGES:
                if start >= map_size:
                    continue
                try:
                    mm.seek(start)
                    first_word = struct.unpack("<I", mm.read(4))[0]
                    # Read a few more words to check if region is populated
                    words = [first_word]
                    for j in range(1, min(4, (end - start) // 4)):
                        words.append(struct.unpack("<I", mm.read(4))[0])

                    all_ff = all(w == 0xFFFFFFFF for w in words)
                    all_zero = all(w == 0 for w in words)

                    results.append({
                        "range": f"0x{start:06x}-0x{end:06x}",
                        "name": name,
                        "status": "unmapped" if all_ff else
                                  "zeroed" if all_zero else "populated",
                        "sample": f"0x{first_word:08x}",
                    })
                except Exception:
                    results.append({
                        "range": f"0x{start:06x}-0x{end:06x}",
                        "name": name,
                        "status": "read_error",
                        "sample": "N/A",
                    })

            mm.close()
        finally:
            os.close(fd)
    except (PermissionError, OSError) as e:
        print(f"  Warning: Cannot probe registers: {e}")

    return results


def print_gpu_report(gpu: GPUDevice, probe: bool = False):
    """Print a detailed report for a GPU."""
    print(f"\n{'='*70}")
    print(f"GPU: {gpu.device_name}")
    print(f"{'='*70}")
    print(f"BDF:       {gpu.bdf}")
    print(f"Vendor:    0x{gpu.vendor_id:04x} (NVIDIA)")
    print(f"Device:    0x{gpu.device_id:04x}")
    print(f"Driver:    {gpu.driver}")

    print(f"\nBAR Regions:")
    print(f"{'BAR':<5} {'Type':<8} {'Physical Address':<20} {'Size':<12} "
          f"{'64bit':<6} {'Prefetch':<9} Description")
    print(f"{'-'*5} {'-'*8} {'-'*20} {'-'*12} {'-'*6} {'-'*9} {'-'*30}")

    for bar in gpu.bars:
        print(f"BAR{bar.index:<2} {bar.bar_type:<8} 0x{bar.physical_addr:016x} "
              f"{format_size(bar.size):<12} {'yes' if bar.is_64bit else 'no':<6} "
              f"{'yes' if bar.is_prefetchable else 'no':<9} {bar.description}")

    if probe and os.geteuid() == 0:
        print(f"\nBAR0 Register Probing:")
        for bar in gpu.bars:
            if bar.index == 0:
                ranges = probe_register_ranges(bar)
                if ranges:
                    print(f"{'Range':<22} {'Name':<35} {'Status':<12} Sample")
                    print(f"{'-'*22} {'-'*35} {'-'*12} {'-'*12}")
                    for r in ranges:
                        print(f"{r['range']:<22} {r['name']:<35} "
                              f"{r['status']:<12} {r['sample']}")

        print(f"\nBAR Sample Reads:")
        for bar in gpu.bars:
            if bar.bar_type == "memory":
                samples = probe_bar_read(bar, num_samples=8)
                if samples:
                    print(f"\n  BAR{bar.index} ({bar.description[:40]}):")
                    for offset, value in samples:
                        print(f"    0x{offset:08x}: 0x{value:08x}")

    elif probe and os.geteuid() != 0:
        print(f"\n  [!] Run as root (sudo) to probe BAR regions")


def main():
    parser = argparse.ArgumentParser(
        description="GPU PCI BAR Region Mapper for NVIDIA GPUs")
    parser.add_argument(
        "--bdf", type=str, default=None,
        help="Specific PCI BDF address (e.g., 01:00.0)")
    parser.add_argument(
        "--probe", action="store_true",
        help="Probe BAR regions for read access (requires root)")
    parser.add_argument(
        "--probe-write", action="store_true",
        help="Test write access to BAR regions (CAUTION — requires root)")
    parser.add_argument(
        "--output", "-o", type=Path, default=None,
        help="Save report to file")

    args = parser.parse_args()

    if args.probe_write:
        print("WARNING: Write probing can destabilize the GPU or crash the system.")
        print("Ensure you are using a secondary/test GPU, not your display GPU.")
        response = input("Continue? [y/N] ")
        if response.lower() != "y":
            print("Aborted.")
            return

    print("Scanning for NVIDIA GPUs...")
    gpus = find_nvidia_gpus()

    if not gpus:
        print("No NVIDIA GPUs found.")
        print("Check: lspci | grep -i nvidia")
        return

    print(f"Found {len(gpus)} NVIDIA GPU(s)")

    for gpu in gpus:
        if args.bdf and not gpu.bdf.endswith(args.bdf):
            continue
        print_gpu_report(gpu, probe=args.probe or args.probe_write)


if __name__ == "__main__":
    main()
