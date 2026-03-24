#!/usr/bin/env python3
"""
VRAM Persistence Test Suite

Tests whether data written to GPU VRAM survives various state transitions:
- Driver reload (rmmod/modprobe)
- D3 power state transitions
- Suspend/resume
- Warm reboot (requires two-phase execution)

This is a key Phase 0 research question: if VRAM persists across driver reloads,
it represents a viable persistence mechanism.

Usage:
    # Phase 1: Write test patterns
    sudo python test_vram_persistence.py write --bdf 01:00.0

    # Phase 2: Verify after transition
    sudo python test_vram_persistence.py verify --bdf 01:00.0

    # Automated driver-reload test
    sudo python test_vram_persistence.py test-driver-reload --bdf 01:00.0
"""

import argparse
import hashlib
import json
import mmap
import os
import struct
import subprocess
import sys
import time
from dataclasses import dataclass
from pathlib import Path

# Test pattern — easily identifiable magic bytes
MAGIC_HEADER = b"SHADOWCORE_PERSIST_TEST_v1"
MAGIC_PATTERN = bytes(range(256)) * 16  # 4KB repeating pattern

# Where to write in VRAM (offsets from BAR1 base)
# We test multiple regions to understand which survive
TEST_REGIONS = [
    {"name": "vram_start", "offset": 0x0000_0000, "size": 4096,
     "desc": "Very start of VRAM aperture"},
    {"name": "vram_1mb", "offset": 0x0010_0000, "size": 4096,
     "desc": "1MB into VRAM"},
    {"name": "vram_16mb", "offset": 0x0100_0000, "size": 4096,
     "desc": "16MB into VRAM"},
    {"name": "vram_64mb", "offset": 0x0400_0000, "size": 4096,
     "desc": "64MB into VRAM"},
    {"name": "vram_128mb", "offset": 0x0800_0000, "size": 4096,
     "desc": "128MB into VRAM (near end of typical BAR1 aperture)"},
]

STATE_FILE = Path("/tmp/shadowcore_persistence_state.json")


@dataclass
class TestResult:
    region_name: str
    offset: int
    written: bool
    survived: bool | None  # None = not yet tested
    hash_before: str
    hash_after: str | None
    notes: str = ""


def find_bar1_resource(bdf: str) -> Path | None:
    """Find the BAR1 (VRAM aperture) sysfs resource path for a GPU."""
    # Search sysfs for matching device
    pci_base = Path("/sys/bus/pci/devices")
    for dev_path in pci_base.iterdir():
        if dev_path.name.endswith(bdf):
            resource1 = dev_path / "resource1"
            if resource1.exists():
                return resource1
            # Check resource1_wc (write-combining variant)
            resource1_wc = dev_path / "resource1_wc"
            if resource1_wc.exists():
                return resource1_wc

    return None


def get_bar1_size(bdf: str) -> int:
    """Get the size of BAR1 from sysfs."""
    pci_base = Path("/sys/bus/pci/devices")
    for dev_path in pci_base.iterdir():
        if dev_path.name.endswith(bdf):
            resource = dev_path / "resource"
            if resource.exists():
                lines = resource.read_text().strip().split("\n")
                if len(lines) > 1:
                    parts = lines[1].split()
                    start = int(parts[0], 16)
                    end = int(parts[1], 16)
                    if start > 0:
                        return end - start + 1
    return 0


def build_test_payload(region_name: str) -> bytes:
    """Build a test payload with identifiable header + pattern."""
    # Header: magic + region name + timestamp
    header = MAGIC_HEADER + b"\x00"
    header += region_name.encode("ascii") + b"\x00"
    header += struct.pack("<Q", int(time.time()))
    # Pad header to 64 bytes
    header = header.ljust(64, b"\x00")
    # Fill rest with repeating pattern
    payload = header + MAGIC_PATTERN
    return payload[:4096]  # Exactly 4KB


def write_to_vram(bar1_path: Path, offset: int, data: bytes) -> bool:
    """Write data to a specific VRAM offset via BAR1 mmap."""
    try:
        fd = os.open(str(bar1_path), os.O_RDWR | os.O_SYNC)
        try:
            # Map the region we need
            page_size = os.sysconf("SC_PAGE_SIZE")
            map_offset = (offset // page_size) * page_size
            map_size = offset - map_offset + len(data)
            # Round up to page boundary
            map_size = ((map_size + page_size - 1) // page_size) * page_size

            mm = mmap.mmap(fd, map_size, mmap.MAP_SHARED,
                           mmap.PROT_READ | mmap.PROT_WRITE,
                           offset=map_offset)
            mm.seek(offset - map_offset)
            mm.write(data)
            mm.flush()
            mm.close()
            return True
        finally:
            os.close(fd)
    except (PermissionError, OSError) as e:
        print(f"  Error writing at offset 0x{offset:x}: {e}")
        return False


def read_from_vram(bar1_path: Path, offset: int, size: int) -> bytes | None:
    """Read data from a specific VRAM offset via BAR1 mmap."""
    try:
        fd = os.open(str(bar1_path), os.O_RDONLY | os.O_SYNC)
        try:
            page_size = os.sysconf("SC_PAGE_SIZE")
            map_offset = (offset // page_size) * page_size
            map_size = offset - map_offset + size
            map_size = ((map_size + page_size - 1) // page_size) * page_size

            mm = mmap.mmap(fd, map_size, mmap.MAP_SHARED,
                           mmap.PROT_READ, offset=map_offset)
            mm.seek(offset - map_offset)
            data = mm.read(size)
            mm.close()
            return data
        finally:
            os.close(fd)
    except (PermissionError, OSError) as e:
        print(f"  Error reading at offset 0x{offset:x}: {e}")
        return None


def cmd_write(bdf: str):
    """Write test patterns to VRAM regions and save state."""
    bar1_path = find_bar1_resource(bdf)
    if not bar1_path:
        print(f"Error: Cannot find BAR1 resource for {bdf}")
        sys.exit(1)

    bar1_size = get_bar1_size(bdf)
    print(f"BAR1 resource: {bar1_path}")
    print(f"BAR1 size: {bar1_size / 1024 / 1024:.0f} MB")

    results = []
    for region in TEST_REGIONS:
        if region["offset"] + region["size"] > bar1_size:
            print(f"  SKIP {region['name']}: offset 0x{region['offset']:x} "
                  f"exceeds BAR1 size")
            continue

        payload = build_test_payload(region["name"])
        payload_hash = hashlib.sha256(payload).hexdigest()

        print(f"  Writing to {region['name']} "
              f"(offset 0x{region['offset']:08x})...", end=" ")

        success = write_to_vram(bar1_path, region["offset"], payload)

        if success:
            # Read back to verify write
            readback = read_from_vram(bar1_path, region["offset"], len(payload))
            if readback == payload:
                print(f"OK (verified)")
            else:
                print(f"WRITTEN but readback mismatch!")
                success = False
        else:
            print(f"FAILED")

        results.append({
            "name": region["name"],
            "offset": region["offset"],
            "size": region["size"],
            "hash": payload_hash,
            "written": success,
            "timestamp": time.time(),
        })

    # Save state for later verification
    state = {
        "bdf": bdf,
        "bar1_path": str(bar1_path),
        "bar1_size": bar1_size,
        "write_time": time.time(),
        "regions": results,
    }
    STATE_FILE.write_text(json.dumps(state, indent=2))
    print(f"\nState saved to {STATE_FILE}")
    print("Now trigger a state transition (driver reload, suspend, etc.) "
          "and run 'verify'")


def cmd_verify(bdf: str):
    """Verify whether written patterns survived a state transition."""
    if not STATE_FILE.exists():
        print(f"Error: No state file found at {STATE_FILE}")
        print("Run 'write' first to establish test patterns.")
        sys.exit(1)

    state = json.loads(STATE_FILE.read_text())

    bar1_path = find_bar1_resource(bdf)
    if not bar1_path:
        print(f"Error: Cannot find BAR1 resource for {bdf}")
        sys.exit(1)

    elapsed = time.time() - state["write_time"]
    print(f"Verifying patterns written {elapsed:.1f} seconds ago")
    print(f"BAR1 resource: {bar1_path}")

    survived_count = 0
    total_count = 0

    for region in state["regions"]:
        if not region["written"]:
            continue

        total_count += 1
        print(f"\n  Checking {region['name']} "
              f"(offset 0x{region['offset']:08x})...", end=" ")

        data = read_from_vram(bar1_path, region["offset"], region["size"])
        if data is None:
            print("READ FAILED")
            continue

        actual_hash = hashlib.sha256(data).hexdigest()

        if actual_hash == region["hash"]:
            print("SURVIVED!")
            survived_count += 1

            # Check if we can still read our header
            if data.startswith(MAGIC_HEADER):
                # Extract timestamp
                ts_offset = len(MAGIC_HEADER) + 1 + len(region["name"]) + 1
                ts = struct.unpack_from("<Q", data, ts_offset)[0]
                print(f"    Header intact, written at timestamp {ts}")
        else:
            print("CLEARED/MODIFIED")
            # Check what's there now
            if all(b == 0 for b in data):
                print("    Region is zeroed")
            elif all(b == 0xFF for b in data):
                print("    Region is 0xFF (unmapped?)")
            elif data.startswith(MAGIC_HEADER):
                print("    Header present but data corrupted")
            else:
                print(f"    Contains different data "
                      f"(first 16 bytes: {data[:16].hex()})")

    print(f"\n{'='*50}")
    print(f"RESULTS: {survived_count}/{total_count} regions survived")
    if survived_count > 0:
        print(">>> VRAM PERSISTENCE CONFIRMED <<<")
    else:
        print("No persistence detected for this transition type.")


def cmd_test_driver_reload(bdf: str):
    """Automated test: write, reload driver, verify."""
    print("=== AUTOMATED DRIVER RELOAD PERSISTENCE TEST ===")
    print(f"Target GPU: {bdf}")
    print()
    print("WARNING: This will unload and reload the NVIDIA driver.")
    print("Ensure no GPU workloads are running and display is on another GPU.")
    response = input("Continue? [y/N] ")
    if response.lower() != "y":
        print("Aborted.")
        return

    # Phase 1: Write patterns
    print("\n--- Phase 1: Writing test patterns ---")
    cmd_write(bdf)

    # Unload and reload driver
    print("\n--- Unloading NVIDIA driver ---")
    unload_cmds = [
        "modprobe -r nvidia_drm",
        "modprobe -r nvidia_modeset",
        "modprobe -r nvidia_uvm",
        "modprobe -r nvidia",
    ]
    for cmd in unload_cmds:
        print(f"  $ {cmd}")
        result = subprocess.run(cmd.split(), capture_output=True, text=True)
        if result.returncode != 0:
            print(f"    Warning: {result.stderr.strip()}")

    time.sleep(2)  # Brief pause

    print("\n--- Reloading NVIDIA driver ---")
    result = subprocess.run(
        ["modprobe", "nvidia"], capture_output=True, text=True)
    if result.returncode != 0:
        print(f"  Error reloading: {result.stderr}")
        print("  Try manual reload and then run 'verify'")
        return

    time.sleep(3)  # Let driver initialize

    # Phase 2: Verify
    print("\n--- Phase 2: Verifying persistence ---")
    cmd_verify(bdf)


def main():
    parser = argparse.ArgumentParser(
        description="VRAM Persistence Test Suite")
    parser.add_argument(
        "command", choices=["write", "verify", "test-driver-reload"],
        help="Command to execute")
    parser.add_argument(
        "--bdf", type=str, required=True,
        help="PCI BDF address of target GPU (e.g., 01:00.0)")

    args = parser.parse_args()

    if os.geteuid() != 0:
        print("Error: This tool requires root privileges (sudo)")
        sys.exit(1)

    if args.command == "write":
        cmd_write(args.bdf)
    elif args.command == "verify":
        cmd_verify(args.bdf)
    elif args.command == "test-driver-reload":
        cmd_test_driver_reload(args.bdf)


if __name__ == "__main__":
    main()
