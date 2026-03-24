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

IMPORTANT: VRAM persistence is NOT the same as firmware persistence. VRAM is
volatile memory; data surviving a driver reload means the memory controller
doesn't zero VRAM on reset. Firmware persistence (surviving cold boot) requires
writing to non-volatile storage (flash/ROM), which is a Phase 2 research goal.

Usage:
    # Phase 1: Write test patterns
    sudo python test_vram_persistence.py write --bdf 01:00.0

    # Phase 2: Verify after transition
    sudo python test_vram_persistence.py verify --bdf 01:00.0

    # Automated driver-reload test
    sudo python test_vram_persistence.py test-driver-reload --bdf 01:00.0

    # JSON output for pipeline consumption
    sudo python test_vram_persistence.py verify --bdf 01:00.0 --format json
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
from pathlib import Path

# Test pattern — easily identifiable magic bytes
MAGIC_HEADER = b"SHADOWCORE_PERSIST_TEST_v1"
MAGIC_PATTERN = bytes(range(256)) * 16  # 4KB repeating pattern

DEFAULT_STATE_FILE = Path("/tmp/shadowcore_persistence_state.json")

# Fixed test regions (used as fallback; dynamic regions preferred)
FIXED_TEST_REGIONS = [
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


def build_test_regions(bar1_size: int) -> list[dict]:
    """Build test regions dynamically based on actual BAR1 aperture size.

    Tests at: start, 25%, 50%, 75%, and near-end of the aperture,
    plus the fixed offsets that fit within the aperture.
    """
    if bar1_size == 0:
        return FIXED_TEST_REGIONS

    regions = []

    # Fixed regions that fit
    for r in FIXED_TEST_REGIONS:
        if r["offset"] + r["size"] <= bar1_size:
            regions.append(r)

    # Dynamic regions based on actual size
    dynamic_offsets = {
        "vram_quarter": bar1_size // 4,
        "vram_half": bar1_size // 2,
        "vram_three_quarter": (bar1_size * 3) // 4,
        "vram_near_end": bar1_size - 8192,  # 8KB from end
    }

    for name, offset in dynamic_offsets.items():
        # Align to page boundary
        offset = (offset // 4096) * 4096
        if offset < 0 or offset + 4096 > bar1_size:
            continue
        # Skip if too close to an existing region
        if any(abs(offset - r["offset"]) < 8192 for r in regions):
            continue
        regions.append({
            "name": name,
            "offset": offset,
            "size": 4096,
            "desc": f"{name} (dynamic, {offset / 1024 / 1024:.0f}MB into aperture)",
        })

    return sorted(regions, key=lambda r: r["offset"])


def find_bar1_resource(bdf: str) -> Path | None:
    """Find the BAR1 (VRAM aperture) sysfs resource path for a GPU."""
    pci_base = Path("/sys/bus/pci/devices")
    for dev_path in pci_base.iterdir():
        if dev_path.name.endswith(bdf):
            resource1 = dev_path / "resource1"
            if resource1.exists():
                return resource1
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
    header = MAGIC_HEADER + b"\x00"
    header += region_name.encode("ascii") + b"\x00"
    header += struct.pack("<Q", int(time.time()))
    header = header.ljust(64, b"\x00")
    payload = header + MAGIC_PATTERN
    return payload[:4096]


def write_to_vram(bar1_path: Path, offset: int, data: bytes) -> bool:
    """Write data to a specific VRAM offset via BAR1 mmap."""
    try:
        fd = os.open(str(bar1_path), os.O_RDWR | os.O_SYNC)
        try:
            page_size = os.sysconf("SC_PAGE_SIZE")
            map_offset = (offset // page_size) * page_size
            map_size = offset - map_offset + len(data)
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
        print(f"  Error writing at offset 0x{offset:x}: {e}", file=sys.stderr)
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
        print(f"  Error reading at offset 0x{offset:x}: {e}", file=sys.stderr)
        return None


def is_nvidia_driver_loaded() -> bool:
    """Check if the nvidia kernel module is currently loaded."""
    try:
        result = subprocess.run(
            ["lsmod"], capture_output=True, text=True, timeout=5)
        return "nvidia " in result.stdout or "nvidia\n" in result.stdout
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return False


def is_nvidia_persistenced_running() -> bool:
    """Check if nvidia-persistenced is running (blocks driver unload)."""
    try:
        result = subprocess.run(
            ["pgrep", "-x", "nvidia-persist"],
            capture_output=True, timeout=5)
        if result.returncode == 0:
            return True
        # Also check the full name
        result = subprocess.run(
            ["pgrep", "-f", "nvidia-persistenced"],
            capture_output=True, timeout=5)
        return result.returncode == 0
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return False


def stop_nvidia_persistenced() -> bool:
    """Stop nvidia-persistenced daemon. Returns True if stopped or wasn't running."""
    if not is_nvidia_persistenced_running():
        return True
    print("  Stopping nvidia-persistenced...")
    try:
        result = subprocess.run(
            ["systemctl", "stop", "nvidia-persistenced"],
            capture_output=True, text=True, timeout=10)
        if result.returncode == 0:
            print("  nvidia-persistenced stopped via systemctl")
            return True
        # Fallback: direct kill
        result = subprocess.run(
            ["pkill", "-f", "nvidia-persistenced"],
            capture_output=True, text=True, timeout=5)
        time.sleep(1)
        return not is_nvidia_persistenced_running()
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return False


def wait_for_driver(timeout: int = 15) -> bool:
    """Wait for nvidia driver to become ready after modprobe."""
    for _ in range(timeout):
        if is_nvidia_driver_loaded():
            # Check if sysfs entries are populated
            pci_devices = Path("/sys/bus/pci/devices")
            for dev_path in pci_devices.iterdir():
                vendor_path = dev_path / "vendor"
                if vendor_path.exists():
                    try:
                        vid = int(vendor_path.read_text().strip(), 16)
                        if vid == 0x10de and (dev_path / "resource1").exists():
                            return True
                    except (ValueError, OSError):
                        pass
        time.sleep(1)
    return False


def cmd_write(bdf: str, state_file: Path, fmt: str = "text"):
    """Write test patterns to VRAM regions and save state."""
    bar1_path = find_bar1_resource(bdf)
    if not bar1_path:
        print(f"Error: Cannot find BAR1 resource for {bdf}", file=sys.stderr)
        sys.exit(1)

    bar1_size = get_bar1_size(bdf)
    if fmt == "text":
        print(f"BAR1 resource: {bar1_path}")
        print(f"BAR1 size: {bar1_size / 1024 / 1024:.0f} MB")

    test_regions = build_test_regions(bar1_size)

    results = []
    for region in test_regions:
        if region["offset"] + region["size"] > bar1_size:
            if fmt == "text":
                print(f"  SKIP {region['name']}: offset 0x{region['offset']:x} "
                      f"exceeds BAR1 size")
            continue

        payload = build_test_payload(region["name"])
        payload_hash = hashlib.sha256(payload).hexdigest()

        if fmt == "text":
            print(f"  Writing to {region['name']} "
                  f"(offset 0x{region['offset']:08x})...", end=" ")

        success = write_to_vram(bar1_path, region["offset"], payload)

        if success:
            readback = read_from_vram(bar1_path, region["offset"], len(payload))
            if readback == payload:
                if fmt == "text":
                    print(f"OK (verified)")
            else:
                if fmt == "text":
                    print(f"WRITTEN but readback mismatch!")
                success = False
        else:
            if fmt == "text":
                print(f"FAILED")

        results.append({
            "name": region["name"],
            "offset": region["offset"],
            "size": region["size"],
            "hash": payload_hash,
            "written": success,
            "timestamp": time.time(),
        })

    state = {
        "bdf": bdf,
        "bar1_path": str(bar1_path),
        "bar1_size": bar1_size,
        "write_time": time.time(),
        "regions": results,
    }

    # Write state file with restrictive permissions
    state_file.write_text(json.dumps(state, indent=2))
    os.chmod(state_file, 0o600)

    if fmt == "text":
        print(f"\nState saved to {state_file}")
        print("Now trigger a state transition (driver reload, suspend, etc.) "
              "and run 'verify'")
    elif fmt == "json":
        print(json.dumps({"action": "write", "state_file": str(state_file),
                          "results": results}, indent=2))


def cmd_verify(bdf: str, state_file: Path, fmt: str = "text"):
    """Verify whether written patterns survived a state transition."""
    if not state_file.exists():
        print(f"Error: No state file found at {state_file}", file=sys.stderr)
        print("Run 'write' first to establish test patterns.", file=sys.stderr)
        sys.exit(1)

    state = json.loads(state_file.read_text())

    bar1_path = find_bar1_resource(bdf)
    if not bar1_path:
        print(f"Error: Cannot find BAR1 resource for {bdf}", file=sys.stderr)
        sys.exit(1)

    elapsed = time.time() - state["write_time"]
    if fmt == "text":
        print(f"Verifying patterns written {elapsed:.1f} seconds ago")
        print(f"BAR1 resource: {bar1_path}")

    survived_count = 0
    total_count = 0
    verify_results = []

    for region in state["regions"]:
        if not region["written"]:
            continue

        total_count += 1
        if fmt == "text":
            print(f"\n  Checking {region['name']} "
                  f"(offset 0x{region['offset']:08x})...", end=" ")

        data = read_from_vram(bar1_path, region["offset"], region["size"])
        if data is None:
            if fmt == "text":
                print("READ FAILED")
            verify_results.append({
                "name": region["name"], "offset": region["offset"],
                "survived": False, "reason": "read_failed",
            })
            continue

        actual_hash = hashlib.sha256(data).hexdigest()
        survived = actual_hash == region["hash"]

        result_entry = {
            "name": region["name"],
            "offset": region["offset"],
            "survived": survived,
            "expected_hash": region["hash"],
            "actual_hash": actual_hash,
        }

        if survived:
            survived_count += 1
            if fmt == "text":
                print("SURVIVED! (VRAM data intact after transition)")
                if data.startswith(MAGIC_HEADER):
                    ts_offset = len(MAGIC_HEADER) + 1 + len(region["name"]) + 1
                    ts = struct.unpack_from("<Q", data, ts_offset)[0]
                    print(f"    Header intact, written at timestamp {ts}")
            result_entry["reason"] = "data_intact"
        else:
            if fmt == "text":
                print("CLEARED/MODIFIED")
                if all(b == 0 for b in data):
                    print("    Region is zeroed")
                elif all(b == 0xFF for b in data):
                    print("    Region is 0xFF (unmapped?)")
                elif data.startswith(MAGIC_HEADER):
                    print("    Header present but data corrupted")
                else:
                    print(f"    Contains different data "
                          f"(first 16 bytes: {data[:16].hex()})")

            if all(b == 0 for b in data):
                result_entry["reason"] = "zeroed"
            elif all(b == 0xFF for b in data):
                result_entry["reason"] = "unmapped_0xff"
            elif data.startswith(MAGIC_HEADER):
                result_entry["reason"] = "header_intact_data_corrupted"
            else:
                result_entry["reason"] = "different_data"
                result_entry["first_bytes"] = data[:16].hex()

        verify_results.append(result_entry)

    summary = {
        "survived": survived_count,
        "total": total_count,
        "elapsed_seconds": round(elapsed, 1),
        "vram_persistent": survived_count > 0,
    }

    if fmt == "text":
        print(f"\n{'='*50}")
        print(f"RESULTS: {survived_count}/{total_count} regions survived")
        if survived_count > 0:
            print(">>> VRAM DATA PERSISTENCE CONFIRMED <<<")
            print("NOTE: This means VRAM contents survived the state transition.")
            print("This is NOT firmware persistence (non-volatile storage).")
            print("See Phase 2 for firmware-level persistence research.")
        else:
            print("No VRAM data persistence detected for this transition type.")
    elif fmt == "json":
        print(json.dumps({
            "action": "verify",
            "summary": summary,
            "regions": verify_results,
        }, indent=2))


def cmd_test_driver_reload(bdf: str, state_file: Path, fmt: str = "text"):
    """Automated test: write, reload driver, verify."""
    if fmt == "text":
        print("=== AUTOMATED DRIVER RELOAD PERSISTENCE TEST ===")
        print(f"Target GPU: {bdf}")
        print()
        print("WARNING: This will unload and reload the NVIDIA driver.")
        print("Ensure no GPU workloads are running and display is on another GPU.")

    response = input("Continue? [y/N] ")
    if response.lower() != "y":
        print("Aborted.")
        return

    # Check for nvidia-persistenced before starting
    if is_nvidia_persistenced_running():
        if fmt == "text":
            print("\n  [!] nvidia-persistenced is running (will block driver unload)")
        response = input("  Stop nvidia-persistenced? [y/N] ")
        if response.lower() != "y":
            print("Aborted. Stop nvidia-persistenced manually first.")
            return
        if not stop_nvidia_persistenced():
            print("ERROR: Failed to stop nvidia-persistenced.", file=sys.stderr)
            sys.exit(1)

    # Phase 1: Write patterns
    if fmt == "text":
        print("\n--- Phase 1: Writing test patterns ---")
    cmd_write(bdf, state_file, fmt="text")  # Always text for interactive

    # Unload driver
    if fmt == "text":
        print("\n--- Unloading NVIDIA driver ---")

    unload_cmds = [
        ["modprobe", "-r", "nvidia_drm"],
        ["modprobe", "-r", "nvidia_modeset"],
        ["modprobe", "-r", "nvidia_uvm"],
        ["modprobe", "-r", "nvidia"],
    ]
    for cmd in unload_cmds:
        if fmt == "text":
            print(f"  $ {' '.join(cmd)}")
        result = subprocess.run(cmd, capture_output=True, text=True)
        if result.returncode != 0:
            if fmt == "text":
                print(f"    Warning: {result.stderr.strip()}")

    # Verify driver actually unloaded
    if is_nvidia_driver_loaded():
        print("\nERROR: NVIDIA driver is still loaded after modprobe -r.",
              file=sys.stderr)
        print("Common causes:", file=sys.stderr)
        print("  - GPU is in use (display, compute workload)", file=sys.stderr)
        print("  - nvidia-persistenced is holding device open", file=sys.stderr)
        print("  - Another process has /dev/nvidia* open", file=sys.stderr)
        print("\nCheck with: lsof /dev/nvidia*", file=sys.stderr)
        sys.exit(1)

    if fmt == "text":
        print("  Driver successfully unloaded (verified via lsmod)")

    # Reload driver
    if fmt == "text":
        print("\n--- Reloading NVIDIA driver ---")
    result = subprocess.run(
        ["modprobe", "nvidia"], capture_output=True, text=True)
    if result.returncode != 0:
        print(f"  Error reloading: {result.stderr}", file=sys.stderr)
        print("  Try manual reload and then run 'verify'", file=sys.stderr)
        sys.exit(1)

    # Wait for driver to be ready (poll instead of arbitrary sleep)
    if fmt == "text":
        print("  Waiting for driver to initialize...")
    if not wait_for_driver(timeout=15):
        print("  Warning: Driver may not be fully initialized", file=sys.stderr)

    if fmt == "text":
        print("  Driver reloaded and ready")

    # Phase 2: Verify
    if fmt == "text":
        print("\n--- Phase 2: Verifying persistence ---")
    cmd_verify(bdf, state_file, fmt)


def main():
    parser = argparse.ArgumentParser(
        description="VRAM Persistence Test Suite")
    parser.add_argument(
        "command", choices=["write", "verify", "test-driver-reload"],
        help="Command to execute")
    parser.add_argument(
        "--bdf", type=str, required=True,
        help="PCI BDF address of target GPU (e.g., 01:00.0)")
    parser.add_argument(
        "--state-file", type=Path, default=DEFAULT_STATE_FILE,
        help=f"Path to state file (default: {DEFAULT_STATE_FILE})")
    parser.add_argument(
        "--format", choices=["text", "json"], default="text",
        help="Output format (default: text)")

    args = parser.parse_args()

    if os.geteuid() != 0:
        print("Error: This tool requires root privileges (sudo)",
              file=sys.stderr)
        sys.exit(1)

    if args.command == "write":
        cmd_write(args.bdf, args.state_file, args.format)
    elif args.command == "verify":
        cmd_verify(args.bdf, args.state_file, args.format)
    elif args.command == "test-driver-reload":
        cmd_test_driver_reload(args.bdf, args.state_file, args.format)


if __name__ == "__main__":
    main()
