#!/usr/bin/env python3
"""
GSP Firmware Blob Extraction & Triage Tool

Extracts and analyzes NVIDIA GSP firmware blobs from driver packages.
Identifies architecture, sections, strings, and cryptographic constants.

Usage:
    python extract_gsp_firmware.py <firmware.bin> [--output-dir ./output]
    python extract_gsp_firmware.py --scan-system  # Find all installed firmware blobs
"""

import argparse
import hashlib
import os
import struct
import sys
from pathlib import Path

# Known firmware search paths
FIRMWARE_SEARCH_PATHS = [
    "/lib/firmware/nvidia/",
    "/usr/lib/firmware/nvidia/",
    "/usr/share/nvidia/firmware/",
]

# Known magic bytes for firmware identification
FALCON_MAGIC = b"\x00\x00\x00\x00"  # Placeholder — needs RE to confirm
RISCV_MAGIC = b"\x7fELF"  # RISC-V firmware may be ELF-wrapped

# Known GSP firmware filename patterns
GSP_FIRMWARE_PATTERNS = [
    "gsp_ga10x.bin",   # Ampere (GA100 series)
    "gsp_ad10x.bin",   # Ada Lovelace (AD100 series)
    "gsp_tu10x.bin",   # Turing (TU100 series)
    "gsp*.bin",        # Catch-all
]

# Crypto constants to search for (indicate signing/verification)
CRYPTO_CONSTANTS = {
    "RSA_PUBKEY_DER": bytes.fromhex("30820122300d06092a864886f70d01010105000382010f003082010a0282010100"),
    "SHA256_INIT": struct.pack("<8I",
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
        0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19),
    "AES_SBOX_START": bytes([
        0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5,
        0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76]),
}


def find_system_firmware() -> list[Path]:
    """Scan system paths for NVIDIA GSP firmware blobs."""
    found = []
    for search_path in FIRMWARE_SEARCH_PATHS:
        base = Path(search_path)
        if not base.exists():
            continue
        # Walk directory tree looking for gsp*.bin files
        for path in base.rglob("gsp*.bin"):
            if path.is_file():
                found.append(path)
    return found


def compute_hashes(data: bytes) -> dict[str, str]:
    """Compute multiple hashes for firmware identification."""
    return {
        "md5": hashlib.md5(data).hexdigest(),
        "sha256": hashlib.sha256(data).hexdigest(),
        "size": len(data),
    }


def identify_architecture(data: bytes) -> str:
    """Attempt to identify the CPU architecture of the firmware blob."""
    # Check for ELF header (RISC-V firmware is often ELF-wrapped)
    if data[:4] == b"\x7fELF":
        # Parse ELF header for machine type
        if len(data) >= 20:
            e_machine = struct.unpack_from("<H", data, 18)[0]
            arch_map = {
                0xF3: "RISC-V",
                0x03: "x86",
                0x3E: "x86_64",
                0x28: "ARM",
                0xB7: "AArch64",
            }
            return arch_map.get(e_machine, f"ELF (unknown machine: 0x{e_machine:x})")

    # Check for Falcon microcode header patterns
    # Falcon code segment starts with a specific header structure
    # TODO: Confirm Falcon header magic from envytools documentation
    if len(data) >= 8:
        word0, word1 = struct.unpack_from("<II", data, 0)
        # Falcon boot vector is typically at offset 0x100
        # Header contains code/data segment sizes
        if word0 < 0x10000 and word1 < 0x10000:
            return "Possible Falcon (needs confirmation)"

    return "Unknown (needs manual analysis)"


def find_strings(data: bytes, min_length: int = 8) -> list[tuple[int, str]]:
    """Extract printable ASCII strings from binary data."""
    strings = []
    current = b""
    start_offset = 0

    for i, byte in enumerate(data):
        if 0x20 <= byte <= 0x7e:
            if not current:
                start_offset = i
            current += bytes([byte])
        else:
            if len(current) >= min_length:
                strings.append((start_offset, current.decode("ascii")))
            current = b""

    if len(current) >= min_length:
        strings.append((start_offset, current.decode("ascii")))

    return strings


def find_crypto_constants(data: bytes) -> list[tuple[str, int]]:
    """Search for known cryptographic constants in the firmware."""
    found = []
    for name, pattern in CRYPTO_CONSTANTS.items():
        offset = data.find(pattern)
        while offset != -1:
            found.append((name, offset))
            offset = data.find(pattern, offset + 1)
    return found


def analyze_sections(data: bytes) -> list[dict]:
    """Attempt to identify code/data sections in the firmware blob."""
    sections = []

    # If it's an ELF, parse sections properly
    if data[:4] == b"\x7fELF":
        try:
            from elftools.elf.elffile import ELFFile
            from io import BytesIO
            elf = ELFFile(BytesIO(data))
            for section in elf.iter_sections():
                sections.append({
                    "name": section.name,
                    "type": section["sh_type"],
                    "offset": section["sh_offset"],
                    "size": section["sh_size"],
                    "addr": section["sh_addr"],
                    "flags": section["sh_flags"],
                })
        except Exception as e:
            sections.append({"error": f"ELF parse failed: {e}"})
    else:
        # For non-ELF blobs, do entropy-based section detection
        # High entropy = compressed/encrypted, low entropy = code/data
        chunk_size = 4096
        for i in range(0, len(data), chunk_size):
            chunk = data[i:i + chunk_size]
            if len(chunk) < chunk_size:
                break
            # Simple byte frequency entropy estimate
            freq = [0] * 256
            for b in chunk:
                freq[b] += 1
            import math
            entropy = -sum(
                (f / len(chunk)) * math.log2(f / len(chunk))
                for f in freq if f > 0
            )
            sections.append({
                "offset": i,
                "size": chunk_size,
                "entropy": round(entropy, 2),
                "type": "high_entropy" if entropy > 7.5 else
                        "code/data" if entropy > 4.0 else "low_entropy",
            })

    return sections


def triage_firmware(filepath: Path, output_dir: Path | None = None):
    """Perform full triage analysis on a firmware blob."""
    print(f"\n{'='*70}")
    print(f"FIRMWARE TRIAGE: {filepath}")
    print(f"{'='*70}")

    data = filepath.read_bytes()

    # Basic info
    hashes = compute_hashes(data)
    print(f"\nSize:   {hashes['size']:,} bytes ({hashes['size'] / 1024 / 1024:.2f} MB)")
    print(f"MD5:    {hashes['md5']}")
    print(f"SHA256: {hashes['sha256']}")

    # Architecture
    arch = identify_architecture(data)
    print(f"\nArchitecture: {arch}")

    # Crypto constants
    crypto = find_crypto_constants(data)
    if crypto:
        print(f"\nCryptographic constants found:")
        for name, offset in crypto:
            print(f"  {name} at offset 0x{offset:08x}")
    else:
        print(f"\nNo known crypto constants found (may use custom/obfuscated)")

    # Strings (interesting ones)
    strings = find_strings(data, min_length=10)
    interesting_keywords = [
        "boot", "init", "gsp", "falcon", "riscv", "sign", "verify",
        "hash", "crypt", "key", "cert", "auth", "secur", "dma",
        "error", "fail", "version", "nvidia", "copyright",
    ]
    print(f"\nTotal strings found: {len(strings)}")
    print(f"Interesting strings (keyword matches):")
    for offset, s in strings:
        if any(kw in s.lower() for kw in interesting_keywords):
            print(f"  0x{offset:08x}: {s[:100]}")

    # Sections
    sections = analyze_sections(data)
    if sections and "error" not in sections[0]:
        print(f"\nSection analysis:")
        for s in sections[:20]:  # First 20 only
            if "name" in s:
                print(f"  {s['name']:20s} offset=0x{s['offset']:08x} "
                      f"size=0x{s['size']:08x} addr=0x{s['addr']:08x}")
            elif "entropy" in s:
                print(f"  0x{s['offset']:08x} entropy={s['entropy']:.2f} "
                      f"({s['type']})")

    # Save outputs
    if output_dir:
        output_dir.mkdir(parents=True, exist_ok=True)
        # Save strings
        strings_file = output_dir / f"{filepath.stem}_strings.txt"
        with open(strings_file, "w") as f:
            for offset, s in strings:
                f.write(f"0x{offset:08x}: {s}\n")
        print(f"\nStrings saved to: {strings_file}")

        # Save triage summary
        summary_file = output_dir / f"{filepath.stem}_triage.txt"
        with open(summary_file, "w") as f:
            f.write(f"File: {filepath}\n")
            f.write(f"Size: {hashes['size']}\n")
            f.write(f"SHA256: {hashes['sha256']}\n")
            f.write(f"Architecture: {arch}\n")
            f.write(f"Crypto constants: {len(crypto)}\n")
            f.write(f"Strings: {len(strings)}\n")
        print(f"Summary saved to: {summary_file}")

    print()


def main():
    parser = argparse.ArgumentParser(
        description="GSP Firmware Blob Extraction & Triage Tool")
    parser.add_argument(
        "firmware", nargs="?", type=Path,
        help="Path to firmware .bin file to analyze")
    parser.add_argument(
        "--scan-system", action="store_true",
        help="Scan system paths for installed NVIDIA firmware blobs")
    parser.add_argument(
        "--output-dir", "-o", type=Path, default=None,
        help="Directory to save analysis outputs")
    parser.add_argument(
        "--min-string-length", type=int, default=10,
        help="Minimum string length for extraction (default: 10)")

    args = parser.parse_args()

    if args.scan_system:
        print("Scanning system for NVIDIA GSP firmware blobs...")
        found = find_system_firmware()
        if not found:
            print("No GSP firmware blobs found in standard locations.")
            print("Try installing NVIDIA drivers or specify path manually.")
            return
        print(f"Found {len(found)} firmware blob(s):")
        for path in found:
            triage_firmware(path, args.output_dir)

    elif args.firmware:
        if not args.firmware.exists():
            print(f"Error: {args.firmware} not found", file=sys.stderr)
            sys.exit(1)
        triage_firmware(args.firmware, args.output_dir)

    else:
        parser.print_help()


if __name__ == "__main__":
    main()
