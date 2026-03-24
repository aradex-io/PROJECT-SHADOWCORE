#!/usr/bin/env python3
"""
GSP Firmware Blob Extraction & Triage Tool

Extracts and analyzes NVIDIA GSP firmware blobs from driver packages.
Identifies architecture, sections, strings, and cryptographic constants.

Usage:
    python extract_gsp_firmware.py <firmware.bin> [--output-dir ./output]
    python extract_gsp_firmware.py --scan-system  # Find all installed firmware blobs
    python extract_gsp_firmware.py <firmware.bin> --format json
"""

import argparse
import hashlib
import json
import math
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

# Falcon microcode header structure (from envytools nv_pfalcon_v2.xml):
# offset 0x00: OS code offset (u32) — typically 0x100 (boot vector)
# offset 0x04: OS code size (u32)
# offset 0x08: OS data offset (u32)
# offset 0x0c: OS data size (u32)
# offset 0x10: num apps (u32)
# The boot vector at 0x100 is a distinguishing feature.
FALCON_BOOT_VECTOR_OFFSET = 0x100
FALCON_HEADER_SIZE = 0x14  # Minimum header before app entries


def find_system_firmware() -> list[Path]:
    """Scan system paths for NVIDIA GSP firmware blobs."""
    found = []
    for search_path in FIRMWARE_SEARCH_PATHS:
        base = Path(search_path)
        if not base.exists():
            continue
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

    # Check for Falcon microcode header patterns (envytools-based heuristic)
    # Falcon header: os_code_offset, os_code_size, os_data_offset,
    #                os_data_size, num_apps
    # os_code_offset is typically 0x100 (the boot vector location)
    if len(data) >= FALCON_HEADER_SIZE:
        os_code_off, os_code_sz, os_data_off, os_data_sz, num_apps = \
            struct.unpack_from("<5I", data, 0)
        if (os_code_off == FALCON_BOOT_VECTOR_OFFSET
                and 0 < os_code_sz < len(data)
                and os_data_off < len(data)
                and 0 < os_data_sz < len(data)
                and num_apps < 64):
            return "Falcon (microcode header detected)"

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
        # Entropy-based section detection for non-ELF blobs
        chunk_size = 4096
        for i in range(0, len(data), chunk_size):
            chunk = data[i:i + chunk_size]
            if len(chunk) < chunk_size:
                break
            freq = [0] * 256
            for b in chunk:
                freq[b] += 1
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


INTERESTING_KEYWORDS = [
    "boot", "init", "gsp", "falcon", "riscv", "sign", "verify",
    "hash", "crypt", "key", "cert", "auth", "secur", "dma",
    "error", "fail", "version", "nvidia", "copyright",
]


def triage_firmware(filepath: Path, min_string_length: int = 10) -> dict:
    """Perform full triage analysis on a firmware blob. Returns structured results."""
    data = filepath.read_bytes()

    hashes = compute_hashes(data)
    arch = identify_architecture(data)
    crypto = find_crypto_constants(data)
    strings = find_strings(data, min_length=min_string_length)
    sections = analyze_sections(data)

    interesting_strings = [
        {"offset": offset, "value": s}
        for offset, s in strings
        if any(kw in s.lower() for kw in INTERESTING_KEYWORDS)
    ]

    return {
        "file": str(filepath),
        "size": hashes["size"],
        "md5": hashes["md5"],
        "sha256": hashes["sha256"],
        "architecture": arch,
        "crypto_constants": [
            {"name": name, "offset": offset}
            for name, offset in crypto
        ],
        "strings_total": len(strings),
        "strings_interesting": interesting_strings,
        "strings_all": [
            {"offset": offset, "value": s}
            for offset, s in strings
        ],
        "sections": sections,
    }


def print_triage(result: dict):
    """Print triage results in human-readable format."""
    print(f"\n{'='*70}")
    print(f"FIRMWARE TRIAGE: {result['file']}")
    print(f"{'='*70}")

    print(f"\nSize:   {result['size']:,} bytes ({result['size'] / 1024 / 1024:.2f} MB)")
    print(f"MD5:    {result['md5']}")
    print(f"SHA256: {result['sha256']}")

    print(f"\nArchitecture: {result['architecture']}")

    if result["crypto_constants"]:
        print(f"\nCryptographic constants found:")
        for c in result["crypto_constants"]:
            print(f"  {c['name']} at offset 0x{c['offset']:08x}")
    else:
        print(f"\nNo known crypto constants found (may use custom/obfuscated)")

    print(f"\nTotal strings found: {result['strings_total']}")
    print(f"Interesting strings (keyword matches):")
    for s in result["strings_interesting"]:
        print(f"  0x{s['offset']:08x}: {s['value'][:100]}")

    sections = result["sections"]
    if sections and "error" not in sections[0]:
        print(f"\nSection analysis:")
        for s in sections[:20]:
            if "name" in s:
                print(f"  {s['name']:20s} offset=0x{s['offset']:08x} "
                      f"size=0x{s['size']:08x} addr=0x{s['addr']:08x}")
            elif "entropy" in s:
                print(f"  0x{s['offset']:08x} entropy={s['entropy']:.2f} "
                      f"({s['type']})")

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
    parser.add_argument(
        "--format", choices=["text", "json"], default="text",
        help="Output format (default: text)")

    args = parser.parse_args()

    if args.scan_system:
        print("Scanning system for NVIDIA GSP firmware blobs...",
              file=sys.stderr if args.format == "json" else sys.stdout)
        found = find_system_firmware()
        if not found:
            print("No GSP firmware blobs found in standard locations.",
                  file=sys.stderr)
            print("Try installing NVIDIA drivers or specify path manually.",
                  file=sys.stderr)
            return

        results = []
        for path in found:
            result = triage_firmware(path, args.min_string_length)
            results.append(result)
            if args.format == "text":
                print_triage(result)

        if args.format == "json":
            print(json.dumps(results, indent=2))

        if args.output_dir:
            args.output_dir.mkdir(parents=True, exist_ok=True)
            for result in results:
                _save_outputs(result, args.output_dir, args.format)

    elif args.firmware:
        if not args.firmware.exists():
            print(f"Error: {args.firmware} not found", file=sys.stderr)
            sys.exit(1)

        result = triage_firmware(args.firmware, args.min_string_length)

        if args.format == "json":
            print(json.dumps(result, indent=2))
        else:
            print_triage(result)

        if args.output_dir:
            args.output_dir.mkdir(parents=True, exist_ok=True)
            _save_outputs(result, args.output_dir, args.format)

    else:
        parser.print_help()


def _save_outputs(result: dict, output_dir: Path, fmt: str):
    """Save triage outputs to files."""
    stem = Path(result["file"]).stem

    if fmt == "json":
        out_file = output_dir / f"{stem}_triage.json"
        out_file.write_text(json.dumps(result, indent=2))
        print(f"JSON saved to: {out_file}", file=sys.stderr)
    else:
        # Save strings
        strings_file = output_dir / f"{stem}_strings.txt"
        with open(strings_file, "w") as f:
            for s in result["strings_all"]:
                f.write(f"0x{s['offset']:08x}: {s['value']}\n")
        print(f"Strings saved to: {strings_file}")

        # Save triage summary
        summary_file = output_dir / f"{stem}_triage.txt"
        with open(summary_file, "w") as f:
            f.write(f"File: {result['file']}\n")
            f.write(f"Size: {result['size']}\n")
            f.write(f"SHA256: {result['sha256']}\n")
            f.write(f"Architecture: {result['architecture']}\n")
            f.write(f"Crypto constants: {len(result['crypto_constants'])}\n")
            f.write(f"Strings: {result['strings_total']}\n")
        print(f"Summary saved to: {summary_file}")


if __name__ == "__main__":
    main()
