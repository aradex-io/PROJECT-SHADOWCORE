#!/usr/bin/env python3
"""Unit tests for GSP Firmware Extraction & Triage tool."""

import hashlib
import math
import struct
import sys
import tempfile
from pathlib import Path
from unittest import mock

import pytest

# Add tools to path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "tools" / "firmware-extract"))
import extract_gsp_firmware as fw


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def elf_riscv_blob() -> bytes:
    """Minimal ELF header identifying as RISC-V."""
    header = bytearray(64)
    header[0:4] = b"\x7fELF"
    header[4] = 2       # 64-bit
    header[5] = 1       # little-endian
    struct.pack_into("<H", header, 18, 0xF3)  # e_machine = RISC-V
    return bytes(header)


@pytest.fixture
def elf_arm_blob() -> bytes:
    header = bytearray(64)
    header[0:4] = b"\x7fELF"
    struct.pack_into("<H", header, 18, 0x28)  # ARM
    return bytes(header)


@pytest.fixture
def falcon_like_blob() -> bytes:
    """Blob that looks like Falcon microcode (two small 32-bit words)."""
    return struct.pack("<II", 0x0200, 0x0400) + b"\x00" * 56


@pytest.fixture
def firmware_file(tmp_path: Path, elf_riscv_blob: bytes) -> Path:
    """Write a fake firmware blob to disk."""
    p = tmp_path / "gsp_ad10x.bin"
    # Pad to 8 KB so entropy analysis gets at least one chunk
    data = elf_riscv_blob + b"\x00" * (8192 - len(elf_riscv_blob))
    p.write_bytes(data)
    return p


# ---------------------------------------------------------------------------
# compute_hashes
# ---------------------------------------------------------------------------

class TestComputeHashes:
    def test_returns_md5_sha256_size(self):
        data = b"hello"
        h = fw.compute_hashes(data)
        assert h["md5"] == hashlib.md5(data).hexdigest()
        assert h["sha256"] == hashlib.sha256(data).hexdigest()
        assert h["size"] == 5

    def test_empty_data(self):
        h = fw.compute_hashes(b"")
        assert h["size"] == 0


# ---------------------------------------------------------------------------
# identify_architecture
# ---------------------------------------------------------------------------

class TestIdentifyArchitecture:
    def test_riscv_elf(self, elf_riscv_blob):
        assert fw.identify_architecture(elf_riscv_blob) == "RISC-V"

    def test_arm_elf(self, elf_arm_blob):
        assert fw.identify_architecture(elf_arm_blob) == "ARM"

    def test_unknown_elf_machine(self):
        header = bytearray(64)
        header[0:4] = b"\x7fELF"
        struct.pack_into("<H", header, 18, 0xFF)
        result = fw.identify_architecture(bytes(header))
        assert "unknown machine" in result

    def test_falcon_heuristic(self, falcon_like_blob):
        assert "Falcon" in fw.identify_architecture(falcon_like_blob)

    def test_unknown_blob(self):
        # Large first words rule out Falcon heuristic
        data = struct.pack("<II", 0xDEADBEEF, 0xCAFEBABE)
        assert "Unknown" in fw.identify_architecture(data)

    def test_too_short(self):
        assert "Unknown" in fw.identify_architecture(b"\x00")


# ---------------------------------------------------------------------------
# find_strings
# ---------------------------------------------------------------------------

class TestFindStrings:
    def test_extracts_long_strings(self):
        data = b"\x00" * 10 + b"nvidia_boot_init" + b"\x00" * 10
        strings = fw.find_strings(data, min_length=8)
        assert len(strings) == 1
        assert strings[0][1] == "nvidia_boot_init"
        assert strings[0][0] == 10

    def test_respects_min_length(self):
        data = b"short" + b"\x00" + b"this_is_long_enough"
        assert len(fw.find_strings(data, min_length=10)) == 1

    def test_empty_data(self):
        assert fw.find_strings(b"", min_length=4) == []

    def test_string_at_end_of_data(self):
        data = b"\x00" + b"trailing_string"
        strings = fw.find_strings(data, min_length=8)
        assert len(strings) == 1
        assert strings[0][1] == "trailing_string"

    def test_multiple_strings(self):
        data = b"aaaaaaaaaa" + b"\x00" + b"bbbbbbbbbb"
        strings = fw.find_strings(data, min_length=8)
        assert len(strings) == 2


# ---------------------------------------------------------------------------
# find_crypto_constants
# ---------------------------------------------------------------------------

class TestFindCryptoConstants:
    def test_finds_sha256_init(self):
        sha_init = fw.CRYPTO_CONSTANTS["SHA256_INIT"]
        data = b"\x00" * 100 + sha_init + b"\x00" * 100
        results = fw.find_crypto_constants(data)
        names = [r[0] for r in results]
        assert "SHA256_INIT" in names
        offsets = [r[1] for r in results if r[0] == "SHA256_INIT"]
        assert offsets[0] == 100

    def test_finds_aes_sbox(self):
        aes_start = fw.CRYPTO_CONSTANTS["AES_SBOX_START"]
        data = aes_start + b"\x00" * 200
        results = fw.find_crypto_constants(data)
        assert any(r[0] == "AES_SBOX_START" for r in results)

    def test_no_constants(self):
        assert fw.find_crypto_constants(b"\x00" * 1024) == []

    def test_multiple_occurrences(self):
        sha_init = fw.CRYPTO_CONSTANTS["SHA256_INIT"]
        data = sha_init + b"\x00" * 16 + sha_init
        results = [r for r in fw.find_crypto_constants(data) if r[0] == "SHA256_INIT"]
        assert len(results) == 2


# ---------------------------------------------------------------------------
# analyze_sections (non-ELF entropy path)
# ---------------------------------------------------------------------------

class TestAnalyzeSections:
    def test_low_entropy_section(self):
        data = b"\x00" * 4096 * 2
        sections = fw.analyze_sections(data)
        assert len(sections) >= 1
        assert sections[0]["type"] == "low_entropy"
        assert sections[0]["entropy"] == 0.0

    def test_high_entropy_section(self):
        # All 256 byte values equally → entropy ≈ 8.0
        data = bytes(range(256)) * 16  # exactly 4096
        sections = fw.analyze_sections(data)
        assert sections[0]["entropy"] >= 7.5
        assert sections[0]["type"] == "high_entropy"

    def test_partial_chunk_skipped(self):
        data = b"\x00" * 5000  # one full 4096 chunk + partial
        sections = fw.analyze_sections(data)
        assert len(sections) == 1  # partial chunk not included


# ---------------------------------------------------------------------------
# find_system_firmware (mocked filesystem)
# ---------------------------------------------------------------------------

class TestFindSystemFirmware:
    def test_finds_blobs(self, tmp_path):
        nvidia_dir = tmp_path / "lib" / "firmware" / "nvidia"
        nvidia_dir.mkdir(parents=True)
        (nvidia_dir / "gsp_ad10x.bin").write_bytes(b"\x00")
        (nvidia_dir / "gsp_ga10x.bin").write_bytes(b"\x00")

        with mock.patch.object(fw, "FIRMWARE_SEARCH_PATHS", [str(nvidia_dir.parent)]):
            # The parent of the nvidia dir is searched, but rglob matches in nvidia/
            pass

        # Directly patch the constant to point at our tmp dir
        with mock.patch.object(fw, "FIRMWARE_SEARCH_PATHS", [str(nvidia_dir)]):
            found = fw.find_system_firmware()
        assert len(found) == 2

    def test_returns_empty_when_no_paths(self):
        with mock.patch.object(fw, "FIRMWARE_SEARCH_PATHS", ["/nonexistent/path"]):
            assert fw.find_system_firmware() == []


# ---------------------------------------------------------------------------
# triage_firmware (integration: writes output files)
# ---------------------------------------------------------------------------

class TestTriageFirmware:
    def test_writes_output_files(self, firmware_file, tmp_path):
        output_dir = tmp_path / "output"
        fw.triage_firmware(firmware_file, output_dir)
        assert (output_dir / f"{firmware_file.stem}_strings.txt").exists()
        assert (output_dir / f"{firmware_file.stem}_triage.txt").exists()

    def test_no_output_dir(self, firmware_file, capsys):
        fw.triage_firmware(firmware_file, output_dir=None)
        captured = capsys.readouterr()
        assert "SHA256:" in captured.out


# ---------------------------------------------------------------------------
# CLI (--help / argument parsing)
# ---------------------------------------------------------------------------

class TestCLI:
    def test_help_flag(self):
        with pytest.raises(SystemExit) as exc_info:
            with mock.patch("sys.argv", ["extract_gsp_firmware.py", "--help"]):
                fw.main()
        assert exc_info.value.code == 0

    def test_missing_firmware_file(self, tmp_path):
        missing = tmp_path / "nope.bin"
        with mock.patch("sys.argv", ["extract_gsp_firmware.py", str(missing)]):
            with pytest.raises(SystemExit) as exc_info:
                fw.main()
            assert exc_info.value.code == 1
