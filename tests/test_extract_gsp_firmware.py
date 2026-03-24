#!/usr/bin/env python3
"""Unit tests for GSP Firmware Extraction & Triage tool."""

import hashlib
import json
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
    """Blob that matches the Falcon microcode header heuristic.

    Falcon header: os_code_offset=0x100, os_code_size, os_data_offset,
    os_data_size, num_apps. os_code_offset must be 0x100 (boot vector).
    """
    # os_code_offset=0x100, os_code_size=0x400, os_data_offset=0x500,
    # os_data_size=0x200, num_apps=1
    # Pad to 2KB so all offset/size fields are < len(data)
    return struct.pack("<5I", 0x100, 0x400, 0x500, 0x200, 1) + b"\x00" * (2048 - 20)


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

    def test_falcon_rejects_wrong_boot_vector(self):
        """First word must be 0x100 (boot vector offset) for Falcon."""
        # os_code_offset=0x200 (not 0x100) should NOT match
        data = struct.pack("<5I", 0x200, 0x400, 0x500, 0x200, 1) + b"\x00" * 44
        assert "Unknown" in fw.identify_architecture(data)

    def test_unknown_blob(self):
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
        data = bytes(range(256)) * 16  # exactly 4096
        sections = fw.analyze_sections(data)
        assert sections[0]["entropy"] >= 7.5
        assert sections[0]["type"] == "high_entropy"

    def test_partial_chunk_skipped(self):
        data = b"\x00" * 5000  # one full 4096 chunk + partial
        sections = fw.analyze_sections(data)
        assert len(sections) == 1


# ---------------------------------------------------------------------------
# find_system_firmware (mocked filesystem)
# ---------------------------------------------------------------------------

class TestFindSystemFirmware:
    def test_finds_blobs(self, tmp_path):
        nvidia_dir = tmp_path / "lib" / "firmware" / "nvidia"
        nvidia_dir.mkdir(parents=True)
        (nvidia_dir / "gsp_ad10x.bin").write_bytes(b"\x00")
        (nvidia_dir / "gsp_ga10x.bin").write_bytes(b"\x00")

        with mock.patch.object(fw, "FIRMWARE_SEARCH_PATHS", [str(nvidia_dir)]):
            found = fw.find_system_firmware()
        assert len(found) == 2

    def test_returns_empty_when_no_paths(self):
        with mock.patch.object(fw, "FIRMWARE_SEARCH_PATHS", ["/nonexistent/path"]):
            assert fw.find_system_firmware() == []


# ---------------------------------------------------------------------------
# triage_firmware (integration: returns structured data)
# ---------------------------------------------------------------------------

class TestTriageFirmware:
    def test_returns_structured_result(self, firmware_file):
        result = fw.triage_firmware(firmware_file)
        assert "sha256" in result
        assert "architecture" in result
        assert "strings_total" in result
        assert "sections" in result
        assert result["size"] > 0

    def test_respects_min_string_length(self, firmware_file):
        result_default = fw.triage_firmware(firmware_file, min_string_length=10)
        result_short = fw.triage_firmware(firmware_file, min_string_length=4)
        # Shorter min length should find at least as many strings
        assert result_short["strings_total"] >= result_default["strings_total"]

    def test_json_serializable(self, firmware_file):
        result = fw.triage_firmware(firmware_file)
        # Should not raise
        output = json.dumps(result, indent=2)
        parsed = json.loads(output)
        assert parsed["sha256"] == result["sha256"]

    def test_save_outputs_json(self, firmware_file, tmp_path):
        result = fw.triage_firmware(firmware_file)
        output_dir = tmp_path / "output"
        output_dir.mkdir()
        fw._save_outputs(result, output_dir, "json")
        json_file = output_dir / f"{firmware_file.stem}_triage.json"
        assert json_file.exists()
        data = json.loads(json_file.read_text())
        assert data["sha256"] == result["sha256"]

    def test_save_outputs_text(self, firmware_file, tmp_path):
        result = fw.triage_firmware(firmware_file)
        output_dir = tmp_path / "output"
        output_dir.mkdir()
        fw._save_outputs(result, output_dir, "text")
        assert (output_dir / f"{firmware_file.stem}_strings.txt").exists()
        assert (output_dir / f"{firmware_file.stem}_triage.txt").exists()


# ---------------------------------------------------------------------------
# print_triage (smoke test)
# ---------------------------------------------------------------------------

class TestPrintTriage:
    def test_prints_report(self, firmware_file, capsys):
        result = fw.triage_firmware(firmware_file)
        fw.print_triage(result)
        captured = capsys.readouterr()
        assert "SHA256:" in captured.out
        assert "Architecture:" in captured.out


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

    def test_json_format_flag(self, firmware_file, capsys):
        with mock.patch("sys.argv", ["extract_gsp_firmware.py",
                                      str(firmware_file), "--format", "json"]):
            fw.main()
        out = capsys.readouterr().out
        data = json.loads(out)
        assert "sha256" in data
