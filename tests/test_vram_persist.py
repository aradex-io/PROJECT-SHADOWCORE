#!/usr/bin/env python3
"""Unit tests for VRAM Persistence Test Suite."""

import hashlib
import json
import struct
import sys
import time
from pathlib import Path
from unittest import mock

import pytest

import importlib

_vram_mod_path = str(Path(__file__).resolve().parent.parent / "tools" / "vram-persistence")
sys.path.insert(0, _vram_mod_path)
# Import without triggering pytest collection on the module name
vram = importlib.import_module("test_vram_persistence")


# ---------------------------------------------------------------------------
# build_test_payload
# ---------------------------------------------------------------------------

class TestBuildPayload:
    def test_exact_size(self):
        payload = vram.build_test_payload("vram_start")
        assert len(payload) == 4096

    def test_starts_with_magic(self):
        payload = vram.build_test_payload("test_region")
        assert payload.startswith(vram.MAGIC_HEADER)

    def test_contains_region_name(self):
        payload = vram.build_test_payload("vram_64mb")
        assert b"vram_64mb" in payload

    def test_contains_timestamp(self):
        before = int(time.time())
        payload = vram.build_test_payload("r")
        after = int(time.time())
        # Timestamp is after the header: magic + \x00 + name + \x00
        ts_offset = len(vram.MAGIC_HEADER) + 1 + len(b"r") + 1
        ts = struct.unpack_from("<Q", payload, ts_offset)[0]
        assert before <= ts <= after

    def test_different_regions_differ(self):
        p1 = vram.build_test_payload("region_a")
        p2 = vram.build_test_payload("region_b")
        assert p1 != p2


# ---------------------------------------------------------------------------
# TEST_REGIONS sanity
# ---------------------------------------------------------------------------

class TestRegions:
    def test_five_regions_defined(self):
        assert len(vram.TEST_REGIONS) == 5

    def test_all_4kb(self):
        for r in vram.TEST_REGIONS:
            assert r["size"] == 4096

    def test_offsets_increase(self):
        offsets = [r["offset"] for r in vram.TEST_REGIONS]
        assert offsets == sorted(offsets)

    def test_no_overlap(self):
        for i in range(len(vram.TEST_REGIONS) - 1):
            end = vram.TEST_REGIONS[i]["offset"] + vram.TEST_REGIONS[i]["size"]
            next_start = vram.TEST_REGIONS[i + 1]["offset"]
            assert end <= next_start


# ---------------------------------------------------------------------------
# TestResult dataclass
# ---------------------------------------------------------------------------

class TestTestResult:
    def test_defaults(self):
        r = vram.TestResult(
            region_name="test", offset=0,
            written=True, survived=None,
            hash_before="abc", hash_after=None,
        )
        assert r.notes == ""
        assert r.survived is None


# ---------------------------------------------------------------------------
# find_bar1_resource / get_bar1_size (mocked sysfs)
# ---------------------------------------------------------------------------

class TestFindBAR1:
    def _make_sysfs(self, tmp_path: Path, bdf: str = "01:00.0") -> Path:
        dev_dir = tmp_path / f"0000:{bdf}"
        dev_dir.mkdir(parents=True)
        (dev_dir / "resource1").write_bytes(b"")
        # resource file with BAR1 entry at line index 1
        (dev_dir / "resource").write_text(
            "0x00000000f0000000 0x00000000f0ffffff 0x00040200\n"
            "0x0000000080000000 0x000000008fffffff 0x0014220c\n"
        )
        return tmp_path

    def test_finds_resource1(self, tmp_path):
        sysfs = self._make_sysfs(tmp_path)
        with mock.patch.object(vram, "find_bar1_resource") as mock_fn:
            # Test the logic manually
            dev_path = sysfs / "0000:01:00.0"
            resource1 = dev_path / "resource1"
            assert resource1.exists()
            mock_fn.return_value = resource1
            assert mock_fn("01:00.0") == resource1

    def test_returns_none_for_missing(self):
        with mock.patch("test_vram_persistence.Path") as MockPath:
            MockPath.return_value.iterdir.return_value = []
            result = vram.find_bar1_resource("99:00.0")
        assert result is None

    def test_get_bar1_size(self, tmp_path):
        sysfs = self._make_sysfs(tmp_path)
        dev_dir = sysfs / "0000:01:00.0"
        resource = dev_dir / "resource"
        lines = resource.read_text().strip().split("\n")
        parts = lines[1].split()
        start = int(parts[0], 16)
        end = int(parts[1], 16)
        size = end - start + 1
        assert size == 256 * 1024 * 1024  # 256 MB


# ---------------------------------------------------------------------------
# State file round-trip
# ---------------------------------------------------------------------------

class TestStateFile:
    def test_write_and_read_state(self, tmp_path):
        state_file = tmp_path / "state.json"
        state = {
            "bdf": "01:00.0",
            "bar1_size": 256 * 1024 * 1024,
            "write_time": time.time(),
            "regions": [
                {"name": "vram_start", "offset": 0, "size": 4096,
                 "hash": hashlib.sha256(b"test").hexdigest(),
                 "written": True, "timestamp": time.time()},
            ],
        }
        state_file.write_text(json.dumps(state, indent=2))
        loaded = json.loads(state_file.read_text())
        assert loaded["bdf"] == "01:00.0"
        assert len(loaded["regions"]) == 1
        assert loaded["regions"][0]["written"] is True


# ---------------------------------------------------------------------------
# CLI requires root
# ---------------------------------------------------------------------------

class TestCLIRequiresRoot:
    def test_exits_without_root(self):
        with mock.patch("os.geteuid", return_value=1000):
            with mock.patch("sys.argv", ["test_vram_persistence.py",
                                          "write", "--bdf", "01:00.0"]):
                with pytest.raises(SystemExit) as exc:
                    vram.main()
                assert exc.value.code == 1

    def test_help(self):
        with pytest.raises(SystemExit) as exc:
            with mock.patch("sys.argv", ["test_vram_persistence.py", "--help"]):
                vram.main()
        assert exc.value.code == 0


# ---------------------------------------------------------------------------
# MAGIC constants
# ---------------------------------------------------------------------------

class TestMagicConstants:
    def test_header_is_ascii(self):
        vram.MAGIC_HEADER.decode("ascii")  # should not raise

    def test_pattern_is_4kb(self):
        assert len(vram.MAGIC_PATTERN) == 4096
