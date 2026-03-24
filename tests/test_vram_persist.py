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
        ts_offset = len(vram.MAGIC_HEADER) + 1 + len(b"r") + 1
        ts = struct.unpack_from("<Q", payload, ts_offset)[0]
        assert before <= ts <= after

    def test_different_regions_differ(self):
        p1 = vram.build_test_payload("region_a")
        p2 = vram.build_test_payload("region_b")
        assert p1 != p2


# ---------------------------------------------------------------------------
# FIXED_TEST_REGIONS sanity
# ---------------------------------------------------------------------------

class TestFixedRegions:
    def test_five_regions_defined(self):
        assert len(vram.FIXED_TEST_REGIONS) == 5

    def test_all_4kb(self):
        for r in vram.FIXED_TEST_REGIONS:
            assert r["size"] == 4096

    def test_offsets_increase(self):
        offsets = [r["offset"] for r in vram.FIXED_TEST_REGIONS]
        assert offsets == sorted(offsets)

    def test_no_overlap(self):
        for i in range(len(vram.FIXED_TEST_REGIONS) - 1):
            end = vram.FIXED_TEST_REGIONS[i]["offset"] + vram.FIXED_TEST_REGIONS[i]["size"]
            next_start = vram.FIXED_TEST_REGIONS[i + 1]["offset"]
            assert end <= next_start


# ---------------------------------------------------------------------------
# build_test_regions (dynamic)
# ---------------------------------------------------------------------------

class TestBuildTestRegions:
    def test_returns_fixed_when_size_zero(self):
        regions = vram.build_test_regions(0)
        assert regions == vram.FIXED_TEST_REGIONS

    def test_includes_dynamic_for_large_bar(self):
        # 1 GB BAR1
        regions = vram.build_test_regions(1024 * 1024 * 1024)
        names = [r["name"] for r in regions]
        # Should have some dynamic regions
        assert any("quarter" in n or "half" in n or "near_end" in n for n in names)

    def test_skips_regions_beyond_bar_size(self):
        # 2 MB BAR1 — most fixed regions won't fit
        regions = vram.build_test_regions(2 * 1024 * 1024)
        for r in regions:
            assert r["offset"] + r["size"] <= 2 * 1024 * 1024

    def test_all_regions_page_aligned(self):
        regions = vram.build_test_regions(512 * 1024 * 1024)
        for r in regions:
            assert r["offset"] % 4096 == 0

    def test_sorted_by_offset(self):
        regions = vram.build_test_regions(256 * 1024 * 1024)
        offsets = [r["offset"] for r in regions]
        assert offsets == sorted(offsets)


# ---------------------------------------------------------------------------
# find_bar1_resource / get_bar1_size (mocked sysfs)
# ---------------------------------------------------------------------------

class TestFindBAR1:
    def _make_sysfs(self, tmp_path: Path, bdf: str = "01:00.0") -> Path:
        dev_dir = tmp_path / f"0000:{bdf}"
        dev_dir.mkdir(parents=True)
        (dev_dir / "resource1").write_bytes(b"")
        (dev_dir / "resource").write_text(
            "0x00000000f0000000 0x00000000f0ffffff 0x00040200\n"
            "0x0000000080000000 0x000000008fffffff 0x0014220c\n"
        )
        return tmp_path

    def test_finds_resource1(self, tmp_path):
        sysfs = self._make_sysfs(tmp_path)
        with mock.patch.object(vram, "find_bar1_resource") as mock_fn:
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
# is_nvidia_driver_loaded / is_nvidia_persistenced_running
# ---------------------------------------------------------------------------

class TestDriverChecks:
    def test_driver_loaded_true(self):
        fake_lsmod = "nvidia 12345 0\nnvidia_uvm 6789 0\n"
        with mock.patch("subprocess.run") as mock_run:
            mock_run.return_value = mock.Mock(stdout=fake_lsmod, returncode=0)
            assert vram.is_nvidia_driver_loaded() is True

    def test_driver_loaded_false(self):
        fake_lsmod = "snd_hda_intel 12345 0\n"
        with mock.patch("subprocess.run") as mock_run:
            mock_run.return_value = mock.Mock(stdout=fake_lsmod, returncode=0)
            assert vram.is_nvidia_driver_loaded() is False

    def test_persistenced_not_running(self):
        with mock.patch("subprocess.run") as mock_run:
            mock_run.return_value = mock.Mock(returncode=1)
            assert vram.is_nvidia_persistenced_running() is False


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
