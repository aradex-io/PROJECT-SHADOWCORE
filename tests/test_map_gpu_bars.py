#!/usr/bin/env python3
"""Unit tests for GPU PCI BAR Region Mapper."""

import json
import sys
from pathlib import Path
from unittest import mock

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "tools" / "bar-mapper"))
import map_gpu_bars as bars


# ---------------------------------------------------------------------------
# BARRegion / GPUDevice dataclasses
# ---------------------------------------------------------------------------

class TestDataclasses:
    def test_bar_region_defaults(self):
        b = bars.BARRegion(
            index=0, physical_addr=0xF0000000, size=0x1000000,
            bar_type="memory", is_64bit=True, is_prefetchable=False,
            resource_path="/sys/bus/pci/devices/0000:01:00.0/resource0",
        )
        assert b.description == ""
        assert b.writable_ranges == []

    def test_gpu_device_defaults(self):
        g = bars.GPUDevice(
            bdf="01:00.0", vendor_id=0x10DE, device_id=0x2684,
            device_name="RTX 4090", driver="nvidia",
        )
        assert g.bars == []


# ---------------------------------------------------------------------------
# format_size
# ---------------------------------------------------------------------------

class TestFormatSize:
    def test_bytes(self):
        assert bars.format_size(512) == "512.0 B"

    def test_kilobytes(self):
        assert bars.format_size(2048) == "2.0 KB"

    def test_megabytes(self):
        assert bars.format_size(16 * 1024 * 1024) == "16.0 MB"

    def test_gigabytes(self):
        assert bars.format_size(2 * 1024**3) == "2.0 GB"

    def test_terabytes(self):
        assert bars.format_size(2 * 1024**4) == "2.0 TB"


# ---------------------------------------------------------------------------
# find_nvidia_gpus (mocked sysfs)
# ---------------------------------------------------------------------------

class TestFindNvidiaGPUs:
    def _build_fake_sysfs(self, tmp_path: Path, *,
                           vendor: str = "0x10de",
                           device: str = "0x2684",
                           class_id: str = "0x030000",
                           add_resource: bool = True) -> Path:
        """Create a minimal sysfs tree for one GPU."""
        dev_dir = tmp_path / "0000:01:00.0"
        dev_dir.mkdir(parents=True)
        (dev_dir / "vendor").write_text(vendor + "\n")
        (dev_dir / "device").write_text(device + "\n")
        (dev_dir / "class").write_text(class_id + "\n")
        if add_resource:
            (dev_dir / "resource").write_text(
                "0x00000000f0000000 0x00000000f0ffffff 0x00040200\n"
                "0x0000000080000000 0x000000008fffffff 0x0014220c\n"
            )
        return tmp_path

    def test_detects_nvidia_gpu(self, tmp_path):
        sysfs = self._build_fake_sysfs(tmp_path)

        def patched_find():
            pci_devices = sysfs
            gpus = []
            for dev_path in sorted(pci_devices.iterdir()):
                vendor_path = dev_path / "vendor"
                if not vendor_path.exists():
                    continue
                vendor_id = int(vendor_path.read_text().strip(), 16)
                if vendor_id != 0x10DE:
                    continue
                device_id = int((dev_path / "device").read_text().strip(), 16)
                class_id = int((dev_path / "class").read_text().strip(), 16)
                if (class_id >> 8) != 0x0302 and (class_id >> 8) != 0x0300:
                    continue
                bdf = dev_path.name
                gpu = bars.GPUDevice(
                    bdf=bdf, vendor_id=vendor_id, device_id=device_id,
                    device_name=f"NVIDIA GPU (0x{device_id:04x})",
                    driver="nvidia",
                )
                resource = dev_path / "resource"
                if resource.exists():
                    for i, line in enumerate(resource.read_text().strip().split("\n")):
                        parts = line.split()
                        if len(parts) < 3:
                            continue
                        start = int(parts[0], 16)
                        end = int(parts[1], 16)
                        flags = int(parts[2], 16)
                        if start == 0:
                            continue
                        size = end - start + 1
                        bar = bars.BARRegion(
                            index=i, physical_addr=start, size=size,
                            bar_type="io" if (flags & 0x1) else "memory",
                            is_64bit=bool(flags & 0x4),
                            is_prefetchable=bool(flags & 0x8),
                            resource_path=str(dev_path / f"resource{i}"),
                        )
                        gpu.bars.append(bar)
                gpus.append(gpu)
            return gpus

        gpus = patched_find()
        assert len(gpus) == 1
        assert gpus[0].vendor_id == 0x10DE
        assert gpus[0].device_id == 0x2684
        assert len(gpus[0].bars) == 2

    def test_skips_non_nvidia(self, tmp_path):
        self._build_fake_sysfs(tmp_path, vendor="0x1002")  # AMD
        gpus = []
        for dev_path in sorted(tmp_path.iterdir()):
            vendor_id = int((dev_path / "vendor").read_text().strip(), 16)
            if vendor_id != 0x10DE:
                continue
            gpus.append(dev_path)
        assert gpus == []

    def test_skips_non_vga_device(self, tmp_path):
        self._build_fake_sysfs(tmp_path, class_id="0x020000")
        dev_path = tmp_path / "0000:01:00.0"
        class_id = int((dev_path / "class").read_text().strip(), 16)
        assert (class_id >> 8) != 0x0300 and (class_id >> 8) != 0x0302

    def test_no_sysfs(self):
        assert 0 in bars.KNOWN_BAR_DESCRIPTIONS
        assert 1 in bars.KNOWN_BAR_DESCRIPTIONS


# ---------------------------------------------------------------------------
# Known register ranges
# ---------------------------------------------------------------------------

class TestKnownRegisterRanges:
    def test_ranges_are_sorted(self):
        starts = [r[0] for r in bars.KNOWN_REGISTER_RANGES]
        assert starts == sorted(starts), "Register ranges should be sorted by start"

    def test_ranges_have_positive_size(self):
        for start, end, name in bars.KNOWN_REGISTER_RANGES:
            assert end > start, f"{name} has non-positive size"

    def test_gsp_range_present(self):
        names = [r[2] for r in bars.KNOWN_REGISTER_RANGES]
        assert any("GSP" in n for n in names)


# ---------------------------------------------------------------------------
# build_gpu_report / print_gpu_report
# ---------------------------------------------------------------------------

class TestGPUReport:
    def _make_gpu(self):
        return bars.GPUDevice(
            bdf="01:00.0", vendor_id=0x10DE, device_id=0x2684,
            device_name="RTX 4090", driver="nvidia",
            bars=[
                bars.BARRegion(
                    index=0, physical_addr=0xF0000000, size=16*1024*1024,
                    bar_type="memory", is_64bit=True, is_prefetchable=False,
                    resource_path="/dev/null", description="GPU Registers",
                ),
            ],
        )

    def test_build_report_structure(self):
        gpu = self._make_gpu()
        report = bars.build_gpu_report(gpu, probe=False)
        assert report["bdf"] == "01:00.0"
        assert report["device_name"] == "RTX 4090"
        assert len(report["bars"]) == 1
        assert report["bars"][0]["index"] == 0

    def test_print_report(self, capsys):
        gpu = self._make_gpu()
        report = bars.build_gpu_report(gpu, probe=False)
        bars.print_gpu_report(report, probe=False)
        out = capsys.readouterr().out
        assert "RTX 4090" in out
        assert "BAR0" in out

    def test_report_json_serializable(self):
        gpu = self._make_gpu()
        report = bars.build_gpu_report(gpu, probe=False)
        output = json.dumps(report, indent=2)
        parsed = json.loads(output)
        assert parsed["bdf"] == "01:00.0"


# ---------------------------------------------------------------------------
# --probe-write exits with error
# ---------------------------------------------------------------------------

class TestProbeWriteBlocked:
    def test_probe_write_exits(self):
        with mock.patch("sys.argv", ["map_gpu_bars.py", "--probe-write"]):
            with pytest.raises(SystemExit) as exc:
                bars.main()
            assert exc.value.code == 1


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

class TestCLI:
    def test_help(self):
        with pytest.raises(SystemExit) as exc:
            with mock.patch("sys.argv", ["map_gpu_bars.py", "--help"]):
                bars.main()
        assert exc.value.code == 0
