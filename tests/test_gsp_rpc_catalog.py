#!/usr/bin/env python3
"""Unit tests for GSP RPC Interface Cataloger."""

import json
import sys
from pathlib import Path
from unittest import mock

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "tools" / "gsp-rpc-monitor"))
import gsp_rpc_catalog as rpc


# ---------------------------------------------------------------------------
# Fixtures — fake NVIDIA source tree
# ---------------------------------------------------------------------------

@pytest.fixture
def nvidia_source(tmp_path: Path) -> Path:
    """Build a minimal fake NVIDIA open-gpu-kernel-modules tree."""
    gsp_dir = tmp_path / "src" / "nvidia" / "inc" / "kernel" / "gpu" / "gsp"
    gsp_dir.mkdir(parents=True)

    # Header with RPC command defines
    (gsp_dir / "gsp_rpc.h").write_text("""\
#ifndef GSP_RPC_H
#define GSP_RPC_H

#define NV_VGPU_MSG_FUNCTION_ALLOC_MEMORY     0x0001  /* Allocate GPU memory */
#define NV_VGPU_MSG_FUNCTION_FREE_MEMORY      0x0002
#define NV_VGPU_MSG_FUNCTION_MAP_BUFFER       0x0003

#define NV_VGPU_MSG_EVENT_GSP_INIT_DONE       0x1000
#define NV_VGPU_MSG_EVENT_POST_EVENT          0x1001

#define GSP_MSG_BOOT_COMPLETE                 0x00FF

typedef struct rpc_alloc_memory_v1 {
    NvU32 hClient;    /* Client handle */
    NvU32 hMemory;
    NvU64 size;
    NvU32 flags;
} rpc_alloc_memory_v1;

typedef struct rpc_message_header {
    NvU32 function;
    NvU32 length;
    NvU32 sequence;
} rpc_message_header;

typedef enum GspBootStage {
    GSP_BOOT_STAGE_INIT   = 0x00,
    GSP_BOOT_STAGE_FRTS   = 0x01,
    GSP_BOOT_STAGE_LOADER = 0x02,
    GSP_BOOT_STAGE_RM     = 0x03,
} GspBootStage;

#endif
""")

    # A second file in a different directory
    vgpu_dir = tmp_path / "src" / "nvidia" / "inc" / "kernel" / "vgpu"
    vgpu_dir.mkdir(parents=True)
    (vgpu_dir / "vgpu_rpc.h").write_text("""\
#define NV_VGPU_MSG_FUNCTION_SET_POWER_STATE  0x0010
""")

    return tmp_path


# ---------------------------------------------------------------------------
# Pattern matching
# ---------------------------------------------------------------------------

class TestPatterns:
    def test_rpc_command_pattern(self):
        text = "#define NV_VGPU_MSG_FUNCTION_FOO 0x42 /* does foo */"
        m = rpc.PATTERNS["rpc_command"].search(text)
        assert m is not None
        assert m.group(1) == "NV_VGPU_MSG_FUNCTION_FOO"
        assert m.group(2) == "0x42"
        assert m.group(3) == "does foo"

    def test_rpc_event_pattern(self):
        text = "#define NV_VGPU_MSG_EVENT_BAR 0x100"
        m = rpc.PATTERNS["rpc_event"].search(text)
        assert m is not None
        assert m.group(1) == "NV_VGPU_MSG_EVENT_BAR"

    def test_gsp_msg_pattern(self):
        text = "#define GSP_MSG_INIT 0x01"
        m = rpc.PATTERNS["gsp_msg"].search(text)
        assert m is not None

    def test_gsp_enum_pattern(self):
        text = "enum GspState { GSP_ON = 0x1, GSP_OFF = 0x2 }"
        m = rpc.PATTERNS["gsp_enum"].search(text)
        assert m is not None
        assert m.group(1) == "GspState"


# ---------------------------------------------------------------------------
# parse_struct_fields
# ---------------------------------------------------------------------------

class TestParseStructFields:
    def test_basic_fields(self):
        body = """
    NvU32 hClient;    /* Client handle */
    NvU64 size;
    NvU32 flags;
"""
        fields = rpc.parse_struct_fields(body)
        assert len(fields) == 3
        assert fields[0]["name"] == "hClient"
        assert fields[0]["type"] == "NvU32"
        assert fields[0]["comment"] == "Client handle"

    def test_array_field(self):
        body = "    NvU8 data[256];"
        fields = rpc.parse_struct_fields(body)
        assert len(fields) == 1
        assert fields[0]["array_size"] == 256

    def test_empty_body(self):
        assert rpc.parse_struct_fields("") == []


# ---------------------------------------------------------------------------
# find_header_files
# ---------------------------------------------------------------------------

class TestFindHeaderFiles:
    def test_finds_files(self, nvidia_source):
        headers = rpc.find_header_files(nvidia_source)
        assert len(headers) >= 2
        names = [h.name for h in headers]
        assert "gsp_rpc.h" in names
        assert "vgpu_rpc.h" in names

    def test_empty_tree(self, tmp_path):
        assert rpc.find_header_files(tmp_path) == []


# ---------------------------------------------------------------------------
# build_catalog (integration)
# ---------------------------------------------------------------------------

class TestBuildCatalog:
    def test_finds_commands(self, nvidia_source):
        catalog = rpc.build_catalog(nvidia_source)
        names = [c.name for c in catalog.commands]
        assert "NV_VGPU_MSG_FUNCTION_ALLOC_MEMORY" in names
        assert "NV_VGPU_MSG_FUNCTION_FREE_MEMORY" in names
        assert "NV_VGPU_MSG_FUNCTION_SET_POWER_STATE" in names

    def test_finds_events(self, nvidia_source):
        catalog = rpc.build_catalog(nvidia_source)
        names = [c.name for c in catalog.commands]
        assert "NV_VGPU_MSG_EVENT_GSP_INIT_DONE" in names

    def test_finds_gsp_msg(self, nvidia_source):
        catalog = rpc.build_catalog(nvidia_source)
        names = [c.name for c in catalog.commands]
        assert "GSP_MSG_BOOT_COMPLETE" in names

    def test_finds_structs(self, nvidia_source):
        catalog = rpc.build_catalog(nvidia_source)
        struct_names = [s.name for s in catalog.structs]
        assert "rpc_alloc_memory_v1" in struct_names
        assert "rpc_message_header" in struct_names

    def test_struct_fields_parsed(self, nvidia_source):
        catalog = rpc.build_catalog(nvidia_source)
        alloc_struct = next(
            s for s in catalog.structs if s.name == "rpc_alloc_memory_v1")
        field_names = [f["name"] for f in alloc_struct.fields]
        assert "hClient" in field_names
        assert "size" in field_names

    def test_finds_enums(self, nvidia_source):
        catalog = rpc.build_catalog(nvidia_source)
        assert len(catalog.enums) >= 1
        boot_enum = next(e for e in catalog.enums if e["name"] == "GspBootStage")
        value_names = [v["name"] for v in boot_enum["values"]]
        assert "GSP_BOOT_STAGE_INIT" in value_names
        assert "GSP_BOOT_STAGE_RM" in value_names

    def test_deduplicates_commands(self, nvidia_source):
        catalog = rpc.build_catalog(nvidia_source)
        names = [c.name for c in catalog.commands]
        assert len(names) == len(set(names))

    def test_records_source_files(self, nvidia_source):
        catalog = rpc.build_catalog(nvidia_source)
        assert len(catalog.source_files_parsed) >= 2

    def test_command_values_are_ints(self, nvidia_source):
        catalog = rpc.build_catalog(nvidia_source)
        for cmd in catalog.commands:
            assert isinstance(cmd.value, int)

    def test_command_line_numbers(self, nvidia_source):
        catalog = rpc.build_catalog(nvidia_source)
        for cmd in catalog.commands:
            assert cmd.line_number >= 1


# ---------------------------------------------------------------------------
# JSON output
# ---------------------------------------------------------------------------

class TestJSONOutput:
    def test_json_round_trip(self, nvidia_source, tmp_path):
        catalog = rpc.build_catalog(nvidia_source)
        from dataclasses import asdict
        output = json.dumps({
            "commands": [asdict(c) for c in catalog.commands],
            "structs": [asdict(s) for s in catalog.structs],
            "enums": catalog.enums,
            "source_files": catalog.source_files_parsed,
        }, indent=2)
        data = json.loads(output)
        assert "commands" in data
        assert "structs" in data
        assert len(data["commands"]) > 0


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

class TestCLI:
    def test_help(self):
        with pytest.raises(SystemExit) as exc:
            with mock.patch("sys.argv", ["gsp_rpc_catalog.py", "--help"]):
                rpc.main()
        assert exc.value.code == 0

    def test_missing_source(self, tmp_path):
        missing = tmp_path / "nonexistent"
        with mock.patch("sys.argv", ["gsp_rpc_catalog.py", str(missing)]):
            with pytest.raises(SystemExit) as exc:
                rpc.main()
            assert exc.value.code == 1

    def test_text_output(self, nvidia_source, capsys):
        with mock.patch("sys.argv", ["gsp_rpc_catalog.py", str(nvidia_source)]):
            rpc.main()
        out = capsys.readouterr().out
        assert "RPC INTERFACE CATALOG" in out
        assert "NV_VGPU_MSG_FUNCTION_ALLOC_MEMORY" in out

    def test_json_output(self, nvidia_source, tmp_path):
        out_file = tmp_path / "out.json"
        with mock.patch("sys.argv", ["gsp_rpc_catalog.py", str(nvidia_source),
                                      "--format", "json", "-o", str(out_file)]):
            rpc.main()
        data = json.loads(out_file.read_text())
        assert len(data["commands"]) > 0

    def test_json_file_output(self, nvidia_source, tmp_path):
        out_file = tmp_path / "catalog.json"
        with mock.patch("sys.argv", ["gsp_rpc_catalog.py", str(nvidia_source),
                                      "--format", "json", "-o", str(out_file)]):
            rpc.main()
        assert out_file.exists()
        data = json.loads(out_file.read_text())
        assert "commands" in data
