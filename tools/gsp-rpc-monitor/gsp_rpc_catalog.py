#!/usr/bin/env python3
"""
GSP RPC Interface Cataloger

Parses NVIDIA open-source kernel module headers to extract GSP RPC command
definitions, parameter structures, and message formats. This builds the
reference catalog needed to understand host-to-GSP communication.

Usage:
    # Point at cloned NVIDIA open-source kernel modules
    python gsp_rpc_catalog.py /path/to/open-gpu-kernel-modules

    # Generate structured output
    python gsp_rpc_catalog.py /path/to/open-gpu-kernel-modules --format json
"""

import argparse
import json
import re
import sys
from dataclasses import dataclass, field, asdict
from pathlib import Path


@dataclass
class RPCCommand:
    """Represents a single GSP RPC command."""
    name: str
    value: int | str
    source_file: str
    line_number: int
    comment: str = ""
    param_struct: str = ""


@dataclass
class RPCStruct:
    """Represents an RPC parameter structure."""
    name: str
    source_file: str
    fields: list[dict] = field(default_factory=list)


@dataclass
class RPCCatalog:
    """Complete catalog of GSP RPC interface."""
    commands: list[RPCCommand] = field(default_factory=list)
    structs: list[RPCStruct] = field(default_factory=list)
    enums: list[dict] = field(default_factory=list)
    source_files_parsed: list[str] = field(default_factory=list)


# Patterns to search for in NVIDIA headers
PATTERNS = {
    # RPC command definitions (typically #define NV_VGPU_MSG_FUNCTION_*)
    "rpc_command": re.compile(
        r"#define\s+(NV_VGPU_MSG_FUNCTION_\w+)\s+(0x[0-9a-fA-F]+|\d+)"
        r"(?:\s*/\*\s*(.*?)\s*\*/)?",
        re.MULTILINE
    ),
    # Alternative RPC patterns
    "rpc_event": re.compile(
        r"#define\s+(NV_VGPU_MSG_EVENT_\w+)\s+(0x[0-9a-fA-F]+|\d+)"
        r"(?:\s*/\*\s*(.*?)\s*\*/)?",
        re.MULTILINE
    ),
    # GSP message types
    "gsp_msg": re.compile(
        r"#define\s+(GSP_MSG_\w+|NV_GSP_\w+)\s+(0x[0-9a-fA-F]+|\d+)",
        re.MULTILINE
    ),
    # RPC parameter structures
    "rpc_struct": re.compile(
        r"typedef\s+struct\s+(\w*rpc\w*|.*_RPC_\w+)\s*\{([^}]+)\}",
        re.MULTILINE | re.IGNORECASE | re.DOTALL
    ),
    # Generic message structures
    "msg_struct": re.compile(
        r"typedef\s+struct\s+(\w*[Mm]sg\w*|.*_MSG_\w+)\s*\{([^}]+)\}",
        re.MULTILINE | re.DOTALL
    ),
    # Enum definitions related to GSP/RPC
    "gsp_enum": re.compile(
        r"(?:typedef\s+)?enum\s+(\w*[Gg]sp\w*|\w*GSP\w*)\s*\{([^}]+)\}",
        re.MULTILINE | re.DOTALL
    ),
}

# Key directories within open-gpu-kernel-modules to search
SEARCH_DIRS = [
    "src/nvidia/inc/kernel/gpu/gsp",
    "src/nvidia/inc/kernel/gpu/falcon",
    "src/nvidia/inc/kernel/gpu/sec2",
    "src/nvidia/inc/kernel/vgpu",
    "src/nvidia/inc/libraries/mmu",
    "src/nvidia/src/kernel/gpu/gsp",
    "src/nvidia/generated",
    "src/common/sdk/nvidia/inc",
    "kernel-open/nvidia",
    "src/nvidia/inc/ctrl",
]


def find_header_files(base_path: Path) -> list[Path]:
    """Find all relevant header files in the NVIDIA source tree."""
    headers = []

    for search_dir in SEARCH_DIRS:
        dir_path = base_path / search_dir
        if dir_path.exists():
            for ext in ("*.h", "*.c"):
                headers.extend(dir_path.rglob(ext))

    # Also search for any file with "rpc" or "gsp" in the name
    for pattern in ["*rpc*", "*gsp*", "*GSP*", "*RPC*"]:
        for ext in (".h", ".c"):
            headers.extend(base_path.rglob(f"{pattern}{ext}"))

    # Deduplicate
    return sorted(set(headers))


def parse_struct_fields(body: str) -> list[dict]:
    """Parse C struct body into field list."""
    fields = []
    # Match typical C struct field declarations
    field_pattern = re.compile(
        r"\s*((?:unsigned\s+|signed\s+|const\s+|volatile\s+)*"
        r"(?:NvU\d+|NvS\d+|NvBool|NvHandle|void|char|int|long|"
        r"NV_\w+|Nv\w+|\w+_t)\s*\*?\s*)"
        r"(\w+)(?:\[(\d+)\])?\s*;(?:\s*/\*(.*?)\*/)?"
    )

    for match in field_pattern.finditer(body):
        field_type = match.group(1).strip()
        field_name = match.group(2)
        array_size = match.group(3)
        comment = match.group(4).strip() if match.group(4) else ""

        field_info = {
            "type": field_type,
            "name": field_name,
            "comment": comment,
        }
        if array_size:
            field_info["array_size"] = int(array_size)
        fields.append(field_info)

    return fields


def catalog_source_file(filepath: Path, catalog: RPCCatalog, base_path: Path):
    """Parse a single source file for RPC definitions."""
    try:
        content = filepath.read_text(errors="replace")
    except Exception as e:
        print(f"  Warning: Cannot read {filepath}: {e}", file=sys.stderr)
        return

    rel_path = str(filepath.relative_to(base_path))

    # Find RPC commands
    for pattern_name in ("rpc_command", "rpc_event", "gsp_msg"):
        for match in PATTERNS[pattern_name].finditer(content):
            name = match.group(1)
            value_str = match.group(2)
            comment = match.group(3) if match.lastindex >= 3 else ""

            value = int(value_str, 0)

            # Find line number
            line_num = content[:match.start()].count("\n") + 1

            catalog.commands.append(RPCCommand(
                name=name,
                value=value,
                source_file=rel_path,
                line_number=line_num,
                comment=comment or "",
            ))

    # Find RPC/message structures
    for pattern_name in ("rpc_struct", "msg_struct"):
        for match in PATTERNS[pattern_name].finditer(content):
            struct_name = match.group(1)
            struct_body = match.group(2)

            fields = parse_struct_fields(struct_body)
            catalog.structs.append(RPCStruct(
                name=struct_name,
                source_file=rel_path,
                fields=fields,
            ))

    # Find GSP enums
    for match in PATTERNS["gsp_enum"].finditer(content):
        enum_name = match.group(1)
        enum_body = match.group(2)

        values = []
        for value_match in re.finditer(
            r"(\w+)\s*=\s*(0x[0-9a-fA-F]+|\d+)", enum_body
        ):
            values.append({
                "name": value_match.group(1),
                "value": value_match.group(2),
            })

        if values:
            catalog.enums.append({
                "name": enum_name,
                "source_file": rel_path,
                "values": values,
            })


def build_catalog(base_path: Path) -> RPCCatalog:
    """Build complete RPC catalog from NVIDIA source tree."""
    catalog = RPCCatalog()

    print(f"Searching {base_path} for GSP/RPC definitions...")
    headers = find_header_files(base_path)
    print(f"Found {len(headers)} relevant source files")

    for header in headers:
        catalog_source_file(header, catalog, base_path)
        catalog.source_files_parsed.append(
            str(header.relative_to(base_path)))

    # Deduplicate commands by name
    seen = set()
    unique_commands = []
    for cmd in catalog.commands:
        if cmd.name not in seen:
            seen.add(cmd.name)
            unique_commands.append(cmd)
    catalog.commands = unique_commands

    return catalog


def print_catalog(catalog: RPCCatalog):
    """Print catalog in human-readable format."""
    print(f"\n{'='*70}")
    print(f"GSP RPC INTERFACE CATALOG")
    print(f"{'='*70}")

    print(f"\nFiles parsed: {len(catalog.source_files_parsed)}")
    print(f"RPC commands: {len(catalog.commands)}")
    print(f"Structures:   {len(catalog.structs)}")
    print(f"Enums:        {len(catalog.enums)}")

    if catalog.commands:
        print(f"\n--- RPC Commands ---")
        print(f"{'Name':<55} {'Value':<12} Source")
        print(f"{'-'*55} {'-'*12} {'-'*40}")
        for cmd in sorted(catalog.commands, key=lambda c: c.value
                          if isinstance(c.value, int) else 0):
            value_str = (f"0x{cmd.value:04x}" if isinstance(cmd.value, int)
                         else str(cmd.value))
            print(f"{cmd.name:<55} {value_str:<12} "
                  f"{cmd.source_file}:{cmd.line_number}")
            if cmd.comment:
                print(f"  // {cmd.comment}")

    if catalog.structs:
        print(f"\n--- RPC Structures ({len(catalog.structs)} total) ---")
        for s in catalog.structs:
            print(f"\n{s.name} ({s.source_file}):")
            for f in s.fields:
                array_suffix = f"[{f['array_size']}]" if "array_size" in f else ""
                comment = f"  // {f['comment']}" if f.get("comment") else ""
                print(f"    {f['type']:<30} {f['name']}{array_suffix}{comment}")

    if catalog.enums:
        print(f"\n--- GSP Enums ({len(catalog.enums)} total) ---")
        for e in catalog.enums:
            print(f"\n{e['name']} ({e['source_file']}):")
            for v in e["values"]:
                print(f"    {v['name']:<50} = {v['value']}")


def main():
    parser = argparse.ArgumentParser(
        description="GSP RPC Interface Cataloger")
    parser.add_argument(
        "source_path", type=Path,
        help="Path to cloned open-gpu-kernel-modules repository")
    parser.add_argument(
        "--format", choices=["text", "json"], default="text",
        help="Output format")
    parser.add_argument(
        "--output", "-o", type=Path, default=None,
        help="Save output to file")

    args = parser.parse_args()

    if not args.source_path.exists():
        print(f"Error: {args.source_path} not found", file=sys.stderr)
        print("Clone the repo first:")
        print("  git clone https://github.com/NVIDIA/open-gpu-kernel-modules")
        sys.exit(1)

    catalog = build_catalog(args.source_path)

    json_data = {
        "commands": [asdict(c) for c in catalog.commands],
        "structs": [asdict(s) for s in catalog.structs],
        "enums": catalog.enums,
        "source_files": catalog.source_files_parsed,
    }

    if args.format == "json":
        output = json.dumps(json_data, indent=2)
        if args.output:
            args.output.write_text(output)
            print(f"JSON catalog saved to {args.output}", file=sys.stderr)
        else:
            print(output)
    else:
        if args.output:
            # Write to file via print_catalog with redirected file handle
            import io
            buf = io.StringIO()
            old_stdout = sys.stdout
            sys.stdout = buf
            print_catalog(catalog)
            sys.stdout = old_stdout
            args.output.write_text(buf.getvalue())
            print(f"Catalog saved to {args.output}")
        else:
            print_catalog(catalog)


if __name__ == "__main__":
    main()
