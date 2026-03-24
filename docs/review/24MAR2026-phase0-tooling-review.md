# Review: Phase 0 Reconnaissance Tooling & Project Foundation

**Date:** 24 MAR 2026
**Reviewing:** All Phase 0 tools, project scaffold, documentation, test suite
**Verdict:** REVISE

## Summary

Phase 0 tooling (4 tools, 1352 lines) and supporting infrastructure (tests,
docs, setup script) are structurally sound and well-scaffolded. However, several
issues across the tools would cause failures or misleading results on real
hardware. This review catalogs every issue found and recommends specific fixes
before executing on target GPUs.

## Assessment

### What's sound

- **Project structure is clean.** Clear separation of tools, docs, analysis,
  detection. Each tool in its own subdirectory. Dependencies documented.
- **Safety protocols are implemented.** Root checks, `--probe-write` gating,
  confirmation prompts, dry-run philosophy. No tool will silently write to
  hardware.
- **CLI contracts are consistent.** All 4 tools use argparse, have `--help`,
  follow the code standards (pathlib, dataclasses, type hints).
- **Test suite exists and passes.** 85 tests covering all tools with mocked
  hardware. Tests run without root or GPU.
- **Documentation is comprehensive.** GSP architecture reference is detailed and
  well-sourced. Phase 0 plan has clear tasks, deliverables, and success criteria.

### Concerns

#### 1. `extract_gsp_firmware.py` — Firmware Extractor

| Issue | Severity | Detail |
|-------|----------|--------|
| Falcon magic is a placeholder | HIGH | `FALCON_MAGIC = b"\x00\x00\x00\x00"` (line 28) — this is literally null bytes. Will match the start of any zero-padded binary. Needs real Falcon microcode header from envytools (`nv_pfalcon_v2.xml` defines the header structure). |
| Falcon heuristic is too broad | HIGH | `identify_architecture()` (line 97) — the check `word0 < 0x10000 and word1 < 0x10000` will match many non-Falcon blobs (any file starting with two small 32-bit values). High false positive rate. |
| `--min-string-length` is accepted but ignored | MEDIUM | The CLI argument exists (line 274) but `triage_firmware()` hardcodes `min_length=10` (line 213) instead of passing `args.min_string_length`. |
| `GSP_FIRMWARE_PATTERNS` unused | LOW | The list at line 32 is defined but never referenced — `find_system_firmware()` uses `rglob("gsp*.bin")` directly. Dead code. |
| `FALCON_MAGIC` / `RISCV_MAGIC` unused | LOW | Defined at lines 28-29 but never referenced in any function. The actual checks use `b"\x7fELF"` and `struct.unpack` instead. Dead code. |
| No JSON/machine-readable output | MEDIUM | Triage results are print-only. For Phase 1 we'll need structured output (JSON) to feed into Ghidra scripts and other tools. |
| `import math` inside loop | LOW | `math` is imported inside `analyze_sections()` on every non-ELF chunk iteration (line 169). Should be a top-level import. |
| No `--dry-run` mode | LOW | Not safety-critical (read-only tool), but CLAUDE.md says all tools should have `--dry-run` or `--help`. Has `--help` so technically compliant, but a `--dry-run` that lists what would be analyzed without reading files would be useful. |

#### 2. `map_gpu_bars.py` — BAR Mapper

| Issue | Severity | Detail |
|-------|----------|--------|
| `--probe-write` is accepted but unimplemented | HIGH | The CLI flag exists (line 311), the confirmation prompt runs (line 319), but no write probing logic exists. After confirmation, it falls through to the same read-only `print_gpu_report()`. Users may believe writes were tested when they weren't. |
| GSP range overlaps FALCON range | MEDIUM | KNOWN_REGISTER_RANGES has FALCON at 0x100000-0x200000 and GSP at 0x110000-0x120000. This is architecturally correct (GSP is within the Falcon block), but `probe_register_ranges()` will read the same bytes twice with different labels. Could confuse analysis. Should document the nesting or restructure into parent/child ranges. |
| No root check at startup | MEDIUM | Unlike `test_vram_persistence.py`, this tool doesn't check `os.geteuid()` at startup. It waits until `probe_bar_read()` fails with PermissionError. Should fail fast with a clear message. |
| `re` imported but unused | LOW | Line 20 — `import re` is never used. |
| `--output` flag accepted but unimplemented | MEDIUM | CLI accepts `-o` (line 314) but `print_gpu_report()` only writes to stdout. The output flag is silently ignored. |
| No JSON output format | MEDIUM | Same as firmware extractor — stdout-only. BAR data needs to be consumable by other tools (VRAM persistence tester, future RPC fuzzer). |

#### 3. `test_vram_persistence.py` — VRAM Persistence Tester

| Issue | Severity | Detail |
|-------|----------|--------|
| State file in /tmp is not safe | MEDIUM | `STATE_FILE = Path("/tmp/shadowcore_persistence_state.json")` (line 56). On multi-user systems, this is predictable and writable by anyone. Could be tampered with between write and verify phases. Should use a configurable path or at minimum `tempfile.mktemp` with restrictive permissions. |
| `test-driver-reload` doesn't verify driver actually unloaded | HIGH | After `modprobe -r nvidia`, there's no check that the module actually unloaded (line 317-322). If `nvidia_drm` has active users, `modprobe -r` will fail silently (stderr is printed as "Warning" but execution continues). The test could report "no persistence" when the driver never actually reloaded. Should check `/proc/modules` or `lsmod` after unload. |
| `test-driver-reload` doesn't handle nvidia-persistenced | HIGH | If `nvidia-persistenced` is running, it will hold device files open and prevent driver unload. The tool doesn't check for or stop this daemon. This is the most common reason driver unload fails on real systems. |
| Only 5 test regions, all at fixed offsets | MEDIUM | Real VRAM layout varies by GPU. RTX 4090 has 24GB VRAM but BAR1 aperture may only be 256MB. The test regions top out at 128MB (line 53). Should dynamically size regions based on actual BAR1 size, and test near the end of the aperture too. |
| Hardcoded `time.sleep(2)` and `time.sleep(3)` | LOW | Driver unload/reload timing (lines 324, 334) is arbitrary. Some GPUs take longer to initialize. Should poll for driver readiness instead of sleeping. |
| `TestResult` dataclass defined but never used | LOW | Lines 59-67 — the dataclass exists but `cmd_write()` and `cmd_verify()` use plain dicts instead. Dead code. |

#### 4. `gsp_rpc_catalog.py` — RPC Cataloger

| Issue | Severity | Detail |
|-------|----------|--------|
| `rpc_struct` regex can't handle nested braces | MEDIUM | Pattern `\{([^}]+)\}` (line 75) breaks on structs containing nested structs or unions (common in NVIDIA headers, e.g., `NV2080_CTRL_CMD_*` types). Will silently truncate or miss fields. |
| No command-to-struct linkage | MEDIUM | Commands and structs are cataloged independently. There's no mapping from "NV_VGPU_MSG_FUNCTION_ALLOC_MEMORY" to its parameter struct "rpc_alloc_memory_v1". This linkage (often via naming convention or co-location) is critical for Phase 1 RPC fuzzing. |
| `size_bytes` field always 0 | LOW | `RPCStruct.size_bytes` (line 42) is never populated. Either calculate it from field types or remove it. |
| Text output truncated silently | LOW | `print_catalog()` limits structs to 30 (line 269) and enums to 10 (line 278) without telling the user. Should print "... and N more" or remove the limit. |
| Text file output calls `print_catalog()` twice | LOW | When `--output` is used with text format (lines 326-333), the catalog is printed once to screen, then again captured to file via stdout redirect. The stdout redirect approach is fragile — any other print statement in the codebase would leak into the file. |

#### 5. Cross-cutting issues

| Issue | Severity | Detail |
|-------|----------|--------|
| No tool produces JSON output that others consume | HIGH | Each tool writes to stdout or text files. There's no structured data pipeline. Phase 1 will need: firmware extractor → Ghidra loader, BAR mapper → persistence tester, RPC catalog → fuzzer. All tools should support `--format json`. |
| Existing docs don't follow the new templates | MEDIUM | `24MAR2026-phase0-recon-plan.md` is close to the planning template but lacks Status, Author, Phase headers and the Risks & Mitigations table. `24MAR2026-gsp-architecture.md` doesn't follow the reference template (no Source(s), Relevance to SHADOWCORE, or Open Questions sections). |
| `click` in requirements.txt but all tools use `argparse` | LOW | `click>=8.0` is listed as a dependency but no tool imports it. Dead dependency. |
| No `__init__.py` files in tool directories | LOW | Tools can't be imported as packages. Fine for CLI usage, but makes testing harder (we had to use `sys.path.insert`). |

### Assumptions challenged

- **"VRAM persistence = firmware persistence"** — VRAM surviving a driver
  reload does NOT prove firmware-level persistence. VRAM is volatile memory
  controlled by the memory controller. Firmware persists in flash/ROM. These are
  different attack surfaces. The research plan (Task 0.5) is clear about this,
  but the tool's output message "VRAM PERSISTENCE CONFIRMED" could be
  misinterpreted. Should clarify this is *VRAM* data survival, not firmware
  implant persistence.

- **"BAR1 maps directly to physical VRAM"** — On modern GPUs with resizable
  BAR, BAR1 may be a window into a larger address space managed by the GPU's
  internal MMU. Writes via BAR1 may not land where we expect in physical VRAM.
  The persistence tester should document this assumption.

- **"Regex parsing of C headers is sufficient for RPC catalog"** — For a Phase 0
  triage this is fine. But NVIDIA headers use complex preprocessor macros,
  nested structs, and conditional compilation (`#if NV_IS_SAFETY_BUILD`). A
  real Phase 1 catalog will need pycparser or clang-based parsing. The regex
  approach should be documented as "triage-quality, not exhaustive."

## Recommendations

### Priority 1 — Fix before hardware testing

1. **Add `--format json` to all 4 tools.** This is the single most impactful
   improvement. All tools should be able to write structured JSON for
   consumption by other tools and for archival in `analysis/notes/`.

2. **Fix `test-driver-reload` to verify driver state.** Check `lsmod | grep
   nvidia` after unload. Check for `nvidia-persistenced`. Fail explicitly if
   driver didn't actually unload.

3. **Fix `--min-string-length` passthrough** in firmware extractor.

4. **Remove or clearly mark `--probe-write` as unimplemented** in BAR mapper.
   Either stub it with `raise NotImplementedError` or remove the flag until
   Phase 1.

### Priority 2 — Improve before Phase 1

5. **Add root check to BAR mapper** at startup (like VRAM persistence tester).

6. **Remove dead code:** `FALCON_MAGIC`, `RISCV_MAGIC`, `GSP_FIRMWARE_PATTERNS`,
   `TestResult` dataclass, `import re` in BAR mapper, `click` from
   requirements.txt.

7. **Refine Falcon detection heuristic** with actual Falcon header structure
   from envytools documentation.

8. **Make VRAM persistence state file path configurable** via `--state-file`
   argument with sane default.

9. **Migrate existing docs** to match new templates (add missing metadata
   headers).

### Priority 3 — Nice to have

10. **Add command-to-struct linkage** in RPC cataloger (name-based heuristic
    matching).

11. **Handle nested struct braces** in RPC cataloger (brace-counting parser or
    switch to pycparser).

12. **Add `--output` implementation** to BAR mapper.

13. **Dynamic VRAM test regions** based on actual BAR1 size.

## Safety check

- [x] No destructive operations on display GPU
- [x] Firmware backups planned before writes
- [x] Write operations gated behind --probe-write + confirmation
- [x] Dry-run mode available (all tools have --help, read-only by default)
- [x] Aligns with responsible disclosure principles

**Note:** `--probe-write` is gated but unimplemented. This is actually *safer*
than if it were implemented poorly — but it should be explicitly marked as such
so no one assumes write testing has occurred.
