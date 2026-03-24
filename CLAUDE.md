# SHADOWCORE — Claude Development Rules

## Project Context

GPU firmware security research project. Authorized security research for
responsible disclosure to NVIDIA PSIRT and MITRE. The goal is to prove that
code can persist in GPU firmware (even "hello world") and then build detection
tooling for this attack surface.

## Development Process

Every action must follow this pipeline:

### 1. Plan
- Define what needs to be done, why, and what the expected outcome is
- Identify dependencies, risks, and blockers
- Break into discrete, testable steps

### 2. Critical Review of the Plan
- Challenge assumptions: is this the simplest approach?
- Identify what could go wrong (bricking GPU, data loss, incorrect conclusions)
- Check: does this align with responsible disclosure principles?
- Check: are we using the right tool/approach, or is there a better one?
- Verify: are safety protocols being followed (test GPU, backups, etc.)?

### 3. Finalize the Plan
- Incorporate review feedback
- Confirm final approach with clear success criteria
- Document the plan before executing

### 4. Execute the Plan
- Implement step by step
- Commit at logical checkpoints, not just at the end
- Follow safety protocols for hardware-interacting code

### 5. Verify Against Plan Benchmarks
- Did we achieve the stated success criteria?
- Do outputs match expected results?
- Are there unexpected side effects or gaps?
- Document findings, even negative results

### 6. Create Test Cases (if applicable)
- Unit tests for tooling code
- Integration tests for multi-component workflows
- Hardware interaction tests should have dry-run/mock modes
- Persistence tests need clear pass/fail criteria
- All tools should have a `--dry-run` or `--help` that works without root/GPU

## Code Standards

- Python 3.10+ with type hints
- All tools must be CLI-runnable with `argparse` and `--help`
- Tools requiring root access must check `os.geteuid()` and fail gracefully
- Tools requiring GPU hardware must detect GPU presence and provide useful
  error messages when no GPU is available
- Prefer `pathlib.Path` over string path manipulation
- Use `dataclasses` for structured data
- No external dependencies unless they're in `requirements.txt`

## Safety Rules

- **Never test destructive operations on a display GPU**
- **Always back up firmware/VBIOS before write experiments**
- **Write probes require explicit `--probe-write` flag and confirmation prompt**
- **All hardware-modifying tools must have a `--dry-run` mode**
- **Document all hardware interactions in tool docstrings**

## Git Conventions

- Develop on feature branches
- Commit messages: imperative mood, explain *why* not just *what*
- Push to `claude/gpu-firmware-research-*` branches
- Never force push

## Directory Structure

```
docs/           — Research documentation, architecture refs
tools/          — Active research tooling (one subdir per tool)
analysis/       — Output artifacts (firmware dumps, RE notes)
detection/      — Defensive tooling (YARA, integrity checks, forensics)
scripts/        — Utility/setup scripts
tests/          — Test suites
```
