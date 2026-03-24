# SHADOWCORE — Claude Development Rules

## Project Context

GPU firmware security research project. Authorized security research for
responsible disclosure to NVIDIA PSIRT and MITRE. The goal is to prove that
code can persist in GPU firmware (even "hello world") and then build detection
tooling for this attack surface.

**Author:** Jay (d0sf3t) <github@aradex.io>
**All commits must use this identity.**

## Research Phases

| Phase | Name | Objective | Status |
|-------|------|-----------|--------|
| 0 | Reconnaissance | Map attack surface, document GSP, test persistence | ACTIVE |
| 1 | Firmware RE | Reverse-engineer GSP internals, identify injection points | PLANNED |
| 2 | PoC Development | Prove GSP code execution (non-destructive hello world) | PLANNED |
| 3 | Detection | Build defensive tooling (YARA, integrity, forensics) | PLANNED |

## Development Process

Every action must follow this pipeline. Each step that produces output must
create a document in the appropriate `docs/` subdirectory using the artifact
format defined below.

### 1. Plan
- Define what needs to be done, why, and what the expected outcome is
- Identify dependencies, risks, and blockers
- Break into discrete, testable steps
- **Create a planning artifact** in `docs/planning/` using the planning template

### 2. Critical Review of the Plan
- Challenge assumptions: is this the simplest approach?
- Identify what could go wrong (bricking GPU, data loss, incorrect conclusions)
- Check: does this align with responsible disclosure principles?
- Check: are we using the right tool/approach, or is there a better one?
- Verify: are safety protocols being followed (test GPU, backups, etc.)?
- **Create a review artifact** in `docs/review/` using the review template

### 3. Finalize the Plan
- Incorporate review feedback
- Confirm final approach with clear success criteria
- **Update the planning artifact** with final decisions and success criteria

### 4. Execute the Plan
- Implement step by step
- Commit at logical checkpoints, not just at the end
- Follow safety protocols for hardware-interacting code

### 5. Verify Against Plan Benchmarks
- Did we achieve the stated success criteria?
- Do outputs match expected results?
- Are there unexpected side effects or gaps?
- Document findings, even negative results
- **Update `docs/completed/ROADMAP-CHECKLIST.md`** with completed items

### 6. Create Test Cases (if applicable)
- Unit tests for tooling code
- Integration tests for multi-component workflows
- Hardware interaction tests should have dry-run/mock modes
- Persistence tests need clear pass/fail criteria
- All tools should have a `--dry-run` or `--help` that works without root/GPU

## Directory Structure

```
docs/
  planning/       — Plans, proposals, task breakdowns (before work begins)
  review/         — Critical reviews, post-mortems, decision records
  reference/      — Architecture docs, prior art, external research notes
  completed/      — ROADMAP-CHECKLIST.md and completion summaries
tools/            — Active research tooling (one subdir per tool)
analysis/         — Output artifacts (firmware dumps, RE notes)
  firmware-blobs/ — Extracted firmware binaries
  ghidra-projects/— Ghidra RE project files
  notes/          — Analysis notes and observations
detection/        — Defensive tooling (YARA, integrity checks, forensics)
  yara-rules/     — YARA detection signatures
  integrity-checker/ — Firmware integrity verification
  forensics/      — GPU memory forensics tools
scripts/          — Utility/setup scripts
tests/            — Test suites
```

## Artifact Standards

### File Naming Convention

All documentation artifacts use the format:

```
DDMMMYYYY-<slug>.md
```

- Date in uppercase: `24MAR2026`
- Slug is lowercase, hyphen-separated, concise: `phase0-recon-plan`
- Full example: `24MAR2026-phase0-recon-plan.md`

### Planning Document Template (`docs/planning/`)

```markdown
# [Title]

**Date:** DD MMM YYYY
**Author:** [name]
**Phase:** [0-3]
**Status:** DRAFT | FINAL | SUPERSEDED

## Objective

[What are we trying to achieve and why]

## Scope

[What's in scope, what's explicitly out of scope]

## Approach

[Step-by-step plan with numbered tasks]

## Dependencies

[What must exist before this work can begin]

## Risks & Mitigations

| Risk | Impact | Mitigation |
|------|--------|------------|

## Success Criteria

- [ ] [Measurable criterion 1]
- [ ] [Measurable criterion 2]

## Estimated Effort

[Rough sizing — not a deadline, just a planning signal]
```

### Review Document Template (`docs/review/`)

```markdown
# Review: [Title of artifact being reviewed]

**Date:** DD MMM YYYY
**Reviewing:** [path to planning doc or component]
**Verdict:** APPROVED | REVISE | BLOCKED

## Summary

[1-2 sentence summary of what's being reviewed]

## Assessment

### What's sound
- [Strengths of the plan/approach]

### Concerns
- [Issues, gaps, risks not addressed]

### Assumptions challenged
- [Assumption] — [why it might be wrong]

## Recommendations

1. [Specific actionable change]
2. [Specific actionable change]

## Safety check
- [ ] No destructive operations on display GPU
- [ ] Firmware backups planned before writes
- [ ] Write operations gated behind --probe-write + confirmation
- [ ] Dry-run mode available
- [ ] Aligns with responsible disclosure principles
```

### Reference Document Template (`docs/reference/`)

```markdown
# [Topic]

**Date:** DD MMM YYYY
**Author:** [name]
**Source(s):** [links, papers, repos referenced]

## Overview

[What this document covers and why it matters to SHADOWCORE]

## Content

[The actual reference material — structured by topic]

## Relevance to SHADOWCORE

[How this connects to our research phases]

## Open Questions

- [Things we still don't know]
```

### Roadmap Checklist (`docs/completed/ROADMAP-CHECKLIST.md`)

Single file, append-only. Tracks all completed milestones:

```markdown
# SHADOWCORE — Roadmap Checklist

## Phase 0: Reconnaissance
- [x] COMPLETED-DATE — Description of completed item
- [ ] Pending item

## Phase 1: Firmware RE
- [ ] Pending item

## Phase 2: PoC Development
- [ ] Pending item

## Phase 3: Detection
- [ ] Pending item
```

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
- Author identity: `Jay (d0sf3t) <github@aradex.io>`
