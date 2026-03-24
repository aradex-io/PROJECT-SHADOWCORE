# SHADOWCORE — Roadmap Checklist

## Phase 0: Reconnaissance

- [x] 24MAR2026 — Project scaffold: directory structure, README, requirements.txt, setup script
- [x] 24MAR2026 — GSP architecture reference document (boot chain, RPC, BAR layout, prior art)
- [x] 24MAR2026 — Phase 0 research plan (tasks 0.1-0.6, hardware targets, timeline)
- [x] 24MAR2026 — Tool: GSP RPC interface cataloger (`tools/gsp-rpc-monitor/`)
- [x] 24MAR2026 — Tool: GSP firmware blob extractor (`tools/firmware-extract/`)
- [x] 24MAR2026 — Tool: GPU PCI BAR region mapper (`tools/bar-mapper/`)
- [x] 24MAR2026 — Tool: VRAM persistence test suite (`tools/vram-persistence/`)
- [x] 24MAR2026 — Unit tests for all Phase 0 tools (85 tests, all passing)
- [x] 24MAR2026 — CLAUDE.md: development rules, safety protocols, code standards
- [x] 24MAR2026 — CLAUDE.md: artifact standards, doc templates, directory restructure
- [ ] Run environment setup on target hardware
- [ ] Task 0.1: Extract RPC catalog from real NVIDIA open-source kernel modules
- [ ] Task 0.2: Nouveau driver study and cross-reference with proprietary interface
- [ ] Task 0.3: Extract and triage real GSP firmware blobs on target GPU
- [ ] Task 0.4: Map PCI BAR regions on target GPU with probe reads
- [ ] Task 0.5: Execute VRAM persistence test matrix (driver reload, suspend, reboot)
- [ ] Task 0.6: Complete annotated prior art bibliography
- [ ] Phase 0 synthesis report and Phase 1 decision points

## Phase 1: Firmware RE

- [ ] Define firmware RE methodology (Ghidra processor module, emulation strategy)
- [ ] Load GSP firmware into Ghidra, identify entry points and boot chain
- [ ] Build GSP emulation harness (Unicorn-based RISC-V / Falcon)
- [ ] Map GSP memory layout: code sections, data sections, shared memory regions
- [ ] Document firmware authentication mechanism (signatures, hashes, WPR)
- [ ] Identify potential injection points (pre-auth, runtime, RPC)
- [ ] Build RPC fuzzer for host-to-GSP interface
- [ ] Phase 1 synthesis report and Phase 2 decision points

## Phase 2: PoC Development

- [ ] Select injection vector based on Phase 1 findings
- [ ] Build non-destructive "hello world" PoC for GSP code execution
- [ ] Validate PoC on test GPU (marker-based proof, no destructive payload)
- [ ] Document PoC methodology and reproduction steps
- [ ] Phase 2 synthesis report

## Phase 3: Detection

- [ ] YARA rules for modified firmware signatures
- [ ] Firmware integrity checker (hash-based validation)
- [ ] GPU memory forensics tooling
- [ ] Detection methodology documentation
- [ ] Responsible disclosure package for NVIDIA PSIRT
- [ ] MITRE CVE coordination (if warranted)
