# firmware-code-graph-platform

Firmware decompilation and code-graph pipeline for producing faithful,
auditable attack-surface evidence for an upstream analysis AI.

The system extracts firmware, decompiles binaries with IDA Pro, builds a
function-level structural graph with codebase-memory-mcp, identifies
conservative source/sink candidates, recovers static routes, and records
qemu-user runtime coverage. It does not issue vulnerability verdicts.

AI semantic tagging is optional and is not required to build a graph. Current
real-firmware jobs default to original IDA names, addresses, pseudocode,
calls/usages, strings, routes, and trace observations.

## Start Here

- [Tomorrow handoff](HANDOFF.md)
- [Project introduction and current evidence](项目介绍.md)
- [Deployment and operations](fwgraph/README.md)
- [Historical development plan](开发计划.md)

## Repository Scope

This repository contains source code, tests, configuration templates, frontend
source, and operational scripts. Firmware images, `.env` files, credentials,
IDA databases, pseudocode corpora, CBM databases, traces, and other generated
evidence are intentionally excluded and remain on the controlled analysis VM.

## Verification Snapshot

- Local tests: `217 passed`
- Ubuntu VM tests: `217 passed`
- Frontend: Vite 8.2.0 production build succeeds
- Current Xiaomi R3 job: `56c105fd7b9a`, final status `routed`
- Current PX4 v6xrt job: `aaae7834a0cd`, final status `routed`

See [HANDOFF.md](HANDOFF.md) for exact continuation steps and known gaps.
