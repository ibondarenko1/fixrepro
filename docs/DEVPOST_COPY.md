# Devpost Final Copy

The canonical paste-ready text is [docs/submission/DEVPOST_FINAL.md](submission/DEVPOST_FINAL.md). The summary below matches the frozen Phase 5A product.

## Project name

FixRepro

## Elevator pitch

Replays the same security test against vulnerable and patched robotics or IoT builds, captures hash-verified evidence, and proves the fix without breaking legitimate behavior.

## Problem statement

Security patches for connected systems are often accepted as code changes without repeatable proof that unsafe behavior is gone and legitimate behavior still works.

## What it does

FixRepro is a controlled security regression environment for a synthetic IoT OTA scenario. Its local dashboard loads a verified demonstration bundle immediately and can start one real fixed verification. The workflow replays identical untrusted package bytes, records virtual device state, runs a trusted positive control, derives deterministic verdicts, and publishes a tamper-evident evidence bundle.

## How it works

The vulnerable gateway checks payload integrity only. The patched gateway also verifies an Ed25519 signature against a trusted public key. Before every scenario, the orchestrator resets and confirms the device state. `PATCH_VERIFIED` requires the unsafe baseline, rejection of the same bytes by the patch, a successful trusted update, and no operational error.

The dashboard never decides a verdict. It independently verifies a bundle, recomputes the outcome through the existing pure verdict engine, parses strict evidence, and returns a limited presentation model. Safe routes expose only the report, evidence, manifest, and digest for internally registered bundles.

## How it was built

Phases 1 through 4 implement the repository contract, synthetic device and gateways, in-memory Ed25519 package generation, deterministic orchestration, evidence and report generation, independent bundle verification, a FastAPI control plane, a plain HTML/CSS/JavaScript dashboard, an in-memory background job manager, and a one-container Docker Compose launch path.

The stack is Python 3.12, FastAPI, Pydantic, `cryptography` with Ed25519, HTTPX, JSON Schema, pytest, plain HTML/CSS/JavaScript, Docker Compose, and GitHub Actions. No cloud deployment is provided.

## Challenges

The design had to prove byte-for-byte replay, preserve a positive control, reset state between scenarios, prevent the browser from selecting arbitrary inputs, and avoid circular hashing in the evidence bundle. It also had to present evidence honestly: file hashes are tamper-evident only when the published digest is retained separately.

## Accomplishments

FixRepro now runs the fixed regression end to end from a local dashboard, keeps security decisions deterministic, provides immediate verified demo evidence, serializes live jobs, prevents arbitrary browser-controlled targets and paths, and reverifies every artifact before serving it.

## What was learned

Patch verification needs identical input, controlled initial state, observable consequences, build identity, and a positive control. A presentation layer is safer when it consumes a narrow verified model instead of raw execution inputs.

## What is next

The remaining submission work is manual: record and upload the video, enter the prepared text and images in Devpost, preview the entry, and submit it. No cloud deployment is provided.

## Built with

- Python 3.12
- FastAPI
- Pydantic
- Ed25519 through `cryptography`
- HTTPX
- JSON Schema Draft 2020-12
- pytest
- Plain HTML, CSS, and JavaScript
- Docker and Docker Compose
- GitHub Actions

The final video has not been recorded, and Devpost entry remains manual.

The repository, demonstration environment, evidence format, interface, and automation are new VoltHacks 2026 development. General methodology is informed by prior security research.
