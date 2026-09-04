# Devpost Draft Copy

## Project name

FixRepro

## Elevator pitch

Replays the same security test against vulnerable and patched robotics or IoT builds, captures hash-verified evidence, and proves the fix without breaking legitimate behavior.

## Problem statement

Security patches for connected systems are often accepted as code changes without repeatable proof that unsafe behavior is gone and legitimate behavior still works.

## What it does

FixRepro is a controlled security regression environment for a synthetic IoT OTA scenario. It runs an identical untrusted update package against vulnerable and patched gateways, observes virtual device state, and runs a trusted positive control. The deterministic verifier produces `PATCH_VERIFIED` only when unsafe behavior reproduces on the vulnerable build, is rejected by the patched build, and the legitimate update still succeeds.

## How it works

The runner resets the virtual device before every scenario. The vulnerable gateway models an integrity-only check, while the patched gateway also verifies an Ed25519 signature against a trusted public key. Each execution records build and case identifiers, payload and complete package hashes, signer identity, request and response hashes, device state, timestamps, decisions, verdicts, and artifacts. The workflow produces a schema-valid evidence document, self-contained HTML report, and tamper-evident manifest that can be checked independently.

## How it was built

Phases 1 through 3 implement the repository contract, synthetic device and gateways, in-memory Ed25519 package generation, deterministic orchestration and verdicts, evidence generation, a self-contained report, bundle hashing, and independent verification. Unit and integration tests cover policy, outcomes, schema validation, output escaping, and bundle modification detection. The final dashboard and container environment are not implemented.

The current and planned stack is Python 3.12, FastAPI, Pydantic, the `cryptography` library with Ed25519, Docker Compose, pytest, plain HTML/CSS/JavaScript, JSON Schema, and GitHub Actions. Docker Compose, the final interface, and GitHub Actions remain planned.

## Challenges

The design must distinguish package integrity from signer trust, guarantee that the patched run receives the exact same unsafe bytes, reset state between scenarios, and avoid crediting a patch that blocks legitimate updates. It must also describe evidence accurately: file hashes make the bundle tamper-evident but do not establish an independent chain of custody.

## Accomplishments

FixRepro now executes the narrow security property end to end, proves exact same-input replay with complete package and request hashes, preserves the trusted positive control, and publishes a bundle whose root digest detects later file modification when retained separately.

## What was learned

Patch verification needs more than a blocked request. A defensible regression result also needs identical input, controlled initial state, observable device consequences, build identity, and a positive control. Clear limitations are part of useful evidence.

## What is next

The next phase will build the final local dashboard and container orchestration around the verified core. Later work will add continuous integration and presentation assets while preserving localhost-only defaults and synthetic data boundaries.

## Planned technologies

- Python 3.12
- FastAPI
- Pydantic
- `cryptography` with Ed25519
- Docker Compose
- pytest
- Plain HTML, CSS, and JavaScript
- JSON Schema
- GitHub Actions

The repository, demonstration environment, evidence format, interface, and automation are new VoltHacks 2026 development. General methodology is informed by prior security research.
