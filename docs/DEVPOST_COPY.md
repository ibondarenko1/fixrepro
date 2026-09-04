# Devpost Draft Copy

## Project name

FixRepro

## Elevator pitch

Replays the same security test against vulnerable and patched robotics or IoT builds, captures hash-verified evidence, and proves the fix without breaking legitimate behavior.

## Problem statement

Security patches for connected systems are often accepted as code changes without repeatable proof that unsafe behavior is gone and legitimate behavior still works.

## What it does

FixRepro is planned as a controlled security regression environment for a synthetic IoT OTA scenario. It will run an identical untrusted update package against vulnerable and patched gateways, observe the virtual device state, and run a trusted positive control. A deterministic verifier will produce `PATCH_VERIFIED` only when the unsafe behavior reproduces on the vulnerable build, is rejected by the patched build, and the legitimate update still succeeds.

## How it works

The planned runner will reset the virtual device before every scenario. The vulnerable gateway will model an integrity-only check, while the patched gateway will also verify an Ed25519 signature against a trusted public key. Each execution will record build and case identifiers, package and signer identity, request and response metadata, device state, timestamps, decisions, verdicts, and artifact hashes. A separate generator will produce a hash-verified evidence bundle and readable report.

## How it was built

Phase 1 establishes the repository scaffold, scope lock, synthetic cases, Draft 2020-12 evidence schema, sample evidence, architecture, threat model, demonstration plan, and a standard-library validator. Application services and the interface have not been implemented yet.

The planned implementation stack is Python 3.12, FastAPI, Pydantic, the `cryptography` library with Ed25519, Docker Compose, pytest, plain HTML/CSS/JavaScript, JSON Schema, and GitHub Actions.

## Challenges

The design must distinguish package integrity from signer trust, guarantee that the patched run receives the exact same unsafe bytes, reset state between scenarios, and avoid crediting a patch that blocks legitimate updates. It must also describe evidence accurately: file hashes make the bundle tamper-evident but do not establish an independent chain of custody.

## Accomplishments

Phase 1 defines a narrow, deterministic security property and an evidence contract that captures both negative and positive controls. The scaffold validator checks required files, case semantics, sample outcomes, hashes, content boundaries, and Devpost limits without third-party dependencies.

## What was learned

Patch verification needs more than a blocked request. A defensible regression result also needs identical input, controlled initial state, observable device consequences, build identity, and a positive control. Clear limitations are part of useful evidence.

## What is next

Future phases will implement the synthetic device and gateways, deterministic verifier, evidence and report generators, control plane, local interface, container orchestration, automated tests, and continuous integration. Each phase will preserve localhost-only defaults and synthetic data boundaries.

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
