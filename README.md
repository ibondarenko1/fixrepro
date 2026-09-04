# FixRepro

FixRepro replays the same security test against vulnerable and patched robotics or IoT builds, captures hash-verified evidence, and proves the fix without breaking legitimate behavior.

## Problem

Security patches for connected systems are often accepted as code changes without repeatable proof that unsafe behavior is gone and legitimate behavior still works.

## Implemented Phase 2 lab

FixRepro now provides a localhost-only synthetic OTA lab. It runs one controlled regression case against deliberately vulnerable and patched gateway policies plus a positive control. The Phase 2 runner validates HTTP responses and device transitions with deterministic assertions. The broader verification orchestrator and evidence bundle remain future work.

## Exact demonstration

1. **Vulnerable build:** a virtual device starts at `1.0.0`. An update with a valid checksum but an untrusted signer is accepted because the vulnerable gateway checks integrity only. The device changes to `9.9.0-test`; the individual verdict is `FAIL`.
2. **Patched build:** the device is reset to `1.0.0`, and the exact same untrusted package is replayed. The patched gateway verifies an Ed25519 signature against a trusted public key and rejects the package. The device remains at `1.0.0`; the individual verdict is `PASS`.
3. **Positive control:** the device is reset to `1.0.0`, then receives a package signed by the trusted key. The patched gateway accepts it and the device changes to `1.1.0`; the positive-control verdict is `PASS`.

The overall outcome is `PATCH_VERIFIED` only when all three observations occur. Any other result is `PATCH_NOT_VERIFIED` or `INCONCLUSIVE`.

## Phase 2 architecture

The implemented lab has a vulnerable OTA gateway on port 8101, a patched OTA gateway on port 8102, and a virtual device simulator on port 8200. All three bind to `127.0.0.1` only. A control plane and web interface on port 8000, a broader deterministic verifier, evidence-bundle generation, and human-readable report generation are still planned.

## Technology stack

- Python 3.12
- FastAPI
- Pydantic
- `cryptography` with Ed25519
- Docker Compose
- pytest
- Plain HTML, CSS, and JavaScript
- JSON Schema
- GitHub Actions

Phase 2 uses Python, FastAPI, Pydantic, `cryptography`, Ed25519, Uvicorn, HTTPX, and pytest. Docker Compose, the web interface, JSON Schema integration with generated run evidence, and GitHub Actions remain planned.

## Local setup

Python 3.12 or newer is required. Dependency installation is isolated to `.venv`.

### Windows PowerShell

```powershell
py -3.12 -m venv .venv
.\.venv\Scripts\python.exe -m pip install -e ".[dev]"
.\.venv\Scripts\python.exe scripts\run_phase2_demo.py
```

If Python 3.12 is not installed, use another available version newer than 3.12, such as `py -3.13`.

### Linux or macOS

```bash
python3.12 -m venv .venv
./.venv/bin/python -m pip install -e '.[dev]'
./.venv/bin/python scripts/run_phase2_demo.py
```

The one-command demonstration starts and stops all three child services. Use `--repeat 3` to run three consecutive repetitions.

Expected outcomes:

| Scenario | Gateway | Input | Decision | Device transition | Reason |
|---|---|---|---|---|---|
| A | Vulnerable | Untrusted signer, valid payload hash | `ACCEPTED` | `1.0.0 -> 9.9.0-test` | `CHECKSUM_ONLY_ACCEPTED` |
| B | Patched | Exact same untrusted package bytes | `REJECTED` | `1.0.0 -> 1.0.0` | `UNTRUSTED_SIGNER` |
| C | Patched | Trusted signer, valid signature | `ACCEPTED` | `1.0.0 -> 1.1.0` | `TRUSTED_SIGNATURE_ACCEPTED` |

Warning: the device reset and apply endpoints are intentionally unauthenticated local simulator interfaces. They are not production interfaces. Do not expose any FixRepro service beyond localhost.

Trusted and untrusted private signing keys are created as in-memory Python objects only and are never written to disk. Runtime public keys, packages, and logs are written under ignored `.runtime/`.

## Evidence model

The Phase 1 schema defines how a future execution record will identify the test role, software build, package and signer, request and response metadata, device state, expected and observed decisions, deterministic verdict, and artifact hashes. Phase 2 does not generate this evidence bundle. Evidence remains designed to be hash-verified and tamper-evident, not tamper-proof.

## Safety boundaries

This project is a controlled demonstration using synthetic packages, keys, devices, and builds. It excludes real vendor firmware, unpublished vulnerabilities, private disclosure material, credentials, persistent signing keys, and production targets. Implemented services bind to `127.0.0.1` in the demonstration runner, and the device client rejects non-loopback configuration.

## Limitations

Phase 2 covers one synthetic OTA signer-trust regression. It has no dashboard, production authentication, persistent device storage, fleet management, evidence bundle, or deployment environment. FixRepro can evaluate only the defined case under tested conditions; it cannot prove that every vulnerability is fixed or that a build is generally secure.

## Hackathon development declaration

The repository, demonstration environment, evidence format, interface, and automation are new VoltHacks 2026 development. General methodology is informed by prior security research; no private research artifacts or unpublished vulnerability details are included.

## Current status

Phase 2 controlled OTA lab is implemented and locally testable.

Implemented now:

- Virtual device
- Vulnerable gateway
- Patched gateway
- Ed25519 package generation
- Three-scenario demonstration runner
- Unit tests

## Not implemented yet

- Web dashboard
- Deterministic verification orchestrator
- Evidence bundle generation
- Human-readable report generation
- Docker Compose
- GitHub Actions
