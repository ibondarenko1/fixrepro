# FixRepro

FixRepro replays the same security test against vulnerable and patched robotics or IoT builds, captures hash-verified evidence, and proves the fix without breaking legitimate behavior.

## Problem

Security patches for connected systems are often accepted as code changes without repeatable proof that unsafe behavior is gone and legitimate behavior still works.

## Proposed solution

FixRepro will run one controlled regression case against two synthetic OTA gateway builds and a positive control. A deterministic verifier will compare observed decisions and device state with the case contract. An evidence generator will record build identifiers, request and response metadata, signer identity, device state, timestamps, artifacts, and SHA-256 hashes.

## Exact demonstration

1. **Vulnerable build:** a virtual device starts at `1.0.0`. An update with a valid checksum but an untrusted signer is accepted because the vulnerable gateway checks integrity only. The device changes to `9.9.0-test`; the individual verdict is `FAIL`.
2. **Patched build:** the device is reset to `1.0.0`, and the exact same untrusted package is replayed. The patched gateway verifies an Ed25519 signature against a trusted public key and rejects the package. The device remains at `1.0.0`; the individual verdict is `PASS`.
3. **Positive control:** the device is reset to `1.0.0`, then receives a package signed by the trusted key. The patched gateway accepts it and the device changes to `1.1.0`; the positive-control verdict is `PASS`.

The overall outcome is `PATCH_VERIFIED` only when all three observations occur. Any other result is `PATCH_NOT_VERIFIED` or `INCONCLUSIVE`.

## Planned architecture

The planned system has a control plane and web interface on port 8000, a vulnerable OTA gateway on port 8101, a patched OTA gateway on port 8102, and a virtual device simulator on port 8200. Separate planned components will perform deterministic verification, evidence-bundle generation, and human-readable report generation.

## Planned technology stack

- Python 3.12
- FastAPI
- Pydantic
- `cryptography` with Ed25519
- Docker Compose
- pytest
- Plain HTML, CSS, and JavaScript
- JSON Schema
- GitHub Actions

These technologies and components are planned; they are not implemented in Phase 1.

## Evidence model

Each future execution record will identify the test role, software build, package and signer, request and response metadata, device state before and after, expected and observed decisions, deterministic verdict, and artifact hashes. Bundle files will be listed with SHA-256 values. Evidence is hash-verified and tamper-evident, not tamper-proof. The evidence document will not contain its own hash.

## Safety boundaries

This project is a controlled demonstration using synthetic packages, keys, devices, and builds. It excludes real vendor firmware, unpublished vulnerabilities, private disclosure material, credentials, persistent signing keys, and production targets. Test services will bind to localhost by default when implemented.

## Limitations

FixRepro will evaluate only the defined regression case under recorded test conditions. It cannot prove that every vulnerability is fixed, that a build is generally secure, or that an evidence bundle could not be replaced by an actor who controls the storage environment.

## Hackathon development declaration

The repository, demonstration environment, evidence format, interface, and automation are new VoltHacks 2026 development. General methodology is informed by prior security research; no private research artifacts or unpublished vulnerability details are included.

## Current status

Phase 1 scaffold and executable specification. Application services are not implemented yet.
