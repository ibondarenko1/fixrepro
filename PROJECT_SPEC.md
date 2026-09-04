# FixRepro Project Specification

## Scope lock

This document fixes the Phase 1 product contract. Later work must preserve these boundaries unless a documented scope change is reviewed before implementation.

## Product objective

FixRepro replays an identical controlled security regression test against synthetic vulnerable and patched IoT OTA builds. It records hash-verified evidence and runs a positive control so that a patch is credited only when unsafe behavior is removed without breaking the intended update path.

## Target users

- Product security engineers validating remediation behavior
- Robotics and IoT development teams maintaining OTA update controls
- Security reviewers who need repeatable evidence for a specific regression case
- Educators and hackathon judges evaluating a safe security demonstration

## Behavioral security property

An OTA gateway must accept an update only when package integrity is valid and the Ed25519 signature verifies against the configured trusted public key. A valid checksum alone must not authorize installation.

The defined regression case can prove only whether this specific behavior reproduces under the tested conditions. It does not establish that the build is free of other vulnerabilities.

## Demonstration scenarios

### Scenario A: vulnerable build

1. Reset the virtual device to firmware `1.0.0`.
2. Provide a synthetic package with a valid SHA-256 checksum and an untrusted signature.
3. The vulnerable gateway checks package integrity only.
4. It accepts the update.
5. The device changes from `1.0.0` to `9.9.0-test`.
6. The individual security verdict is `FAIL`.

### Scenario B: patched build

1. Reset the virtual device to firmware `1.0.0`.
2. Replay the exact same untrusted package used in Scenario A.
3. The patched gateway verifies an Ed25519 signature against a trusted public key.
4. It rejects the update.
5. The device remains at `1.0.0`.
6. The individual security verdict is `PASS`.

### Scenario C: positive control

1. Reset the virtual device to firmware `1.0.0`.
2. Submit a synthetic package signed by the trusted key.
3. The patched gateway accepts it.
4. The device changes from `1.0.0` to `1.1.0`.
5. The positive-control verdict is `PASS`.

## Deterministic verdict rules

No language model, statistical classifier, or probabilistic system may determine a security verdict.

`PATCH_VERIFIED` requires all of the following:

1. The vulnerable execution observes `ACCEPTED`, changes the device to `9.9.0-test`, and receives `FAIL`.
2. The patched execution replays the same untrusted package, observes `REJECTED`, leaves the device at `1.0.0`, and receives `PASS`.
3. The positive control observes `ACCEPTED`, changes the device to `1.1.0`, and receives `PASS`.

`PATCH_NOT_VERIFIED` applies when complete deterministic observations contradict one or more required conditions. `INCONCLUSIVE` applies when an execution errors, evidence is missing, the initial state is wrong, package identity differs between the vulnerable and patched runs, or observations cannot be established reliably.

## Required evidence

Each execution must record:

- Verification, execution, case, and role identifiers
- UTC start and finish times
- Software build identifier
- Package filename and SHA-256
- Complete package envelope SHA-256 and request body SHA-256
- Signer fingerprint and trust classification
- Request method, target, selected metadata, and body hash
- Response status, selected metadata, and body hash
- Device firmware state before and after
- Secure expected decision and observed decision
- Deterministic individual verdict
- Separate artifact names and SHA-256 values

The bundle manifest must list separate bundle artifacts and their SHA-256 values. It must not place a hash of the evidence document inside that same evidence document.

## MVP definition of done

The future MVP is complete only when:

1. All four planned HTTP services run locally with documented health state.
2. Each scenario starts from a verified reset state.
3. The vulnerable and patched scenarios consume the exact same untrusted package bytes.
4. Ed25519 verification is enforced by the patched gateway.
5. The three deterministic verdicts and overall outcome follow this specification.
6. Evidence validates against the JSON Schema and all referenced artifact hashes verify.
7. A human-readable report explains observations without overstating assurance.
8. Automated tests cover success, failure, reset, mismatch, and inconclusive paths.
9. A two-minute local demonstration completes without external systems.

## Explicitly out of scope

- Real vendor firmware, hardware, or production infrastructure
- Real or unpublished vulnerabilities and private disclosure material
- Credentials, API tokens, persistent private signing keys, or production secrets
- General vulnerability discovery or exploit development
- Remote targeting, internet scanning, or deployment to real devices
- A claim that every vulnerability is fixed
- A claim that the evidence cannot be altered
- Autonomous or probabilistic security verdicts
- Production-grade key management, fleet management, or OTA deployment
- Organization-specific branding unrelated to FixRepro

## Planned service ports

| Component | Port | Status after Phase 4 |
|---|---:|---|
| Control plane and judge-facing web dashboard | 8000 | Implemented for localhost demonstration |
| Vulnerable OTA gateway | 8101 | Implemented for localhost demonstration |
| Patched OTA gateway | 8102 | Implemented for localhost demonstration |
| Virtual IoT device simulator | 8200 | Implemented for localhost demonstration |

The deterministic orchestrator, verdict engine, evidence generator, HTML report generator, manifest generator, independent bundle verifier, and in-memory job manager are implemented internal components and do not require public ports.

## Phase 3 implemented components

- Deterministic verification orchestrator
- Pure deterministic verdict engine
- Strict Pydantic evidence model and JSON Schema 1.1
- Atomic evidence and raw-artifact generation
- Self-contained HTML verification report
- Tamper-evident manifest with a separate root digest
- Independent bundle verification with verdict recomputation

## Phase 4 implemented components

- Judge-facing one-page dashboard and strict presentation models
- Local control API with one fixed background verification action
- Verified demo-bundle loading and live-run presentation
- Internal bundle registry and safe artifact routes
- Dashboard and report-specific security headers
- Local dashboard and end-to-end smoke runners
- One-container Dockerfile and Docker Compose topology

Cloud deployment, PDF export, AI features, and demonstration video remain unimplemented. Phase 5A adds continuous integration and submission screenshots without changing the product.

## Submission freeze

The core implementation is frozen for the VoltHacks submission. Phase 5A adds continuous integration and presentation material only. Device behavior, gateway policies, package and signing contracts, scenario transitions, verdict rules, evidence schema, bundle verification, dashboard routes, job behavior, artifact rules, Docker topology, and the tracked demo bundle remain unchanged.

Video recording, video upload, Devpost form entry, and Devpost submission are manual work outside this repository.

## Implementation phases

1. **Phase 1 (complete):** repository scaffold, executable specification, cases, evidence contract, and documentation.
2. **Phase 2 (complete):** synthetic virtual device, vulnerable and patched OTA gateways, in-memory signing identities, package generation, three-scenario runner, and deterministic unit tests.
3. **Phase 3 (complete):** verifier, evidence-bundle generator, schema validation, HTML report, manifest, and independent bundle verification.
4. **Phase 4 (complete):** control plane, plain web interface, Docker Compose launch path, and end-to-end smoke validation.
5. **Phase 5A (complete after validation):** GitHub Actions, final metadata, generated screenshots, video instructions, captions, judge notes, and submission checklist.

Phases 1 through 4 contain the product implementation. Phase 5A is release and submission preparation only. It adds no cloud deployment and does not claim that a video was recorded or that a Devpost entry was submitted.
