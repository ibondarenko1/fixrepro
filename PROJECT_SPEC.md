# FixRepro Project Specification

## Scope lock

This document fixes the Phase 1 product contract. Later work must preserve these boundaries unless a documented scope change is reviewed before implementation.

## Product objective

FixRepro will replay an identical controlled security regression test against synthetic vulnerable and patched IoT OTA builds. It will record hash-verified evidence and run a positive control so that a patch is credited only when unsafe behavior is removed without breaking the intended update path.

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
- A claim that evidence is tamper-proof
- Autonomous or probabilistic security verdicts
- Production-grade key management, fleet management, or OTA deployment
- Organization-specific branding unrelated to FixRepro

## Planned service ports

| Planned component | Port |
|---|---:|
| Control plane and web interface | 8000 |
| Vulnerable OTA gateway | 8101 |
| Patched OTA gateway | 8102 |
| Virtual IoT device simulator | 8200 |

The deterministic verifier, evidence generator, and report generator are planned internal components and do not require public ports.

## Future implementation phases

1. **Phase 1:** repository scaffold, executable specification, cases, evidence contract, and documentation.
2. **Phase 2:** synthetic virtual device and OTA gateway behavior with deterministic unit tests.
3. **Phase 3:** verifier, evidence-bundle generator, schema validation, and report generator.
4. **Phase 4:** control plane, plain web interface, Docker Compose integration, and end-to-end tests.
5. **Phase 5:** GitHub Actions, demonstration hardening, accessibility review, and final presentation assets.

Only Phase 1 is represented as complete in this repository state.
