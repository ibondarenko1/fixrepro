# FixRepro

FixRepro replays the same security test against vulnerable and patched robotics or IoT builds, captures hash-verified evidence, and proves the fix without breaking legitimate behavior.

## Problem

Security patches for connected systems are often accepted as code changes without repeatable proof that unsafe behavior is gone and legitimate behavior still works.

## Implemented Phase 3 product

FixRepro now runs a deterministic, localhost-only OTA regression workflow. The Verification orchestrator resets the virtual device, executes all three scenarios, derives verdicts from recorded observations, and publishes a tamper-evident evidence bundle. Bundle verification independently checks every listed file and recomputes the verdicts instead of trusting the stored outcome.

## Three-scenario verification

1. **Vulnerable baseline:** an integrity-valid package signed by an untrusted key is accepted. The device changes from `1.0.0` to `9.9.0-test`, reproducing the unsafe behavior.
2. **Patched security test:** the exact same untrusted package byte array is replayed. The patched gateway rejects it and the device remains at `1.0.0`.
3. **Positive control:** a trusted package is accepted by the patched gateway. The device changes from `1.0.0` to `1.1.0`, showing that legitimate update behavior is preserved.

The vulnerable and patched executions record the same complete package envelope SHA-256 and the same request body SHA-256. Any mismatch produces `INCONCLUSIVE`.

## Outcome meanings

- `PATCH_VERIFIED`: the vulnerable baseline reproduces, the patched build rejects the exact same unsafe bytes, the trusted positive control succeeds, and no operational error exists.
- `PATCH_NOT_VERIFIED`: the baseline reproduces but complete observations show that the patch still accepts the unsafe package or breaks the trusted positive control.
- `INCONCLUSIVE`: the baseline does not reproduce, required evidence is missing or contradictory, package hashes differ, reset is not confirmed, or an operational error prevents a safe conclusion.

These outcomes are calculated by pure deterministic functions. No language model or probabilistic system determines a verdict.

## Implemented architecture

- Virtual IoT device on `127.0.0.1:8200`
- Deliberately vulnerable OTA gateway on `127.0.0.1:8101`
- Patched Ed25519 OTA gateway on `127.0.0.1:8102`
- Verification orchestrator and verdict engine
- Evidence bundle and HTML report generators
- Independent Bundle verification command

The simulator reset and apply endpoints are intentionally unauthenticated local test interfaces. They are not production interfaces and must never be exposed beyond localhost.

## Local setup

Python 3.12 or newer is required. Install only into a repository-local virtual environment.

### Windows PowerShell

```powershell
py -3.12 -m venv .venv
.\.venv\Scripts\python.exe -m pip install -e ".[dev]"
```

If Python 3.12 is unavailable, another supported newer interpreter such as `py -3.13` may be used.

### Linux or macOS

```bash
python3.12 -m venv .venv
./.venv/bin/python -m pip install -e '.[dev]'
```

## Run verification

Windows:

```powershell
.\.venv\Scripts\python.exe scripts\run_verification.py
.\.venv\Scripts\python.exe scripts\run_verification.py --repeat 3
```

Linux or macOS:

```bash
./.venv/bin/python scripts/run_verification.py
./.venv/bin/python scripts/run_verification.py --repeat 3
```

Normal bundles are written under ignored `evidence/runs/<verification_id>/`. The tracked demonstration report is available at [evidence/demo-bundle/report.html](evidence/demo-bundle/report.html).

## Verify a bundle independently

```powershell
.\.venv\Scripts\python.exe scripts\verify_bundle.py evidence\demo-bundle
```

The verifier checks the root digest, strict manifest, every file hash and size, safe relative paths, evidence schema, package records, raw artifact records, same-input hashes, stored individual verdicts, and recomputed overall outcome.

## Evidence bundle structure

```text
evidence/demo-bundle/
  evidence.json
  report.html
  manifest.json
  manifest.sha256
  packages/
    untrusted-update.json
    trusted-update.json
  raw/
    vulnerable.json
    patched.json
    positive-control.json
  trust/
    trusted-public-key.pem
  run.log
```

`manifest.json` covers every final bundle file except itself and `manifest.sha256`. The SHA-256 in `manifest.sha256` is the bundle root digest. `evidence.json` omits its own hash and lists only artifacts finalized before it, avoiding circular self-hashing.

## Safety boundaries

This is a controlled demonstration using synthetic packages, keys, devices, and builds. It excludes real vendor firmware, private disclosure material, credentials, persistent private signing keys, production targets, and external scanning. Private Ed25519 keys exist only as in-memory Python objects during package generation and are never serialized.

The bundle is tamper-evident when its published manifest digest is retained separately. It is not tamper-proof and is not a substitute for an externally trusted signature or independent laboratory validation.

## Limitations

FixRepro verifies only the defined signer-trust regression under recorded conditions. `PATCH_VERIFIED` does not prove that every vulnerability is fixed or that a build is generally secure. The Phase 3 workflow has no production authentication, persistent device storage, hardware integration, fleet management, or cloud deployment.

## Hackathon development declaration

The repository, demonstration environment, evidence format, interface plan, and automation are new VoltHacks 2026 development. The general methodology is informed by prior security research; no private research artifact or unpublished vulnerability detail is included.

## Current status

Phase 3 deterministic verification and evidence generation are implemented and locally testable.

Implemented now:

- Virtual device
- Vulnerable gateway
- Patched gateway
- Ed25519 package generation
- Three-scenario demonstration runner
- Unit tests and Phase 3 integration tests
- Verification orchestrator
- Deterministic verdict engine
- Evidence bundle generation
- Self-contained HTML report
- Bundle manifest and root digest
- Bundle verification
- Unit and integration tests

## Not implemented yet

- Web dashboard
- Docker Compose
- GitHub Actions
- Cloud deployment
- PDF export
- AI features
- Submission screenshots and video
- Devpost submission
