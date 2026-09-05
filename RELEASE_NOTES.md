# FixRepro v0.4.0 — VoltHacks 2026 Submission

FixRepro is a deterministic security release gate for a defined synthetic IoT signer-trust regression. This release includes:

- Exact-input replay against vulnerable and patched builds.
- A trusted positive control that checks legitimate update behavior.
- A deterministic verdict engine based only on recorded observations.
- A tamper-evident evidence bundle and self-contained HTML report.
- Independent bundle verification that recalculates hashes and verdicts.
- A judge-facing dashboard with a verified demo and one fixed live workflow.
- A Docker Compose launch path that publishes only the dashboard on host loopback.
- GitHub Actions CI for validators, tests, demonstrations, dashboard smoke checks, and Docker validation.
- Optional, default-off Roomba s9+ physical-output-witness code with a safe dry run and fake-transport tests.
- A supplemental owner-authorized proof record for one supported Locate melody. The Roomba was stationary, received no firmware, and was not the OTA target.

## Scope

The reproducible product remains a synthetic localhost lab. The Roomba proof of concept is separate from the Docker workflow and does not claim a Roomba vulnerability or firmware test.

`PATCH_VERIFIED` applies only to the defined regression under the recorded conditions.

It does not establish production readiness, prove every vulnerability is fixed, or show that a build is generally secure.

manifest.sha256 anchors the tracked demonstration bundle for independent checking.
