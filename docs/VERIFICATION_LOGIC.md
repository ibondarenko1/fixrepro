# Verification Logic

FixRepro evaluates one defined OTA signer-trust property: a package must be accepted only when its payload integrity is valid and its Ed25519 signature verifies under the configured trusted public key.

## Baseline reproduction

The virtual device is reset and its full initial state is confirmed. The vulnerable gateway receives an integrity-valid package signed by an untrusted key. A complete baseline reproduction requires HTTP 200, `ACCEPTED`, `CHECKSUM_ONLY_ACCEPTED`, and the device transition from `1.0.0` to `9.9.0-test`. That execution receives `FAIL` because it demonstrates the controlled unsafe behavior.

If the vulnerable baseline does not reproduce, the overall result is `INCONCLUSIVE`. Without the baseline, the workflow cannot show that the patched test is a regression of the same behavior.

## Exact same-input replay

The orchestrator reads the untrusted package once as raw bytes. It uses that exact in-memory byte array for both the vulnerable and patched requests. Both executions record the complete package envelope SHA-256 and request body SHA-256. The overall result becomes `INCONCLUSIVE` if either pair differs or an execution's envelope and request hashes disagree.

## Patched rejection

After a confirmed reset, the patched gateway validates payload size and hash, recomputes the signer fingerprint, compares the raw public key with its trusted key, and verifies the Ed25519 signature. The expected security result is HTTP 403, `REJECTED`, `UNTRUSTED_SIGNER`, and unchanged device state at `1.0.0`. That execution receives `PASS`.

If the patched gateway accepts and applies the untrusted package after a reproduced baseline, the execution receives `FAIL` and the overall outcome is `PATCH_NOT_VERIFIED`.

## Positive control

The device is reset again and the patched gateway receives a package signed by the trusted key. HTTP 200, `ACCEPTED`, `TRUSTED_SIGNATURE_ACCEPTED`, and a transition from `1.0.0` to `1.1.0` produce `PASS`.

A complete rejection of the trusted update is a functional regression. When the unsafe baseline reproduced, this makes the overall outcome `PATCH_NOT_VERIFIED` even if the patched gateway blocked the untrusted input.

## Overall outcomes

`PATCH_VERIFIED` requires all of the following:

1. The unsafe vulnerable baseline is reproduced and receives `FAIL`.
2. The patched execution uses the exact same untrusted bytes, rejects them, leaves device state unchanged, and receives `PASS`.
3. The trusted positive control is accepted, updates the device, and receives `PASS`.
4. No execution has an operational error or conflicting observation.

`PATCH_NOT_VERIFIED` requires a reproduced baseline plus complete, coherent observations proving that required patch behavior is absent. This includes accepting the untrusted package or breaking the trusted positive control.

`INCONCLUSIVE` covers a missing baseline, service or reset failure, malformed response, missing evidence, differing input hashes, conflicting state, duplicate or missing roles, or any condition that prevents a safe deterministic conclusion.

## Determinism and error handling

Verdict functions operate only on supplied evidence models. They perform no HTTP, filesystem, time, environment, random, or model operations. The bundle verifier calls the same pure functions and compares recomputed verdicts with stored labels. Operational code records observations but cannot assign an unsupported successful result.

Services use bounded timeouts and localhost-only URLs. The orchestrator stops only the child processes it started and confirms the three ports close. It never terminates an unknown process.

## Scope of PATCH_VERIFIED

`PATCH_VERIFIED` shows that this specific signer-trust behavior changed as required under the recorded synthetic test conditions while the defined legitimate update still worked. It does not prove that every vulnerability is fixed, that other OTA properties are correct, or that a production device is secure.
