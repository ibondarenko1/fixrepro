# Two-Minute Demonstration Flow

This is the implemented Phase 3 CLI demonstration. The final dashboard is not implemented.

| Time | Operator action | Required visible observation |
|---:|---|---|
| 0:00-0:10 | Run `python scripts/run_verification.py --output-dir evidence/demo-bundle --replace`. | The orchestrator starts all three services on localhost and generates fresh synthetic packages. |
| 0:10-0:25 | Observe the vulnerable scenario in `evidence.json` or the report. | Reset state is `1.0.0`; the untrusted package is `ACCEPTED`; the device changes to `9.9.0-test`; verdict is `FAIL`. |
| 0:25-0:40 | Observe the patched security scenario. | Reset state is `1.0.0`; the identical request body hash is `REJECTED`; the device stays at `1.0.0`; verdict is `PASS`. |
| 0:40-0:55 | Observe the trusted positive control. | Reset state is `1.0.0`; the trusted package is `ACCEPTED`; the device changes to `1.1.0`; verdict is `PASS`. |
| 0:55-1:10 | Read the CLI result. | `PATCH_VERIFIED`, the repository-relative bundle path, the full root digest, and `PHASE3_VERIFICATION_PASS` are printed. |
| 1:10-1:25 | Open `evidence/demo-bundle/report.html` directly from disk. | The three visible result labels, same-input envelope hash, artifact list, safety scope, and limitations are readable. |
| 1:25-1:45 | Run `python scripts/verify_bundle.py evidence/demo-bundle`. | The command checks the manifest, every file, schema, same-input hashes, package records, and recomputed verdicts. |
| 1:45-2:00 | Compare the printed digest with `manifest.sha256`. | `BUNDLE_VERIFICATION_PASS` and the same root digest demonstrate modification detection when that digest is retained separately. |

If the vulnerable baseline does not reproduce, reset fails, package identity changes, an execution errors, or observations conflict, the result is `INCONCLUSIVE`. If the baseline reproduces and complete observations show that the patched behavior is absent, the result is `PATCH_NOT_VERIFIED`.
