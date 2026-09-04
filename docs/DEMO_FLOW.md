# Two-Minute Judge Demonstration

This is the implemented Phase 4 dashboard flow.

| Time | Judge action | Required visible observation |
|---:|---|---|
| 0:00-0:12 | Open `http://127.0.0.1:8000`. | The tracked bundle verifies automatically; `PATCH VERIFIED` and the three scenario cards are immediately visible. |
| 0:12-0:28 | Scan the three cards. | Vulnerable accepts the untrusted update and changes to `9.9.0-test`; patched rejects the same input and stays at `1.0.0`; trusted control reaches `1.1.0`. |
| 0:28-0:40 | Read **Exact same input replayed**. | The full envelope and request-body SHA-256 values match across the vulnerable and patched scenarios. |
| 0:40-0:48 | Select **Run live verification**. | The UI reports only `Running deterministic verification…` and the generated job ID. No fake scenario progress appears. |
| 0:48-1:15 | Wait for the fixed local lab. | One background job starts the existing orchestrator, executes all three scenarios, publishes a normal ignored bundle, and verifies it. |
| 1:15-1:30 | Observe the completed result. | The source changes to `Live local verification`; the new verification ID, timestamp, hashes, digest, and three evidence-derived cards replace the demo. |
| 1:30-1:45 | Open **Open report**. | The self-contained report opens through the fixed, reverified report route. |
| 1:45-2:00 | Open the evidence, manifest, and digest links. | Only the four approved artifacts are available; the manifest digest supports independent tamper-evident verification. |

The browser cannot provide a target, package, path, command, key, case, output directory, or replacement flag. `PATCH_NOT_VERIFIED` and `INCONCLUSIVE` remain completed deterministic outcomes; only an operational failure produces a failed job.
