# Two-Minute Demonstration Flow

This is the planned final demonstration. Phase 1 does not implement the steps.

| Time | Operator action | Required visible observation |
|---:|---|---|
| 0:00-0:10 | Open the fixed OTA signer regression case. | Case IDs, security property, synthetic package identities, and deterministic rules are visible. |
| 0:10-0:20 | Reset the virtual device. | Device state confirms firmware `1.0.0`. |
| 0:20-0:40 | Run the untrusted package against the vulnerable gateway. | Checksum is valid, signer is `UNTRUSTED`, decision is `ACCEPTED`, device changes to `9.9.0-test`, verdict is `FAIL`. |
| 0:40-0:50 | Reset the device. | Device state again confirms firmware `1.0.0`. |
| 0:50-1:10 | Replay the exact same untrusted package against the patched gateway. | The package SHA-256 matches the vulnerable run, decision is `REJECTED`, device remains `1.0.0`, verdict is `PASS`. |
| 1:10-1:20 | Reset the device. | Device state again confirms firmware `1.0.0`. |
| 1:20-1:40 | Submit the trusted positive-control package to the patched gateway. | Signer is `TRUSTED`, decision is `ACCEPTED`, device changes to `1.1.0`, verdict is `PASS`. |
| 1:40-1:52 | Generate the evidence bundle. | Build IDs, UTC timestamps, signer fingerprints, request and response metadata, before and after state, and SHA-256 artifact hashes are visible. |
| 1:52-2:00 | Open the verification summary. | The three individual verdicts and final deterministic outcome `PATCH_VERIFIED` are visible. |

If a reset fails, package identity changes, an execution errors, or required observations are missing, the demonstration must show `INCONCLUSIVE` rather than a successful outcome. If complete observations contradict the required patch behavior, it must show `PATCH_NOT_VERIFIED`.
