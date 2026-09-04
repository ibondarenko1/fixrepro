# VoltHacks Judging Map

All implementation artifacts below are planned unless they already exist as Phase 1 specifications or schemas.

| Criterion | What FixRepro demonstrates | Concrete artifact that will prove it | What must be visible in the final demo |
|---|---|---|---|
| Innovation and Creativity | A patch is evaluated by replaying identical unsafe input and then proving legitimate behavior with a positive control, rather than showing only a code diff. | Versioned cases, matched package hashes, three execution records, and deterministic outcome rules | The same untrusted package hash in both regression runs, followed by the trusted control and one combined outcome |
| Technical Complexity | Coordinated state reset, two target behaviors, Ed25519 trust verification, deterministic verification, schema-constrained evidence, and artifact hashing | Local services, verifier tests, evidence schema, validated bundle manifest, and integration tests | Live state transitions, signer trust decisions, request and response metadata, and verifier inputs and outputs |
| Real World Impact | A repeatable pattern for asking whether one specific connected-system security behavior was fixed without breaking its authorized path | Human-readable verification report tied to build IDs, cases, observations, and hashes | A narrow, accurate conclusion that states the tested conditions and avoids a general security claim |
| Design and Functionality | A focused workflow that makes vulnerable, patched, and positive-control results easy to compare | Control-plane interface, accessible status presentation, evidence download, and deterministic failure states | Clear initial state, three labeled scenarios, visible resets, individual verdicts, and actionable inconclusive output |
| Presentation Quality | A complete two-minute narrative from unsafe reproduction through patch verification and evidence review | Demo script, architecture diagrams, concise project copy, and final report | One uninterrupted flow with readable labels, timestamps, hashes, and the final `PATCH_VERIFIED` rule explanation |

The final presentation must distinguish implemented behavior from planned work and describe evidence as hash-verified or tamper-evident, not tamper-proof.
