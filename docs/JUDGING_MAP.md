# VoltHacks Judging Map

| Criterion | What FixRepro demonstrates | Concrete artifact that will prove it | What must be visible in the final demo |
|---|---|---|---|
| Innovation and Creativity | Exact-input replay plus a trusted positive control and independently verifiable evidence, rather than a code-diff claim. | Matching envelope and request hashes, three execution records, and the checked demo bundle. | The same untrusted package in both security runs, followed by the trusted control and one combined outcome. |
| Technical Complexity | Synthetic services, Ed25519 policy, deterministic orchestration, strict models, JSON Schema, manifest verification, dashboard, Docker, tests, and CI. | Source modules, 1.1 evidence schema, bundle verifier, test suite, Docker setup, and green GitHub Actions workflow. | Device transitions, trust decisions, build IDs, evidence hashes, and reproducible local execution. |
| Real World Impact | Release validation for authorized robotics, IoT, smart-device, industrial IoT, and connected-system workflows. | Narrow security property, reusable orchestration boundary, report, and documented limitations. | A specific conclusion tied to tested conditions, without a general security claim. |
| Design and Functionality | A one-page dashboard with verified demo loading, one live run, safe artifact routes, and responsive layout. | Dashboard, API smoke test, desktop and mobile screenshots, and self-contained HTML report. | Three cards, same-input proof, digest, safe links, and the live source change. |
| Presentation Quality | Four screenshots, a 2:10 script, captions, final Devpost copy, README, and evidence report. | `docs/submission`, README cover image, and tracked report. | A clean flow from the problem through the three outcomes to independently checked evidence. |

The final presentation must distinguish implemented behavior from manual submission work and describe evidence as hash-verified or tamper-evident.
