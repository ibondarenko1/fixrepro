# Security Policy

## Demonstration scope

FixRepro is a synthetic, controlled security demonstration. It must use only purpose-built virtual devices, packages, keys, and vulnerable or patched behaviors.

Do not add real vendor vulnerabilities, firmware, or exploit material without explicit authorization and an appropriate coordinated-disclosure process. Never copy private reports or embargoed details into this repository.

## Secret and key handling

- Private signing keys must never be committed.
- Generated demonstration keys must be ephemeral and recreated for an isolated run.
- Credentials, tokens, environment files, and sensitive reports or evidence must not be committed.
- Generated evidence belongs under ignored run directories unless it has been reviewed and intentionally reduced to a clearly synthetic sample.

## Safe service defaults

When services are implemented, they must bind to localhost by default. The demonstration must not scan networks, contact production devices, or accept real firmware.

## Reporting security issues in FixRepro

Report suspected vulnerabilities privately to the repository maintainer. Do not publish exploitable details before the issue can be assessed and remediated. Include only the minimum synthetic reproduction material needed for review and do not include secrets or third-party confidential data.
