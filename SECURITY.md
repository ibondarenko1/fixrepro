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

## Dashboard boundary

The Phase 4 dashboard is a localhost demonstration without production authentication. It must not be exposed publicly. Browser clients cannot provide targets, paths, packages, keys, commands, cases, or output configuration, and only one fixed verification may run at a time.

Artifact routes use an internal registry of known bundle IDs and independently reverify a bundle before serving only its report, evidence, manifest, or digest. No generic filesystem endpoint exists. The dashboard uses local HTML, CSS, and JavaScript only; it enables no CORS support, cookies, analytics, or external frontend dependency.

In the one-container Docker topology, Compose publishes only the dashboard on host loopback. The virtual device and both OTA gateway ports are not published.

## Reporting security issues in FixRepro

Report suspected vulnerabilities privately to the repository maintainer. Do not publish exploitable details before the issue can be assessed and remediated. Include only the minimum synthetic reproduction material needed for review and do not include secrets or third-party confidential data.
