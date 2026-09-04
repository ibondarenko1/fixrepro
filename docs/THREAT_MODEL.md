# Threat Model

## Scope

This threat model covers a future localhost-only, synthetic IoT OTA security demonstration. It does not cover a production update service or a real device fleet.

## Assets

- Integrity of the versioned regression cases
- Identity and bytes of the synthetic OTA packages
- Trusted public-key configuration used by the patched gateway
- Virtual device state before and after each scenario
- Software build identifiers
- Recorded request and response metadata
- Deterministic verdict rules and their outputs
- Evidence artifacts, SHA-256 values, and the generated report

## Actors

- **Authorized operator:** starts the fixed demonstration and reviews results.
- **Demonstration maintainer:** authors code, cases, and synthetic fixtures.
- **Synthetic untrusted signer:** models a package signer outside the configured trust set.
- **Local process or user:** may attempt to alter state, requests, or stored evidence.
- **Evidence reviewer:** checks whether recorded artifacts support the narrow result.

## Trust boundaries

- Operator input entering the control plane
- Package and metadata crossing from the control plane to each gateway
- Gateway decisions reaching the virtual device
- Runtime observations entering the deterministic verifier
- Finalized artifacts entering evidence storage or leaving the local environment

## Security assumptions

- The host and test runner are under authorized control during a demonstration.
- Synthetic package bytes can be kept identical between the vulnerable and patched runs.
- Every scenario can reset and confirm device firmware `1.0.0`.
- The patched gateway receives the intended trusted public key.
- Ephemeral demonstration private keys are generated outside version control and discarded after use.
- SHA-256 is used to detect changes to finalized artifacts, not to establish an independent chain of custody.

## Threats addressed

- Accepting an integrity-valid update signed by an untrusted key
- Mistaking a checksum check for signer authorization
- Claiming a patch result without replaying the same unsafe input
- Claiming success when legitimate trusted updates are also broken
- Silent package substitution between vulnerable and patched executions
- Unnoticed modification of separately hashed evidence artifacts
- A service self-reporting a favorable verdict that is not supported by device state

## Threats not addressed

- Other OTA, device, network, or application vulnerabilities
- Compromise of a production signing system or hardware root of trust
- Side-channel, fault-injection, rollback, or supply-chain attacks
- Host compromise that can replace both evidence and its reference hashes
- Long-term key custody, fleet enrollment, revocation, or recovery
- Real vendor behavior, firmware, devices, or disclosure handling
- Completeness of testing beyond the defined regression case

## Evidence-integrity limitations

The implemented bundle is hash-verified and tamper-evident. SHA-256 values can show that a file differs from the value recorded in the manifest. They do not make evidence tamper-proof, prove who controlled the host, provide trusted time, or prevent coordinated replacement of both an artifact and its manifest entry. The evidence document does not contain its own hash because that would create a circular definition.

## Safe demonstration constraints

- Use only synthetic packages, builds, device identities, and localhost targets.
- Never add real vendor firmware or unpublished vulnerability details.
- Never commit credentials or private signing keys.
- Generate demonstration keys ephemerally and discard them after the run.
- Bind future services to localhost by default.
- Reset and verify the virtual device before every scenario.
- Do not scan networks or connect the demonstration to production devices.
- Keep sensitive generated evidence and reports out of version control.
- Derive verdicts only from deterministic observations.
