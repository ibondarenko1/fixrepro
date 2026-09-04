# Judge Q&A

## What problem does FixRepro solve?

Security patches for connected systems are often accepted as code changes. FixRepro checks one defined behavior before and after a patch, records what happened, confirms the legitimate feature still works, and produces evidence another person can verify.

## Is FixRepro a vulnerability scanner?

No. It does not discover vulnerabilities or scan targets. It runs one fixed regression case against purpose-built localhost services. The browser cannot select another target, file, package, key, or command.

## Is the demonstrated vulnerability real?

The behavior is realistic, but the demonstration is synthetic. The packages, keys, virtual device, vulnerable gateway, and patched gateway were built for this project. No vendor firmware, real product, private report, or unpublished vulnerability is included.

## What is technically original?

The product combines exact byte replay, a vulnerable baseline, a patched test, a trusted positive control, deterministic verdict rules, and an independently checked evidence bundle in one small workflow. The browser presents the stored result but never decides it.

## Why replay the exact same bytes?

Changing the package between tests would add another variable. FixRepro reads the untrusted package once, keeps that byte array in memory, and uses it for both gateways. Matching envelope and request-body hashes record that identity.

## Why is the positive control necessary?

A gateway that rejects every update would block the unsafe input, but it would also break the product. The trusted update proves the patched path still accepts authorized software and moves the device from 1.0.0 to 1.1.0.

## How is the verdict determined?

Pure functions compare recorded decisions, reason codes, HTTP results, device state transitions, execution roles, and the two same-input hashes. `PATCH_VERIFIED` is possible only when all three scenarios match the fixed contract and no operational error occurred.

## Why does the project not use AI for the verdict?

This result should be reproducible. Given the same complete observations, the verdict must be the same every time. A probabilistic model would add uncertainty to a decision that can be expressed as explicit rules.

## What makes the evidence independently verifiable?

The bundle includes strict JSON evidence, raw sanitized scenario records, exact package copies, a public verification key, a report, and a sorted manifest. `scripts/verify_bundle.py` checks the root digest, every file hash and size, the schema, same-input proof, artifact records, and a recomputed outcome.

## Can the evidence detect modification?

No. It is tamper-evident when the manifest digest is retained separately. If a listed file changes, independent verification fails. This does not replace an externally trusted digital signature, a trusted timestamp, or independent laboratory validation.

## What does PATCH_VERIFIED actually prove?

It proves that the defined signer-trust regression behaved as recorded under the tested conditions: the unsafe baseline reproduced, the patched build blocked identical input, and the trusted update still succeeded. It does not prove that every vulnerability is fixed or that the build is generally secure.

## How could this apply to robotics or industrial IoT?

An authorized release lab could connect the same orchestration and evidence rules to approved device simulators, hardware benches, or CI builds. Each regression would still need a narrow security property, controlled state, observable outcomes, and a positive control.

## Why is the browser not allowed to provide a target?

FixRepro is a controlled demonstration, not an attack interface. The dashboard can trigger only one fixed localhost run. Keeping targets, files, paths, and commands out of browser input prevents the presentation layer from expanding the lab's authority.

## Why use a synthetic environment?

It makes the demo safe, reproducible, public, and easy to audit. Judges can inspect every behavior without vendor firmware, credentials, production devices, private disclosures, or network scanning.

## What would be built next?

The next engineering step would be narrow adapters for authorized robotics, smart-device, and industrial IoT labs. Those adapters should keep the same deterministic verdict and evidence boundaries. Production key management, hardware trust, and external signing would need separate designs and review.
