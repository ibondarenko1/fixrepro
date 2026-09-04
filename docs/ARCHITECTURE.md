# Planned Architecture

All components in this document are planned. Phase 1 defines their contracts but does not implement them.

## Component responsibilities

| Component | Planned responsibility | Planned port |
|---|---|---:|
| Control plane and web interface | Orchestrate resets and executions, display deterministic results, and expose evidence downloads | 8000 |
| Vulnerable OTA gateway | Model the unsafe integrity-only acceptance behavior | 8101 |
| Patched OTA gateway | Enforce package integrity and Ed25519 signer trust | 8102 |
| Virtual IoT device simulator | Hold synthetic firmware state and apply authorized version changes | 8200 |
| Deterministic verifier | Derive individual verdicts and the overall outcome from recorded observations | Internal |
| Evidence bundle generator | Write execution records, artifact manifests, and SHA-256 values | Internal |
| Report generator | Produce a human-readable summary from the verified evidence | Internal |

## Trust boundaries

1. **Operator to control plane:** the operator selects a fixed case but does not supply verdicts.
2. **Control plane to gateways:** the same untrusted package bytes must cross this boundary for the vulnerable and patched executions.
3. **Gateways to virtual device:** a gateway decision controls whether the simulated device may change state.
4. **Runtime to verifier:** observations are inputs; the verifier must not trust service-reported verdicts.
5. **Verifier to evidence storage:** hashes can reveal later modification but cannot prevent replacement by an actor who controls both evidence and reference hashes.

All planned HTTP listeners must bind to localhost by default.

## Planned data flow

1. The control plane selects a versioned case and confirms its package identity.
2. It resets the device and confirms firmware `1.0.0`.
3. It sends the untrusted package to the vulnerable gateway and records request, response, and device state.
4. It resets and confirms the same initial state.
5. It sends the exact same package bytes to the patched gateway and records the same evidence classes.
6. It resets again and sends the trusted positive-control package to the patched gateway.
7. The verifier derives all verdicts from observed decisions, version transitions, package hashes, and execution completeness.
8. The evidence and report generators write separate artifacts and a bundle manifest.

## Reset requirement

Every scenario must begin with an explicit reset followed by an observed firmware version of `1.0.0`. A missing or failed reset makes the affected execution `INCONCLUSIVE`. The vulnerable and patched executions must also record the same untrusted package SHA-256.

## Deterministic verdict flow

- Vulnerable: `ACCEPTED` plus `1.0.0 -> 9.9.0-test` produces `FAIL`.
- Patched: `REJECTED` plus `1.0.0 -> 1.0.0` produces `PASS`.
- Positive control: `ACCEPTED` plus `1.0.0 -> 1.1.0` produces `PASS`.
- Only that exact complete combination produces `PATCH_VERIFIED`.
- Complete contradictory observations produce `PATCH_NOT_VERIFIED`.
- Missing, mismatched, or error observations produce `INCONCLUSIVE`.

No probabilistic component participates in this flow.

## Evidence generation flow

The future runner will capture timestamps, build identifiers, package and signer identity, request and response metadata, device states, and raw synthetic artifacts. The generator will calculate SHA-256 values after each artifact is finalized, then list those separate files in the bundle manifest. The manifest will not include its own hash. A human-readable report will be derived from the same observations and will use the term hash-verified or tamper-evident evidence.

## Architecture diagram

```mermaid
flowchart LR
    O[Operator] --> CP[Control plane and web interface\nplanned :8000]

    subgraph Local synthetic test network
        CP --> VG[Vulnerable OTA gateway\nplanned :8101]
        CP --> PG[Patched OTA gateway\nplanned :8102]
        VG --> D[Virtual IoT device\nplanned :8200]
        PG --> D
    end

    CP --> V[Deterministic verifier]
    D --> V
    V --> E[Evidence bundle generator]
    E --> R[Human-readable report generator]
    E --> B[(Hash-verified bundle files)]
    R --> B
```

## Demonstration sequence

```mermaid
sequenceDiagram
    actor Operator
    participant Control as Control plane
    participant Device as Virtual device
    participant Vulnerable as Vulnerable gateway
    participant Patched as Patched gateway
    participant Verifier as Deterministic verifier
    participant Evidence as Evidence generator

    Operator->>Control: Start fixed regression case
    Control->>Device: Reset to 1.0.0
    Device-->>Control: State confirms 1.0.0
    Control->>Vulnerable: Send untrusted package
    Vulnerable->>Device: Apply 9.9.0-test
    Device-->>Control: State is 9.9.0-test
    Control->>Device: Reset to 1.0.0
    Device-->>Control: State confirms 1.0.0
    Control->>Patched: Replay identical untrusted package
    Patched-->>Control: REJECTED
    Device-->>Control: State remains 1.0.0
    Control->>Device: Reset to 1.0.0
    Device-->>Control: State confirms 1.0.0
    Control->>Patched: Send trusted 1.1.0 package
    Patched->>Device: Apply 1.1.0
    Device-->>Control: State is 1.1.0
    Control->>Verifier: Submit recorded observations
    Verifier-->>Control: PATCH_VERIFIED if all rules match
    Control->>Evidence: Generate artifacts and hashes
    Evidence-->>Operator: Bundle and readable report
```
