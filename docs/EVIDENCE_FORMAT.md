# Evidence Format

FixRepro Phase 3 produces a tamper-evident evidence bundle for one deterministic verification run. All paths stored inside the bundle are repository-independent relative POSIX paths.

## Bundle structure

```text
<bundle>/
  evidence.json
  report.html
  manifest.json
  manifest.sha256
  packages/
    untrusted-update.json
    trusted-update.json
  raw/
    vulnerable.json
    patched.json
    positive-control.json
  trust/
    trusted-public-key.pem
  run.log
```

Private signing keys are never serialized. The trust directory contains only the public Ed25519 key used by the patched gateway.

## Evidence schema

`evidence.json` conforms to JSON Schema Draft 2020-12 in `schemas/evidence.schema.json`, schema version `1.1`. It contains the verification identifier and UTC creation time, fixed case identity, exactly one execution for each role, the deterministic overall outcome, and records for the seven artifacts finalized before the evidence document.

Each execution records a stable build identifier, timestamps, package identity, sanitized request metadata, response status and hashes, complete device state before and after, secure expected decision, observed decision, individual verdict, and its raw scenario artifact.

## Payload hash and envelope hash

`package.sha256` is the SHA-256 of the decoded synthetic firmware payload. It establishes payload integrity.

`package.envelope_sha256` is the SHA-256 of the complete raw JSON package file bytes, including the manifest, encoded payload, public signer key, declared fingerprint, signature, formatting, and final newline. The vulnerable and patched executions must have the same envelope hash.

The orchestrator reads the untrusted package file once, retains that byte array, and submits the same object in both executions. The two matching envelope hashes make that same-input property independently checkable from the stored package file.

## Request and response hashes

`request.body_sha256` covers the exact HTTP request body bytes. For the vulnerable and patched security executions it must equal the shared untrusted envelope hash and must match across both executions.

`response.body_sha256` covers the raw gateway HTTP response bytes. The response record also contains the observed HTTP status, gateway decision, and stable reason code. Raw scenario files store sanitized request metadata, the parsed gateway response, and independently observed before and after device states. They do not store firmware payload contents separately or environment variables.

## Artifact records

Every artifact record has a relative path, SHA-256, byte count, and media type. The bundle verifier compares these values with the actual files. Service stdout remains under ignored runtime storage and is not included in the evidence bundle.

## Manifest and root digest

After all evidence and report files are final, `manifest.json` lists every bundle file except `manifest.json` and `manifest.sha256`. Entries are sorted by path and contain the relative path, SHA-256, and byte count.

`manifest.sha256` contains the SHA-256 of `manifest.json` in standard text form. This value is the bundle root digest and should be retained separately when the bundle is distributed.

Run independent verification with:

```text
python scripts/verify_bundle.py evidence/demo-bundle
```

The command validates safe paths, strict JSON, file presence, file sizes and hashes, JSON Schema conformance, package evidence, exact replay hashes, individual verdicts, and the recomputed overall outcome. It also rejects symlinks and unlisted files.

## No circular self-hashing

`evidence.json` does not list itself. It also omits `report.html`, which is generated from the finalized evidence. The final manifest covers both files but excludes itself and its own digest. The report points to `manifest.sha256` instead of embedding a digest that would change when the report changes.

## Limitation

The bundle is tamper-evident when its published manifest digest is retained separately. It is not a substitute for an externally trusted digital signature or independent laboratory validation. An actor who can replace both the bundle and every external copy of its digest can replace the evidence without detection by this format alone.
