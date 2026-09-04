# Dashboard

## Purpose and layout

The Phase 4 dashboard is a one-page presentation layer over verified evidence. Its first viewport shows the overall outcome and the vulnerable, patched, and positive-control observations. Separate panels show the exact same-input hashes, bundle root digest, artifact links, tested property, workflow, safety scope, and limitation.

The source indicator distinguishes `Verified demo bundle` from `Live local verification`. The interface never calculates a verdict; it renders the strict presentation model created from `evidence.json` after independent bundle verification.

## Demo mode

On load, the browser requests `GET /api/v1/demo`. The server uses only `evidence/demo-bundle`, runs the independent verifier, parses `evidence.json` through `EvidenceDocument`, maps executions by role, and returns a safe summary. A missing or invalid demo produces `DEMO_BUNDLE_UNAVAILABLE`; it is never presented as verified or regenerated.

## Live mode and job states

The **Run live verification** button sends only `{}` with `Content-Type: application/json` and `X-FixRepro-Action: run-verification`. One non-daemon worker executes the existing fixed orchestrator. The in-memory states are `QUEUED`, `RUNNING`, `COMPLETED`, and `FAILED`.

`PATCH_NOT_VERIFIED` and `INCONCLUSIVE` are deterministic completed outcomes. `FAILED` is reserved for an operational failure that prevented a valid outcome. While running, the UI reports no fabricated per-scenario progress. The browser keeps the job ID in memory only.

## API routes

- `GET /health`
- `GET /api/v1/demo`
- `POST /api/v1/verifications`
- `GET /api/v1/verifications/{job_id}`
- `GET /api/v1/bundles/{bundle_id}/report`
- `GET /api/v1/bundles/{bundle_id}/evidence`
- `GET /api/v1/bundles/{bundle_id}/manifest`
- `GET /api/v1/bundles/{bundle_id}/digest`

There is no generic filesystem route, upload route, arbitrary target, or browser-controlled output path.

## Same-input proof

The presentation layer compares the vulnerable and patched `envelope_sha256` fields and their request `body_sha256` fields. `same_input_verified` is true only when both comparisons match. A stored `PATCH_VERIFIED` outcome with different hashes is rejected as an integrity failure.

## Artifact access

An internal registry maps `demo` and successful live job IDs to resolved bundle directories. IDs are never converted directly into paths. Before serving an artifact, the server re-verifies the entire bundle and permits only `report.html`, `evidence.json`, `manifest.json`, or `manifest.sha256`. Packages, keys, raw observations, and logs are never exposed through HTTP.

## Security headers

Dashboard pages and assets receive a self-only Content Security Policy, frame denial, MIME sniffing protection, no-referrer policy, a restrictive permissions policy, same-origin opener isolation, and `Cache-Control: no-store`. The report route has a separate policy that permits its existing inline CSS and forbids scripts. CORS and cookies are not enabled.

## Accessibility

The page uses semantic regions, one heading level-one, a skip link, keyboard-operable buttons and links, visible focus styles, an `aria-live` status region, text labels alongside visual symbols, responsive hash wrapping, and reduced-motion handling. Focus moves to the outcome once after a live run completes.

## No-arbitrary-input boundary

The browser cannot submit target URLs, files, firmware, packages, JSON test cases, keys, commands, output directories, or replacement flags. The only mutation endpoint accepts an empty JSON object plus an exact action header and permits one fixed verification at a time.

## Current limitations

The dashboard is a localhost hackathon demonstration without authentication or durable job history. It must not be published as a production service. It supports only the fixed synthetic signer-trust case and serves no external frontend resources.
