# FixRepro - Devpost final copy

## Project name

FixRepro

## Tagline

Prove the patch. Preserve the feature.

## Inspiration

A code change does not prove that a security patch works. Connected-system teams need a repeatable check that the unsafe behavior is gone and the legitimate feature still works.

## What it does

FixRepro runs one controlled over-the-air software update regression against synthetic vulnerable and patched IoT builds under fixed localhost conditions: first, it reproduces a gateway that accepts an integrity-valid update from an untrusted signer, then it sends the exact same package bytes to the patched gateway, and last it sends a trusted update to confirm that the patch preserved the intended feature.

The result is a tamper-evident evidence bundle with device state, build IDs, request and response hashes, signer identity, verdicts, and a self-contained report. A separate command checks the manifest, every listed file, the evidence schema, same-input hashes, and the recomputed outcome.

## Physical-world proof of concept

An owner-controlled Roomba s9+ produced a supported Locate melody during a separate authorized local test.

It demonstrates how an accepted FixRepro result can be connected to a physical output. The Roomba did not receive firmware and was not the OTA target.

The core Docker workflow remains synthetic and reproducible. The optional witness adapter is disabled by default, and this physical-output-witness test is supplemental.

No Roomba vulnerability was tested or claimed. No Roomba firmware was installed or modified. The repository does not claim a completed automated two-signal Roomba run.

## How it works

Each scenario starts by resetting the virtual device to firmware 1.0.0, the vulnerable gateway then accepts the integrity-valid untrusted package and changes the device to 9.9.0-test, the patched gateway uses Ed25519 digital-signature verification to reject the same bytes and leave the device at 1.0.0, and the positive control uses a trusted signature to reach 1.1.0.

Verdicts come from pure, deterministic rules. No LLM decides the result. `PATCH_VERIFIED` requires the unsafe baseline, rejection of identical input by the patch, a successful trusted update, and complete observations without an operational error.

## How we built it

I built the lab in Python 3.12 with FastAPI, Pydantic, and HTTPX. cryptography provides Ed25519 digital signatures, while JSON Schema Draft 2020-12 validates the evidence. pytest covers the security policy, device behavior, orchestrator, bundle checks, API boundary, and dashboard. The frontend uses plain HTML, CSS, and JavaScript with no external asset or build step.

docker compose runs the dashboard and its loopback-only child lab services in one non-root container, publishing only `127.0.0.1:8000` to the host. GitHub Actions repeats the validators, tests, demonstrations, dashboard smoke checks, and Docker run.

## Challenges

The tricky part was evidence identity. Scenario A and Scenario B had to use one byte array read once, held in memory, sent unchanged to both gateways, and recorded with matching hashes. I also had to avoid circular hashing: `evidence.json` cannot hash itself, and `report.html` cannot contain a manifest digest that includes the report.

The browser boundary took equal care. A client can request only one fixed run. It cannot choose a target, package, key, path, command, case, or output directory.

## Accomplishments

FixRepro now completes the full local proof from a single dashboard action. evidence.json records the unsafe baseline, the rejected same input, the preserved legitimate path, and the observations used for the verdict.

Private signing keys stay in memory and are never written to disk.

manifest.sha256 anchors the tracked demo bundle so it can be checked offline.

report.html presents the evidence without recalculating the result in the browser.

## What we learned

Identical input matters because a changed test cannot isolate the patch, the positive control matters because blocking every update would break the product, evidence verification matters because a readable report alone cannot show whether its files changed, and each of those checks answers a different failure mode.

## What is next

The same pattern could support authorized robotics, smart-device, industrial IoT, and connected-system release pipelines. The next engineering step would be narrow adapters for approved hardware labs and build systems, with the deterministic contract kept intact.

## Built with

Python 3.12, FastAPI, Pydantic, Ed25519 through the cryptography library, HTTPX, JSON Schema Draft 2020-12, pytest, plain HTML, CSS, JavaScript, Docker, Docker Compose, and GitHub Actions.

## Try it out

Docker:

```bash
git clone https://github.com/ibondarenko1/fixrepro.git
cd fixrepro
docker compose up --build
```

Open `http://127.0.0.1:8000`.

Local Python:

```powershell
py -3.12 -m venv .venv
.\.venv\Scripts\python.exe -m pip install -e ".[dev]"
.\.venv\Scripts\python.exe scripts\run_dashboard.py
```

On Linux or macOS, use `python3.12 -m venv .venv`, then `./.venv/bin/python` for install and launch.

## Development declaration

The repository, synthetic lab, evidence format, dashboard, and automation are new VoltHacks 2026 work. The general method is informed by prior security research.

## Safety and limitations

FixRepro is a software-based IoT security engineering demonstration. It uses synthetic packages, virtual devices, and localhost services. It contains no real vendor firmware, unpublished vulnerability details, credentials, or persistent private signing keys. The browser cannot choose arbitrary targets. No cloud deployment is provided.

`PATCH_VERIFIED` applies only to the defined signer-trust regression under the recorded test conditions, it does not prove that every vulnerability is fixed or that a build is generally secure, and the bundle is tamper-evident only when its manifest digest is retained separately, not a substitute for an externally trusted signature or independent laboratory validation.

## Suggested screenshot captions

1. FixRepro shows the three-part patch contract at a glance.

2. Matching hashes connect same-input replay to the evidence digest.

3. The self-contained report records each device transition and verdict.

4. The complete result stays readable on a mobile-width screen.
