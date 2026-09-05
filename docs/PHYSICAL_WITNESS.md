# Optional Roomba physical-output witness

FixRepro can translate an already-recorded verification decision into a supplemental physical signal.

The verified OTA target remains the synthetic virtual device; the Roomba s9+ is only an audible output witness.

An owner-controlled Roomba s9+ produced one finite Locate melody during a separate authorized local test.

It remained stationary, did not start cleaning, and received no firmware or settings change.

roomba-locate-proof.json contains the [sanitized observation](evidence/roomba-locate-proof.json).

## Safety model

- Physical-witness support is optional and disabled by default.
- Dry-run mode verifies the evidence and plans actions without loading credentials or opening a network connection.
- Live mode requires an exact owner-confirmation phrase and an existing Windows DPAPI credential file under ignored `.runtime` storage.
- The target must be a private RFC1918 address, the port is fixed to TLS MQTT 8883, and credentials never enter logs or tracked files.
- `RoombaLocateWitness` exposes one control action: `locate_once()`.
- The fixed action uses the proven local Locate request. There are no clean, move, dock, map, schedule, settings, or firmware methods.
- A complete plan permits at most two signals and waits at least 20 seconds between them. The patched scenario always sends no command.
- Witness success or failure cannot change `PATCH_VERIFIED` or modify the core evidence bundle.

## Deterministic plan

The CLI independently verifies a completed bundle before planning any physical action:

| Scenario | Required evidence | Witness plan |
|---|---|---|
| `VULNERABLE` | Untrusted input accepted; verdict `FAIL` | Signal once |
| `PATCHED` | Exact same input rejected; verdict `PASS` | No command |
| `POSITIVE_CONTROL` | Trusted input accepted; verdict `PASS` | Signal once |

Any other overall outcome, evidence mismatch, or same-input hash mismatch produces zero signals.

## Dry run

Install the optional dependency only when physical-witness support is needed:

```powershell
.\.venv\Scripts\python.exe -m pip install -e ".[physical]"
.\.venv\Scripts\python.exe scripts\roomba_witness.py --bundle evidence\demo-bundle --dry-run
```

The dry run prints the three planned actions and performs no network activity.

## Live owner-authorized use

Live mode is not part of the default Docker workflow or CI.

It relies on the already owner-authorized, encrypted local credential file; this repository does not retrieve, generate, or document device credentials.

The exact confirmation phrase shown by `--help` is required. Operators must keep the robot stationary in a clear area and stop if its condition is unsafe.

paho-mqtt is loaded only when the confirmed live path creates the fixed Locate transport.

No complete automated two-signal run is claimed in this repository. The tracked proof record covers only the separate one-signal test described above.
