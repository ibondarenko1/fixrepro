# Docker

## One-container topology

Phase 4 uses one application container. The existing verifier starts the virtual device and both OTA gateways on loopback. Keeping them in the dashboard container preserves that tested topology and avoids publishing their lab ports.

Only the dashboard is published to the host at `127.0.0.1:8000`. The child services remain reachable only as loopback processes inside the container.

## Runtime controls

The image uses `python:3.12-slim`, installs only runtime dependencies, and runs as the fixed non-root UID `10001`. Linux capabilities are dropped, `no-new-privileges` is set, privileged and host-network modes are absent, and the Docker socket is not mounted.

`FIXREPRO_CONTAINER_MODE=1` permits the dashboard to bind to `0.0.0.0` inside the container. Compose still limits host exposure to `127.0.0.1`.

## Build

```bash
docker compose build
```

## Start

```bash
docker compose up -d
```

Open `http://127.0.0.1:8000`.

## Health

```bash
docker compose ps
```

The image and Compose health checks use Python standard-library HTTP access to `127.0.0.1:8000/health`; no extra operating-system package is installed.

## Smoke test

With the container healthy:

```powershell
.\.venv\Scripts\python.exe scripts\run_phase4_smoke.py --base-url http://127.0.0.1:8000 --external-server
```

The smoke test loads the tracked demo, starts one real live verification, validates all four safe artifact routes, checks response headers, and confirms the child lab ports close after the job.

## Stop

```bash
docker compose down --remove-orphans
```

## Evidence lifecycle and limitations

The tracked demo bundle is copied into the image. Fresh live-run evidence is written under `evidence/runs` inside the container and is ephemeral because Compose declares no volume. Container logs contain high-level service events only and must not contain package payloads or private key material.

This container is a local demonstration, not a hardened multi-user service. It has no authentication and must not be exposed publicly. It contacts no external target and accepts no arbitrary test input.
