#!/usr/bin/env python3
"""Run the Phase 4 dashboard smoke contract on loopback only."""

from __future__ import annotations

import argparse
import json
import os
import socket
import subprocess
import sys
import time
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

import httpx

from fixrepro_core.config import (
    DEVICE_PORT,
    LOOPBACK_HOST,
    PATCHED_GATEWAY_PORT,
    VULNERABLE_GATEWAY_PORT,
)


ROOT = Path(__file__).resolve().parents[1]
DASHBOARD_PORT = 8000
EXPECTED_DEMO_DIGEST = "10fd80148896935b10fd1ccfd056e345d9a4537dff35473c4a025b9dbcab0204"
CHILD_PORTS = (VULNERABLE_GATEWAY_PORT, PATCHED_GATEWAY_PORT, DEVICE_PORT)
ALL_PORTS = (DASHBOARD_PORT, *CHILD_PORTS)
REQUEST_TIMEOUT_SECONDS = 5.0
HEALTH_TIMEOUT_SECONDS = 20.0
JOB_TIMEOUT_SECONDS = 90.0


class SmokeFailure(RuntimeError):
    """A dashboard smoke assertion failed."""


def port_accepts_connections(port: int) -> bool:
    probe = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    probe.settimeout(0.25)
    try:
        return probe.connect_ex((LOOPBACK_HOST, port)) == 0
    finally:
        probe.close()


def wait_for_ports_closed(ports: tuple[int, ...], timeout: float = 8.0) -> list[int]:
    deadline = time.monotonic() + timeout
    while True:
        occupied = [port for port in ports if port_accepts_connections(port)]
        if not occupied or time.monotonic() >= deadline:
            return occupied
        time.sleep(0.1)


def require(condition: bool, message: str) -> None:
    if not condition:
        raise SmokeFailure(message)


def validate_base_url(value: str) -> str:
    parsed = urlsplit(value)
    if (
        parsed.scheme != "http"
        or parsed.hostname != LOOPBACK_HOST
        or parsed.username is not None
        or parsed.password is not None
        or parsed.path not in {"", "/"}
        or parsed.query
        or parsed.fragment
        or parsed.port is None
    ):
        raise argparse.ArgumentTypeError("base URL must be a plain loopback HTTP origin")
    return value.rstrip("/")


def wait_for_health(client: httpx.Client, base_url: str, process: subprocess.Popen[str] | None) -> None:
    deadline = time.monotonic() + HEALTH_TIMEOUT_SECONDS
    last_error = "no response"
    while time.monotonic() < deadline:
        if process is not None and process.poll() is not None:
            raise SmokeFailure(f"dashboard exited before health check with code {process.returncode}")
        try:
            response = client.get(f"{base_url}/health")
            if response.status_code == 200 and response.json() == {
                "status": "ok",
                "service": "fixrepro-dashboard",
                "version": "0.4.0",
            }:
                return
            last_error = f"HTTP {response.status_code}"
        except (httpx.RequestError, ValueError) as exc:
            last_error = str(exc)
        time.sleep(0.15)
    raise SmokeFailure(f"dashboard did not become healthy: {last_error}")


def parse_json(response: httpx.Response, label: str) -> dict[str, Any]:
    try:
        value = response.json()
    except ValueError as exc:
        raise SmokeFailure(f"{label} did not return JSON") from exc
    if not isinstance(value, dict):
        raise SmokeFailure(f"{label} JSON was not an object")
    return value


def assert_no_absolute_path(value: Any, label: str) -> None:
    text = json.dumps(value, sort_keys=True)
    forbidden = (str(ROOT), str(ROOT).replace("\\", "\\\\"), "C:\\\\", "/home/", "/Users/", "/opt/")
    for marker in forbidden:
        require(marker not in text, f"{label} exposed an absolute local path")


def validate_presentation(value: dict[str, Any], expected_digest: str | None = None) -> None:
    require(value.get("verification_outcome") == "PATCH_VERIFIED", "outcome was not PATCH_VERIFIED")
    require(value.get("same_input_verified") is True, "same-input verification was not true")
    scenarios = value.get("scenarios")
    require(isinstance(scenarios, list) and len(scenarios) == 3, "exactly three scenarios are required")
    by_role = {item.get("role"): item for item in scenarios if isinstance(item, dict)}
    expected = {
        "VULNERABLE": (200, "ACCEPTED", "CHECKSUM_ONLY_ACCEPTED", "FAIL", "1.0.0", "9.9.0-test"),
        "PATCHED": (403, "REJECTED", "UNTRUSTED_SIGNER", "PASS", "1.0.0", "1.0.0"),
        "POSITIVE_CONTROL": (200, "ACCEPTED", "TRUSTED_SIGNATURE_ACCEPTED", "PASS", "1.0.0", "1.1.0"),
    }
    require(set(by_role) == set(expected), "scenario roles were incomplete")
    for role, fields in expected.items():
        scenario = by_role[role]
        actual = (
            scenario.get("http_status"),
            scenario.get("observed_decision"),
            scenario.get("reason_code"),
            scenario.get("security_verdict"),
            scenario.get("firmware_version_before"),
            scenario.get("firmware_version_after"),
        )
        require(actual == fields, f"{role} transition did not match the Phase 4 contract")
    require(
        value.get("untrusted_envelope_sha256") == value.get("untrusted_request_body_sha256"),
        "envelope and request hashes differed",
    )
    if expected_digest is not None:
        require(value.get("bundle_manifest_sha256") == expected_digest, "demo digest changed")
    assert_no_absolute_path(value, "presentation response")


def test_security_headers(response: httpx.Response, report: bool = False) -> None:
    headers = response.headers
    csp = headers.get("content-security-policy", "")
    if report:
        require("style-src 'unsafe-inline'" in csp, "report CSP did not allow its inline CSS")
        require("script-src" not in csp and "<script" not in response.text.lower(), "report permitted script")
    else:
        require("script-src 'self'" in csp, "dashboard CSP did not restrict script to self")
        require("script-src 'unsafe-inline'" not in csp, "dashboard CSP allowed inline script")
    expected = {
        "x-content-type-options": "nosniff",
        "x-frame-options": "DENY",
        "referrer-policy": "no-referrer",
        "cross-origin-opener-policy": "same-origin",
        "cache-control": "no-store",
    }
    for name, value in expected.items():
        require(headers.get(name) == value, f"security header {name} was incorrect")
    require("camera=()" in headers.get("permissions-policy", ""), "permissions policy was incomplete")


def run_http_contract(client: httpx.Client, base_url: str) -> None:
    root = client.get(f"{base_url}/")
    require(root.status_code == 200, "root page did not return HTTP 200")
    require(root.headers.get("content-type", "").startswith("text/html"), "root page content type was wrong")
    require("Prove the patch. Preserve the feature." in root.text, "hero heading was missing")
    test_security_headers(root)

    css = client.get(f"{base_url}/static/styles.css")
    script = client.get(f"{base_url}/static/app.js")
    require(css.status_code == 200 and "text/css" in css.headers.get("content-type", ""), "CSS was unavailable")
    require(script.status_code == 200 and "javascript" in script.headers.get("content-type", ""), "JavaScript was unavailable")
    test_security_headers(css)
    test_security_headers(script)

    demo_response = client.get(f"{base_url}/api/v1/demo")
    require(demo_response.status_code == 200, "demo API did not return HTTP 200")
    demo = parse_json(demo_response, "demo API")
    validate_presentation(demo, EXPECTED_DEMO_DIGEST)
    require(demo.get("source") == "DEMO", "demo source marker was incorrect")

    start = client.post(
        f"{base_url}/api/v1/verifications",
        json={},
        headers={"X-FixRepro-Action": "run-verification"},
    )
    require(start.status_code == 202, f"live verification start returned HTTP {start.status_code}")
    start_body = parse_json(start, "verification start")
    job_id = start_body.get("job_id")
    status_url = start_body.get("status_url")
    require(isinstance(job_id, str) and job_id.startswith("JOB-"), "job ID was invalid")
    require(isinstance(status_url, str) and status_url.startswith("/api/v1/verifications/JOB-"), "status URL was invalid")

    deadline = time.monotonic() + JOB_TIMEOUT_SECONDS
    job: dict[str, Any] = {}
    while time.monotonic() < deadline:
        response = client.get(f"{base_url}{status_url}")
        require(response.status_code == 200, "job status request failed")
        job = parse_json(response, "job status")
        if job.get("status") in {"COMPLETED", "FAILED"}:
            break
        require(job.get("status") in {"QUEUED", "RUNNING"}, "job returned an unknown status")
        time.sleep(0.25)
    require(job.get("status") == "COMPLETED", f"live job did not complete: {job.get('error')}")
    live = job.get("result")
    require(isinstance(live, dict), "completed job had no result")
    validate_presentation(live)
    require(live.get("source") == "LIVE", "live source marker was incorrect")
    assert_no_absolute_path(job, "job response")

    links = live.get("links")
    require(isinstance(links, dict), "live result had no artifact links")
    expected_types = {
        "report": "text/html",
        "evidence": "application/json",
        "manifest": "application/json",
        "digest": "text/plain",
    }
    for name, expected_type in expected_types.items():
        path = links.get(name)
        require(isinstance(path, str) and path.startswith("/api/v1/bundles/"), f"{name} link was invalid")
        artifact = client.get(f"{base_url}{path}")
        require(artifact.status_code == 200, f"{name} artifact was unavailable")
        require(artifact.headers.get("content-type", "").startswith(expected_type), f"{name} content type was wrong")
        if name == "report":
            test_security_headers(artifact, report=True)
        if name in {"evidence", "manifest"}:
            assert_no_absolute_path(parse_json(artifact, name), f"{name} artifact")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--base-url", type=validate_base_url, default=f"http://{LOOPBACK_HOST}:{DASHBOARD_PORT}")
    parser.add_argument("--external-server", action="store_true")
    args = parser.parse_args()

    process: subprocess.Popen[str] | None = None
    log_handle = None
    log_path = ROOT / ".runtime" / "logs" / "phase4-dashboard.log"
    failure: Exception | None = None
    try:
        if not args.external_server:
            require(not port_accepts_connections(DASHBOARD_PORT), "dashboard port is occupied; no process was terminated")
            log_path.parent.mkdir(parents=True, exist_ok=True)
            log_handle = log_path.open("w", encoding="utf-8", newline="\n")
            process = subprocess.Popen(
                [
                    sys.executable,
                    "scripts/run_dashboard.py",
                    "--host",
                    LOOPBACK_HOST,
                    "--port",
                    str(DASHBOARD_PORT),
                ],
                cwd=ROOT,
                env=os.environ.copy(),
                stdout=log_handle,
                stderr=subprocess.STDOUT,
                text=True,
                shell=False,
            )
        with httpx.Client(
            timeout=REQUEST_TIMEOUT_SECONDS,
            follow_redirects=False,
            trust_env=False,
        ) as client:
            wait_for_health(client, args.base_url, process)
            run_http_contract(client, args.base_url)
    except (OSError, httpx.RequestError, SmokeFailure) as exc:
        failure = exc
    finally:
        if process is not None and process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=20)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=5)
        if log_handle is not None:
            log_handle.close()

    ports_to_check = CHILD_PORTS if args.external_server else ALL_PORTS
    occupied = wait_for_ports_closed(ports_to_check)
    if occupied and failure is None:
        failure = SmokeFailure("cleanup left occupied loopback ports: " + ", ".join(map(str, occupied)))
    if failure is not None:
        print(f"PHASE4_DASHBOARD_FAIL={failure}", file=sys.stderr)
        if not args.external_server:
            print(f"DASHBOARD_LOG={log_path}", file=sys.stderr)
        return 1
    print("PHASE4_DASHBOARD_PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
