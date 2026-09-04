#!/usr/bin/env python3
"""Run the three-scenario Phase 2 contract against local child services."""

from __future__ import annotations

import argparse
import hashlib
import os
import socket
import subprocess
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import httpx

from fixrepro_core.artifacts import GeneratedArtifacts, generate_demo_artifacts
from fixrepro_core.config import (
    DEFAULT_DEVICE_URL,
    DEVICE_PORT,
    LOOPBACK_HOST,
    PATCHED_GATEWAY_PORT,
    VULNERABLE_GATEWAY_PORT,
)
from fixrepro_core.package import parse_package_bytes


ROOT = Path(__file__).resolve().parents[1]
REQUEST_TIMEOUT_SECONDS = 3.0
HEALTH_TIMEOUT_SECONDS = 15.0
PORTS = (VULNERABLE_GATEWAY_PORT, PATCHED_GATEWAY_PORT, DEVICE_PORT)


@dataclass
class ServiceProcess:
    name: str
    port: int
    process: subprocess.Popen[str]
    log_path: Path
    log_handle: Any


@dataclass(frozen=True)
class ScenarioExpectation:
    label: str
    gateway_role: str
    port: int
    status: int
    decision: str
    reason_code: str
    before_version: str
    after_version: str
    after_counter: int


class DemoFailure(RuntimeError):
    def __init__(self, assertion: str, response: Any | None = None) -> None:
        super().__init__(assertion)
        self.assertion = assertion
        self.response = response


def port_accepts_connections(port: int) -> bool:
    """Return whether a TCP listener is accepting connections on loopback."""

    probe = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    probe.settimeout(0.25)
    try:
        return probe.connect_ex((LOOPBACK_HOST, port)) == 0
    finally:
        probe.close()


def assert_ports_available() -> None:
    occupied = [port for port in PORTS if port_accepts_connections(port)]
    if occupied:
        joined = ", ".join(str(port) for port in occupied)
        raise DemoFailure(
            f"required loopback port(s) already occupied: {joined}; no process was terminated"
        )


def wait_for_ports_closed(timeout_seconds: float = 5.0) -> list[int]:
    """Allow graceful server shutdown, then return any ports still listening."""

    deadline = time.monotonic() + timeout_seconds
    while True:
        occupied = [port for port in PORTS if port_accepts_connections(port)]
        if not occupied or time.monotonic() >= deadline:
            return occupied
        time.sleep(0.1)


def start_service(
    name: str,
    module: str,
    port: int,
    logs_dir: Path,
    environment: dict[str, str],
) -> ServiceProcess:
    log_path = logs_dir / f"{name}.log"
    log_handle = log_path.open("w", encoding="utf-8", newline="\n")
    command = [
        sys.executable,
        "-m",
        "uvicorn",
        module,
        "--host",
        LOOPBACK_HOST,
        "--port",
        str(port),
        "--no-access-log",
    ]
    try:
        process = subprocess.Popen(
            command,
            cwd=ROOT,
            env=environment,
            stdout=log_handle,
            stderr=subprocess.STDOUT,
            text=True,
            shell=False,
        )
    except OSError:
        log_handle.close()
        raise
    return ServiceProcess(name, port, process, log_path, log_handle)


def wait_for_health(service: ServiceProcess) -> None:
    deadline = time.monotonic() + HEALTH_TIMEOUT_SECONDS
    url = f"http://{LOOPBACK_HOST}:{service.port}/health"
    last_error = "no response"
    with httpx.Client(timeout=1.0) as client:
        while time.monotonic() < deadline:
            return_code = service.process.poll()
            if return_code is not None:
                raise DemoFailure(
                    f"{service.name} exited before health check with code {return_code}"
                )
            try:
                response = client.get(url)
                if response.status_code == 200:
                    return
                last_error = f"HTTP {response.status_code}: {response.text[:300]}"
            except httpx.RequestError as exc:
                last_error = str(exc)
            time.sleep(0.15)
    raise DemoFailure(f"{service.name} did not become healthy: {last_error}")


def stop_services(services: list[ServiceProcess]) -> None:
    for service in reversed(services):
        if service.process.poll() is None:
            service.process.terminate()
    for service in reversed(services):
        try:
            service.process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            service.process.kill()
            service.process.wait(timeout=5)
        finally:
            service.log_handle.close()


def assert_services_running(services: list[ServiceProcess]) -> None:
    for service in services:
        return_code = service.process.poll()
        if return_code is not None:
            raise DemoFailure(f"{service.name} exited unexpectedly with code {return_code}")


def expect(label: str, actual: Any, expected: Any, response: Any | None = None) -> None:
    if actual != expected:
        raise DemoFailure(
            f"{label}: expected {expected!r}, found {actual!r}",
            response=response,
        )


def reset_device(client: httpx.Client, repetition: int, scenario: str) -> dict[str, Any]:
    try:
        response = client.post(f"{DEFAULT_DEVICE_URL}/api/v1/reset")
    except httpx.RequestError as exc:
        raise DemoFailure(f"repetition {repetition} {scenario} reset request failed: {exc}") from exc
    try:
        body = response.json()
    except ValueError as exc:
        raise DemoFailure(
            f"repetition {repetition} {scenario} reset response was not JSON",
            response=response.text[:500],
        ) from exc
    expect(f"repetition {repetition} {scenario} reset HTTP status", response.status_code, 200, body)
    expected = {
        "firmware_version": "1.0.0",
        "update_counter": 0,
        "last_payload_sha256": None,
    }
    expect(f"repetition {repetition} {scenario} reset state", body, expected, body)
    return body


def submit_package(
    client: httpx.Client,
    package_bytes: bytes,
    expectation: ScenarioExpectation,
    package_id: str,
    firmware_version: str,
    payload_sha256: str,
    signer_fingerprint: str,
    repetition: int,
) -> dict[str, Any]:
    url = f"http://{LOOPBACK_HOST}:{expectation.port}/api/v1/updates"
    try:
        response = client.post(
            url,
            content=package_bytes,
            headers={"content-type": "application/json"},
        )
    except httpx.RequestError as exc:
        raise DemoFailure(
            f"repetition {repetition} {expectation.label} gateway request failed: {exc}"
        ) from exc
    try:
        body = response.json()
    except ValueError as exc:
        raise DemoFailure(
            f"repetition {repetition} {expectation.label} response was not JSON",
            response=response.text[:500],
        ) from exc

    prefix = f"repetition {repetition} {expectation.label}"
    expect(f"{prefix} HTTP status", response.status_code, expectation.status, body)
    expected_fields = {
        "gateway_role": expectation.gateway_role,
        "decision": expectation.decision,
        "reason_code": expectation.reason_code,
        "package_id": package_id,
        "firmware_version": firmware_version,
        "payload_sha256": payload_sha256,
        "signer_fingerprint": signer_fingerprint,
    }
    for field, expected in expected_fields.items():
        expect(f"{prefix} {field}", body.get(field), expected, body)

    expected_before = {
        "firmware_version": expectation.before_version,
        "update_counter": 0,
        "last_payload_sha256": None,
    }
    expect(f"{prefix} device_state_before", body.get("device_state_before"), expected_before, body)
    expected_after = {
        "firmware_version": expectation.after_version,
        "update_counter": expectation.after_counter,
        "last_payload_sha256": payload_sha256 if expectation.after_counter else None,
    }
    expect(f"{prefix} device_state_after", body.get("device_state_after"), expected_after, body)
    return body


def print_table(rows: list[tuple[int, ScenarioExpectation]]) -> None:
    headers = ("Run", "Scenario", "Gateway", "HTTP", "Decision", "Reason", "Before", "After")
    values = [
        (
            str(repetition),
            item.label,
            item.gateway_role,
            str(item.status),
            item.decision,
            item.reason_code,
            item.before_version,
            item.after_version,
        )
        for repetition, item in rows
    ]
    widths = [max(len(headers[i]), *(len(row[i]) for row in values)) for i in range(len(headers))]
    print("  ".join(headers[i].ljust(widths[i]) for i in range(len(headers))))
    print("  ".join("-" * width for width in widths))
    for row in values:
        print("  ".join(row[i].ljust(widths[i]) for i in range(len(headers))))


def run_demo(repeat: int) -> int:
    artifacts: GeneratedArtifacts | None = None
    services: list[ServiceProcess] = []
    table_rows: list[tuple[int, ScenarioExpectation]] = []
    failure: DemoFailure | None = None
    package_file_sha256 = ""

    scenarios = (
        ScenarioExpectation(
            "A",
            "VULNERABLE",
            VULNERABLE_GATEWAY_PORT,
            200,
            "ACCEPTED",
            "CHECKSUM_ONLY_ACCEPTED",
            "1.0.0",
            "9.9.0-test",
            1,
        ),
        ScenarioExpectation(
            "B",
            "PATCHED",
            PATCHED_GATEWAY_PORT,
            403,
            "REJECTED",
            "UNTRUSTED_SIGNER",
            "1.0.0",
            "1.0.0",
            0,
        ),
        ScenarioExpectation(
            "C",
            "PATCHED",
            PATCHED_GATEWAY_PORT,
            200,
            "ACCEPTED",
            "TRUSTED_SIGNATURE_ACCEPTED",
            "1.0.0",
            "1.1.0",
            1,
        ),
    )

    try:
        assert_ports_available()
        artifacts = generate_demo_artifacts(ROOT / ".runtime")
        untrusted_package_bytes = artifacts.untrusted_package_path.read_bytes()
        trusted_package_bytes = artifacts.trusted_package_path.read_bytes()
        package_file_sha256 = hashlib.sha256(untrusted_package_bytes).hexdigest()
        untrusted = parse_package_bytes(untrusted_package_bytes)
        trusted = parse_package_bytes(trusted_package_bytes)
        print(f"Untrusted package file SHA-256: {package_file_sha256}")

        environment = os.environ.copy()
        environment["FIXREPRO_DEVICE_URL"] = DEFAULT_DEVICE_URL
        environment["FIXREPRO_TRUSTED_PUBLIC_KEY"] = str(artifacts.trusted_public_key_path)

        service_specs = (
            ("device", "device.app:app", DEVICE_PORT),
            ("vulnerable-gateway", "targets.vulnerable.app:app", VULNERABLE_GATEWAY_PORT),
            ("patched-gateway", "targets.patched.app:app", PATCHED_GATEWAY_PORT),
        )
        for name, module, port in service_specs:
            service = start_service(name, module, port, artifacts.logs_dir, environment)
            services.append(service)
            wait_for_health(service)

        with httpx.Client(timeout=REQUEST_TIMEOUT_SECONDS) as client:
            for repetition in range(1, repeat + 1):
                assert_services_running(services)
                for scenario in scenarios:
                    reset_device(client, repetition, scenario.label)
                    if scenario.label in {"A", "B"}:
                        package_bytes = untrusted_package_bytes
                        package = untrusted
                    else:
                        package_bytes = trusted_package_bytes
                        package = trusted
                    submit_package(
                        client=client,
                        package_bytes=package_bytes,
                        expectation=scenario,
                        package_id=package.manifest.package_id,
                        firmware_version=package.manifest.firmware_version,
                        payload_sha256=package.manifest.payload_sha256,
                        signer_fingerprint=package.signer_fingerprint,
                        repetition=repetition,
                    )
                    table_rows.append((repetition, scenario))
                assert_services_running(services)
    except DemoFailure as exc:
        failure = exc
    except OSError as exc:
        failure = DemoFailure(f"local runtime operation failed: {exc}")
    finally:
        stop_services(services)

    occupied_after = wait_for_ports_closed()
    if occupied_after and failure is None:
        failure = DemoFailure(
            "service cleanup left occupied port(s): " + ", ".join(map(str, occupied_after))
        )

    if failure is not None:
        print(f"FAILED ASSERTION: {failure.assertion}", file=sys.stderr)
        if failure.response is not None:
            print(f"RELEVANT RESPONSE: {failure.response}", file=sys.stderr)
        logs_dir = artifacts.logs_dir if artifacts else ROOT / ".runtime" / "logs"
        print(f"SERVICE LOGS: {logs_dir}", file=sys.stderr)
        return 1

    print_table(table_rows)
    print(f"Successful repetitions: {repeat}")
    print("PHASE2_CONTRACT_PASS")
    return 0


def positive_repeat(value: str) -> int:
    parsed = int(value)
    if parsed < 1:
        raise argparse.ArgumentTypeError("repeat must be at least 1")
    return parsed


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repeat", type=positive_repeat, default=1)
    args = parser.parse_args()
    return run_demo(args.repeat)


if __name__ == "__main__":
    raise SystemExit(main())
