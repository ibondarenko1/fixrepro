"""Lifecycle management for the three localhost verification services."""

from __future__ import annotations

import os
import socket
import subprocess
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import TextIO

import httpx

from fixrepro_core.config import (
    DEFAULT_DEVICE_URL,
    DEVICE_PORT,
    LOOPBACK_HOST,
    PATCHED_BUILD_ID,
    PATCHED_GATEWAY_PORT,
    VULNERABLE_BUILD_ID,
    VULNERABLE_GATEWAY_PORT,
)


HEALTH_TIMEOUT_SECONDS = 15.0
PORT_CLOSE_TIMEOUT_SECONDS = 5.0
PORTS = (VULNERABLE_GATEWAY_PORT, PATCHED_GATEWAY_PORT, DEVICE_PORT)


class ProcessError(RuntimeError):
    """A bounded local service lifecycle operation failed."""


@dataclass
class ServiceProcess:
    name: str
    port: int
    process: subprocess.Popen[str]
    log_path: Path
    log_handle: TextIO
    expected_build_id: str | None = None


def port_accepts_connections(port: int) -> bool:
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
        raise ProcessError(
            f"required localhost port(s) already occupied: {joined}; no process was terminated"
        )


def _start_service(
    repository_root: Path,
    logs_dir: Path,
    environment: dict[str, str],
    name: str,
    module: str,
    port: int,
    expected_build_id: str | None,
) -> ServiceProcess:
    log_path = logs_dir / f"phase3-{name}.log"
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
            cwd=repository_root,
            env=environment,
            stdout=log_handle,
            stderr=subprocess.STDOUT,
            text=True,
            shell=False,
        )
    except OSError as exc:
        log_handle.close()
        raise ProcessError(f"could not start {name}: {exc}") from exc
    return ServiceProcess(name, port, process, log_path, log_handle, expected_build_id)


def _wait_for_health(service: ServiceProcess) -> None:
    deadline = time.monotonic() + HEALTH_TIMEOUT_SECONDS
    url = f"http://{LOOPBACK_HOST}:{service.port}/health"
    last_error = "no response"
    with httpx.Client(timeout=1.0, follow_redirects=False, trust_env=False) as client:
        while time.monotonic() < deadline:
            return_code = service.process.poll()
            if return_code is not None:
                raise ProcessError(
                    f"{service.name} exited before its health check with code {return_code}"
                )
            try:
                response = client.get(url)
                body = response.json() if response.status_code == 200 else {}
                if not isinstance(body, dict):
                    raise ValueError("health response must be a JSON object")
                if response.status_code == 200 and body.get("status") == "ok":
                    if (
                        service.expected_build_id is not None
                        and body.get("build_id") != service.expected_build_id
                    ):
                        raise ProcessError(
                            f"{service.name} exposed an unexpected build identifier"
                        )
                    return
                last_error = f"HTTP {response.status_code}"
            except (httpx.RequestError, ValueError) as exc:
                last_error = str(exc)
            time.sleep(0.15)
    raise ProcessError(f"{service.name} did not become healthy: {last_error}")


def start_services(
    repository_root: Path,
    logs_dir: Path,
    trusted_public_key_path: Path,
) -> list[ServiceProcess]:
    """Start only the known lab children and return their process handles."""

    assert_ports_available()
    environment = os.environ.copy()
    environment["FIXREPRO_DEVICE_URL"] = DEFAULT_DEVICE_URL
    environment["FIXREPRO_TRUSTED_PUBLIC_KEY"] = str(trusted_public_key_path)
    specifications = (
        ("device", "device.app:app", DEVICE_PORT, None),
        (
            "vulnerable-gateway",
            "targets.vulnerable.app:app",
            VULNERABLE_GATEWAY_PORT,
            VULNERABLE_BUILD_ID,
        ),
        (
            "patched-gateway",
            "targets.patched.app:app",
            PATCHED_GATEWAY_PORT,
            PATCHED_BUILD_ID,
        ),
    )
    services: list[ServiceProcess] = []
    try:
        for name, module, port, build_id in specifications:
            service = _start_service(
                repository_root,
                logs_dir,
                environment,
                name,
                module,
                port,
                build_id,
            )
            services.append(service)
            _wait_for_health(service)
    except ProcessError:
        stop_services(services)
        raise
    return services


def assert_services_running(services: list[ServiceProcess]) -> None:
    for service in services:
        return_code = service.process.poll()
        if return_code is not None:
            raise ProcessError(f"{service.name} exited unexpectedly with code {return_code}")


def wait_for_ports_closed(timeout_seconds: float = PORT_CLOSE_TIMEOUT_SECONDS) -> list[int]:
    deadline = time.monotonic() + timeout_seconds
    while True:
        occupied = [port for port in PORTS if port_accepts_connections(port)]
        if not occupied or time.monotonic() >= deadline:
            return occupied
        time.sleep(0.1)


def stop_services(services: list[ServiceProcess]) -> None:
    """Stop only supplied child handles; never inspect or kill an unknown process."""

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

    occupied = wait_for_ports_closed()
    if occupied:
        joined = ", ".join(str(port) for port in occupied)
        raise ProcessError(f"verification child services left listening ports: {joined}")
