"""Explicit-timeout HTTP client for the loopback virtual device."""

from __future__ import annotations

import httpx

from .config import require_local_device_url
from .models import DeviceApplyRequest, DeviceState


REQUEST_TIMEOUT_SECONDS = 3.0


class DeviceUnavailable(RuntimeError):
    pass


class DeviceApplyFailed(RuntimeError):
    pass


async def get_device_state(device_url: str) -> DeviceState:
    base_url = require_local_device_url(device_url)
    try:
        async with httpx.AsyncClient(timeout=REQUEST_TIMEOUT_SECONDS) as client:
            response = await client.get(f"{base_url}/api/v1/state")
    except httpx.RequestError as exc:
        raise DeviceUnavailable("virtual device state endpoint is unavailable") from exc
    if response.status_code != 200:
        raise DeviceUnavailable(f"virtual device state returned HTTP {response.status_code}")
    try:
        return DeviceState.model_validate(response.json())
    except (ValueError, TypeError) as exc:
        raise DeviceUnavailable("virtual device returned an invalid state document") from exc


async def apply_device_update(
    device_url: str,
    firmware_version: str,
    payload_sha256: str,
) -> DeviceState:
    base_url = require_local_device_url(device_url)
    request = DeviceApplyRequest(
        firmware_version=firmware_version,
        payload_sha256=payload_sha256,
    )
    try:
        async with httpx.AsyncClient(timeout=REQUEST_TIMEOUT_SECONDS) as client:
            response = await client.post(
                f"{base_url}/api/v1/apply",
                json=request.model_dump(mode="json"),
            )
    except httpx.RequestError as exc:
        raise DeviceUnavailable("virtual device apply endpoint is unavailable") from exc
    if response.status_code != 200:
        raise DeviceApplyFailed(f"virtual device apply returned HTTP {response.status_code}")
    try:
        return DeviceState.model_validate(response.json())
    except (ValueError, TypeError) as exc:
        raise DeviceApplyFailed("virtual device returned an invalid apply response") from exc
