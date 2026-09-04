"""Shared gateway orchestration kept separate from FastAPI routing."""

from __future__ import annotations

from collections.abc import Callable

from .device_client import DeviceApplyFailed, DeviceUnavailable, apply_device_update, get_device_state
from .evaluation import Decision, GatewayRole, PolicyResult, ReasonCode, http_status_for
from .models import GatewayResponse


Policy = Callable[[bytes], PolicyResult]


def _response(
    role: GatewayRole,
    result: PolicyResult,
    before: dict[str, object],
    after: dict[str, object],
) -> GatewayResponse:
    return GatewayResponse(
        gateway_role=role.value,
        decision=result.decision.value,
        reason_code=result.reason_code.value,
        package_id=result.package_id,
        firmware_version=result.firmware_version,
        payload_sha256=result.payload_sha256,
        signer_fingerprint=result.signer_fingerprint,
        device_state_before=before,
        device_state_after=after,
    )


async def process_gateway_update(
    raw_package: bytes,
    role: GatewayRole,
    device_url: str,
    policy: Policy,
) -> tuple[int, GatewayResponse]:
    try:
        state_before = await get_device_state(device_url)
    except DeviceUnavailable:
        result = PolicyResult(Decision.ERROR, ReasonCode.DEVICE_UNAVAILABLE)
        return http_status_for(result), _response(role, result, {}, {})

    before = state_before.model_dump(mode="json")
    result = policy(raw_package)
    if result.decision != Decision.ACCEPTED:
        return http_status_for(result), _response(role, result, before, before)

    try:
        state_after = await apply_device_update(
            device_url,
            result.firmware_version,
            result.payload_sha256,
        )
    except DeviceUnavailable:
        error = PolicyResult(
            Decision.ERROR,
            ReasonCode.DEVICE_UNAVAILABLE,
            result.package_id,
            result.firmware_version,
            result.payload_sha256,
            result.signer_fingerprint,
        )
        return http_status_for(error), _response(role, error, before, before)
    except DeviceApplyFailed:
        error = PolicyResult(
            Decision.ERROR,
            ReasonCode.DEVICE_APPLY_FAILED,
            result.package_id,
            result.firmware_version,
            result.payload_sha256,
            result.signer_fingerprint,
        )
        return http_status_for(error), _response(role, error, before, before)

    after = state_after.model_dump(mode="json")
    return http_status_for(result), _response(role, result, before, after)
