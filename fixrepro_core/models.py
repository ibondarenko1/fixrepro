"""Strict request, state, package, and gateway response models."""

from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field


SHA256_PATTERN = r"^[a-f0-9]{64}$"


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)


class Manifest(StrictModel):
    schema_version: Literal["1.0"]
    package_id: str = Field(min_length=1, max_length=128)
    firmware_version: str = Field(min_length=1, max_length=64)
    payload_sha256: str = Field(pattern=SHA256_PATTERN)
    payload_size: int = Field(gt=0)
    signature_algorithm: Literal["Ed25519"]


class PackageEnvelope(StrictModel):
    manifest: Manifest
    payload_b64: str = Field(min_length=1)
    signer_public_key_b64: str = Field(min_length=1)
    signer_fingerprint: str = Field(pattern=SHA256_PATTERN)
    signature_b64: str = Field(min_length=1)


class DeviceState(StrictModel):
    firmware_version: str = Field(min_length=1, max_length=64)
    update_counter: int = Field(ge=0)
    last_payload_sha256: str | None = Field(default=None, pattern=SHA256_PATTERN)


class DeviceApplyRequest(StrictModel):
    firmware_version: str = Field(min_length=1, max_length=64)
    payload_sha256: str = Field(pattern=SHA256_PATTERN)


class GatewayResponse(StrictModel):
    gateway_role: Literal["VULNERABLE", "PATCHED"]
    decision: Literal["ACCEPTED", "REJECTED", "ERROR"]
    reason_code: str
    package_id: str
    firmware_version: str
    payload_sha256: str
    signer_fingerprint: str
    device_state_before: dict[str, Any]
    device_state_after: dict[str, Any]
