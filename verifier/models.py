"""Strict Phase 3 evidence, observation, and manifest models."""

from __future__ import annotations

from enum import StrEnum
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator


SHA256_PATTERN = r"^[a-f0-9]{64}$"
UTC_PATTERN = r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$"
VERIFICATION_ID_PATTERN = r"^FR-\d{8}T\d{9}Z-[a-f0-9]{8}$"
EXECUTION_ID_PATTERN = (
    r"^EX-(VULNERABLE|PATCHED|POSITIVE_CONTROL)-[a-f0-9]{8}$"
)


class ExecutionRole(StrEnum):
    VULNERABLE = "VULNERABLE"
    PATCHED = "PATCHED"
    POSITIVE_CONTROL = "POSITIVE_CONTROL"


class ObservedDecision(StrEnum):
    ACCEPTED = "ACCEPTED"
    REJECTED = "REJECTED"
    ERROR = "ERROR"


class SecurityVerdict(StrEnum):
    PASS = "PASS"
    FAIL = "FAIL"
    INCONCLUSIVE = "INCONCLUSIVE"


class VerificationOutcome(StrEnum):
    PATCH_VERIFIED = "PATCH_VERIFIED"
    PATCH_NOT_VERIFIED = "PATCH_NOT_VERIFIED"
    INCONCLUSIVE = "INCONCLUSIVE"


class SignerTrust(StrEnum):
    TRUSTED = "TRUSTED"
    UNTRUSTED = "UNTRUSTED"


class StrictEvidenceModel(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)


class TestCaseEvidence(StrictEvidenceModel):
    case_id: str = Field(min_length=1, max_length=128)
    title: str = Field(min_length=1, max_length=240)
    security_property: str = Field(min_length=1, max_length=500)
    positive_control_case_id: str = Field(min_length=1, max_length=128)


class PackageEvidence(StrictEvidenceModel):
    filename: str = Field(min_length=1, max_length=255)
    sha256: str = Field(pattern=SHA256_PATTERN)
    envelope_sha256: str = Field(pattern=SHA256_PATTERN)
    signer_fingerprint: str = Field(pattern=SHA256_PATTERN)
    signer_trust: SignerTrust


class RequestEvidence(StrictEvidenceModel):
    method: Literal["POST"]
    path: Literal["/api/v1/updates"]
    content_type: Literal["application/json"]
    body_sha256: str = Field(pattern=SHA256_PATTERN)


class ResponseEvidence(StrictEvidenceModel):
    http_status: int = Field(ge=100, le=599)
    decision: ObservedDecision
    reason_code: str = Field(min_length=1, max_length=128)
    body_sha256: str = Field(pattern=SHA256_PATTERN)


class DeviceStateEvidence(StrictEvidenceModel):
    firmware_version: str = Field(min_length=1, max_length=64)
    update_counter: int = Field(ge=0)
    last_payload_sha256: str | None = Field(default=None, pattern=SHA256_PATTERN)


class ArtifactRecord(StrictEvidenceModel):
    path: str = Field(min_length=1, max_length=500)
    sha256: str = Field(pattern=SHA256_PATTERN)
    size_bytes: int = Field(ge=0)
    media_type: str = Field(min_length=1, max_length=128)


class ExecutionEvidence(StrictEvidenceModel):
    execution_id: str = Field(pattern=EXECUTION_ID_PATTERN)
    role: ExecutionRole
    build_id: str = Field(min_length=1, max_length=128)
    started_at: str = Field(pattern=UTC_PATTERN)
    finished_at: str = Field(pattern=UTC_PATTERN)
    package: PackageEvidence
    request: RequestEvidence
    response: ResponseEvidence
    device_state_before: DeviceStateEvidence
    device_state_after: DeviceStateEvidence
    secure_expected_decision: ObservedDecision
    observed_decision: ObservedDecision
    security_verdict: SecurityVerdict
    artifacts: list[ArtifactRecord] = Field(min_length=1)

    @model_validator(mode="after")
    def decisions_agree(self) -> "ExecutionEvidence":
        if self.observed_decision != self.response.decision:
            raise ValueError("observed_decision must equal response.decision")
        return self


class EvidenceDocument(StrictEvidenceModel):
    schema_version: Literal["1.1"]
    verification_id: str = Field(pattern=VERIFICATION_ID_PATTERN)
    created_at: str = Field(pattern=UTC_PATTERN)
    test_case: TestCaseEvidence
    executions: list[ExecutionEvidence] = Field(min_length=3, max_length=3)
    verification_outcome: VerificationOutcome
    bundle_files: list[ArtifactRecord] = Field(min_length=7, max_length=7)

    @model_validator(mode="after")
    def one_execution_per_role(self) -> "EvidenceDocument":
        roles = [execution.role for execution in self.executions]
        if len(set(roles)) != 3 or set(roles) != set(ExecutionRole):
            raise ValueError("exactly one execution is required for each role")
        return self


class RawScenarioRecord(StrictEvidenceModel):
    execution_id: str = Field(pattern=EXECUTION_ID_PATTERN)
    role: ExecutionRole
    started_at: str = Field(pattern=UTC_PATTERN)
    finished_at: str = Field(pattern=UTC_PATTERN)
    reset_confirmed: bool
    request: RequestEvidence
    gateway_response: dict[str, Any]
    device_state_before: DeviceStateEvidence
    device_state_after: DeviceStateEvidence


class ManifestEntry(StrictEvidenceModel):
    path: str = Field(min_length=1, max_length=500)
    sha256: str = Field(pattern=SHA256_PATTERN)
    size_bytes: int = Field(ge=0)


class BundleManifest(StrictEvidenceModel):
    schema_version: Literal["1.0.0"]
    files: list[ManifestEntry] = Field(min_length=1)

    @model_validator(mode="after")
    def paths_are_unique_and_sorted(self) -> "BundleManifest":
        paths = [entry.path for entry in self.files]
        if paths != sorted(paths):
            raise ValueError("manifest entries must be sorted by path")
        if len(paths) != len(set(paths)):
            raise ValueError("manifest paths must be unique")
        return self
