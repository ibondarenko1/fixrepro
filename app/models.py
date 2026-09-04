"""Strict public models for the FixRepro dashboard API."""

from __future__ import annotations

from enum import StrEnum
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

from verifier.models import ExecutionRole, SecurityVerdict, VerificationOutcome


SHA256_PATTERN = r"^[a-f0-9]{64}$"
JOB_ID_PATTERN = r"^JOB-[a-f0-9]{8}$"
UTC_PATTERN = r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$"


class StrictAppModel(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)


class PresentationSource(StrEnum):
    DEMO = "DEMO"
    LIVE = "LIVE"


class JobStatus(StrEnum):
    QUEUED = "QUEUED"
    RUNNING = "RUNNING"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"


class HealthResponse(StrictAppModel):
    status: Literal["ok"] = "ok"
    service: Literal["fixrepro-dashboard"] = "fixrepro-dashboard"
    version: Literal["0.4.0"] = "0.4.0"


class ScenarioPresentation(StrictAppModel):
    role: ExecutionRole
    visible_label: str = Field(min_length=1, max_length=80)
    build_id: str = Field(min_length=1, max_length=128)
    http_status: int = Field(ge=100, le=599)
    observed_decision: str = Field(min_length=1, max_length=32)
    reason_code: str = Field(min_length=1, max_length=128)
    security_verdict: SecurityVerdict
    firmware_version_before: str = Field(min_length=1, max_length=64)
    firmware_version_after: str = Field(min_length=1, max_length=64)
    update_counter_before: int = Field(ge=0)
    update_counter_after: int = Field(ge=0)


class ArtifactLinks(StrictAppModel):
    report: str = Field(pattern=r"^/api/v1/bundles/[A-Za-z0-9-]+/report$")
    evidence: str = Field(pattern=r"^/api/v1/bundles/[A-Za-z0-9-]+/evidence$")
    manifest: str = Field(pattern=r"^/api/v1/bundles/[A-Za-z0-9-]+/manifest$")
    digest: str = Field(pattern=r"^/api/v1/bundles/[A-Za-z0-9-]+/digest$")


class BundlePresentation(StrictAppModel):
    source: PresentationSource
    bundle_id: str = Field(pattern=r"^(demo|JOB-[a-f0-9]{8})$")
    verification_id: str = Field(min_length=1, max_length=128)
    verification_outcome: VerificationOutcome
    created_at: str = Field(pattern=UTC_PATTERN)
    security_property: str = Field(min_length=1, max_length=500)
    same_input_verified: bool
    untrusted_envelope_sha256: str = Field(pattern=SHA256_PATTERN)
    untrusted_request_body_sha256: str = Field(pattern=SHA256_PATTERN)
    bundle_manifest_sha256: str = Field(pattern=SHA256_PATTERN)
    manifest_entry_count: int = Field(ge=1)
    scenarios: list[ScenarioPresentation] = Field(min_length=3, max_length=3)
    links: ArtifactLinks
    safety_scope: str = Field(min_length=1, max_length=500)
    limitation: str = Field(min_length=1, max_length=500)


class StartVerificationRequest(StrictAppModel):
    pass


class StartVerificationResponse(StrictAppModel):
    job_id: str = Field(pattern=JOB_ID_PATTERN)
    status: Literal[JobStatus.RUNNING]
    status_url: str = Field(pattern=r"^/api/v1/verifications/JOB-[a-f0-9]{8}$")


class PublicJobError(StrictAppModel):
    code: str = Field(min_length=1, max_length=80)
    message: str = Field(min_length=1, max_length=200)


class JobStatusResponse(StrictAppModel):
    job_id: str = Field(pattern=JOB_ID_PATTERN)
    status: JobStatus
    created_at: str = Field(pattern=UTC_PATTERN)
    started_at: str | None = Field(default=None, pattern=UTC_PATTERN)
    finished_at: str | None = Field(default=None, pattern=UTC_PATTERN)
    result: BundlePresentation | None = None
    error: PublicJobError | None = None


class ErrorDetail(StrictAppModel):
    code: str = Field(min_length=1, max_length=80)
    message: str = Field(min_length=1, max_length=200)


class ErrorResponse(StrictAppModel):
    error: ErrorDetail
