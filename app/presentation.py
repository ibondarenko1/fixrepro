"""Verified evidence-to-dashboard presentation mapping."""

from __future__ import annotations

import threading
from pathlib import Path

from pydantic import ValidationError

from verifier.bundle import BundleVerificationResult, verify_bundle
from verifier.models import EvidenceDocument, ExecutionRole, VerificationOutcome

from .models import (
    ArtifactLinks,
    BundlePresentation,
    PresentationSource,
    ScenarioPresentation,
)


VISIBLE_LABELS = {
    ExecutionRole.VULNERABLE: "UNSAFE BEHAVIOR REPRODUCED",
    ExecutionRole.PATCHED: "PATCH BLOCKED SAME INPUT",
    ExecutionRole.POSITIVE_CONTROL: "LEGITIMATE UPDATE PRESERVED",
}
SAFETY_SCOPE = (
    "Controlled synthetic IoT OTA verification on localhost using harmless test "
    "firmware and in-memory signing identities."
)
LIMITATION = (
    "FixRepro proves only that the defined signer-trust regression behaved as "
    "recorded under the tested conditions. It does not prove that every "
    "vulnerability is fixed or that a build is generally secure."
)


class PresentationError(RuntimeError):
    """A known bundle cannot be safely presented."""


class BundleNotFoundError(PresentationError):
    """The requested bundle ID is not registered."""


class BundleIntegrityError(PresentationError):
    """The requested bundle failed independent verification."""


class BundleRegistry:
    """Thread-safe map from opaque public IDs to known bundle directories."""

    def __init__(self, repository_root: Path) -> None:
        self.repository_root = repository_root.resolve()
        self._lock = threading.RLock()
        self._bundles: dict[str, Path] = {
            "demo": self.repository_root / "evidence" / "demo-bundle"
        }

    def register_live(self, bundle_id: str, bundle_path: Path) -> None:
        if not bundle_id.startswith("JOB-"):
            raise ValueError("live bundle IDs must use the JOB prefix")
        if bundle_path.is_symlink():
            raise ValueError("live bundle must not be a symlink")
        resolved = bundle_path.resolve()
        evidence_root = (self.repository_root / "evidence").resolve()
        if not resolved.is_relative_to(evidence_root) or resolved.is_symlink():
            raise ValueError("live bundle must be a non-symlink child of evidence")
        with self._lock:
            self._bundles[bundle_id] = resolved

    def resolve(self, bundle_id: str) -> Path:
        with self._lock:
            path = self._bundles.get(bundle_id)
        if path is None:
            raise BundleNotFoundError("bundle ID is not registered")
        return path


def verify_registered_bundle(
    repository_root: Path,
    registry: BundleRegistry,
    bundle_id: str,
) -> tuple[Path, BundleVerificationResult]:
    bundle_path = registry.resolve(bundle_id)
    if bundle_path.is_symlink():
        raise BundleIntegrityError("bundle directory is a symlink")
    verification = verify_bundle(
        bundle_path,
        repository_root,
        repository_root / "schemas" / "evidence.schema.json",
    )
    if not verification.valid or verification.verification_outcome is None:
        raise BundleIntegrityError("bundle failed independent verification")
    if verification.manifest_sha256 is None:
        raise BundleIntegrityError("bundle manifest digest is unavailable")
    return bundle_path, verification


def present_bundle(
    repository_root: Path,
    registry: BundleRegistry,
    bundle_id: str,
    source: PresentationSource,
) -> BundlePresentation:
    bundle_path, verification = verify_registered_bundle(
        repository_root,
        registry,
        bundle_id,
    )
    evidence_path = bundle_path / "evidence.json"
    if evidence_path.is_symlink():
        raise BundleIntegrityError("evidence document is a symlink")
    try:
        evidence = EvidenceDocument.model_validate_json(evidence_path.read_bytes())
    except (OSError, ValidationError) as exc:
        raise BundleIntegrityError("evidence document failed strict parsing") from exc

    by_role = {execution.role: execution for execution in evidence.executions}
    if set(by_role) != set(ExecutionRole) or len(evidence.executions) != 3:
        raise BundleIntegrityError("bundle does not contain exactly one execution per role")
    vulnerable = by_role[ExecutionRole.VULNERABLE]
    patched = by_role[ExecutionRole.PATCHED]
    same_input = (
        vulnerable.package.envelope_sha256 == patched.package.envelope_sha256
        and vulnerable.request.body_sha256 == patched.request.body_sha256
    )
    if evidence.verification_outcome == VerificationOutcome.PATCH_VERIFIED and not same_input:
        raise BundleIntegrityError("verified outcome does not preserve exact same input")
    if verification.verification_outcome != evidence.verification_outcome:
        raise BundleIntegrityError("stored and independently computed outcomes differ")

    scenarios = [
        ScenarioPresentation(
            role=role,
            visible_label=VISIBLE_LABELS[role],
            build_id=execution.build_id,
            http_status=execution.response.http_status,
            observed_decision=execution.observed_decision.value,
            reason_code=execution.response.reason_code,
            security_verdict=execution.security_verdict,
            firmware_version_before=execution.device_state_before.firmware_version,
            firmware_version_after=execution.device_state_after.firmware_version,
            update_counter_before=execution.device_state_before.update_counter,
            update_counter_after=execution.device_state_after.update_counter,
        )
        for role, execution in (
            (ExecutionRole.VULNERABLE, by_role[ExecutionRole.VULNERABLE]),
            (ExecutionRole.PATCHED, by_role[ExecutionRole.PATCHED]),
            (ExecutionRole.POSITIVE_CONTROL, by_role[ExecutionRole.POSITIVE_CONTROL]),
        )
    ]
    link_root = f"/api/v1/bundles/{bundle_id}"
    return BundlePresentation(
        source=source,
        bundle_id=bundle_id,
        verification_id=evidence.verification_id,
        verification_outcome=evidence.verification_outcome,
        created_at=evidence.created_at,
        security_property=evidence.test_case.security_property,
        same_input_verified=same_input,
        untrusted_envelope_sha256=vulnerable.package.envelope_sha256,
        untrusted_request_body_sha256=vulnerable.request.body_sha256,
        bundle_manifest_sha256=verification.manifest_sha256,
        manifest_entry_count=verification.manifest_entry_count,
        scenarios=scenarios,
        links=ArtifactLinks(
            report=f"{link_root}/report",
            evidence=f"{link_root}/evidence",
            manifest=f"{link_root}/manifest",
            digest=f"{link_root}/digest",
        ),
        safety_scope=SAFETY_SCOPE,
        limitation=LIMITATION,
    )
