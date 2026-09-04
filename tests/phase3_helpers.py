from __future__ import annotations

import hashlib
from pathlib import Path

from fixrepro_core.artifacts import generate_demo_artifacts
from fixrepro_core.config import PATCHED_BUILD_ID, VULNERABLE_BUILD_ID
from fixrepro_core.package import parse_and_decode_package
from verifier.bundle import (
    artifact_record,
    atomic_write_bytes,
    atomic_write_json,
    atomic_write_text,
    write_manifest,
)
from verifier.evidence import write_evidence
from verifier.models import (
    DeviceStateEvidence,
    EvidenceDocument,
    ExecutionEvidence,
    ExecutionRole,
    ObservedDecision,
    PackageEvidence,
    RawScenarioRecord,
    RequestEvidence,
    ResponseEvidence,
    SecurityVerdict,
    SignerTrust,
    TestCaseEvidence,
)
from verifier.report import write_report
from verifier.verdicts import calculate_individual_verdict, calculate_verification_outcome


ROOT = Path(__file__).resolve().parents[1]
STAMP = "2026-09-04T03:00:00.000Z"
UNTRUSTED_PAYLOAD_HASH = "1" * 64
UNTRUSTED_ENVELOPE_HASH = "a" * 64
TRUSTED_PAYLOAD_HASH = "2" * 64
TRUSTED_ENVELOPE_HASH = "c" * 64


def state(
    version: str = "1.0.0",
    counter: int = 0,
    payload_sha256: str | None = None,
) -> DeviceStateEvidence:
    return DeviceStateEvidence(
        firmware_version=version,
        update_counter=counter,
        last_payload_sha256=payload_sha256,
    )


def make_execution(
    role: ExecutionRole,
    *,
    decision: ObservedDecision | None = None,
    http_status: int | None = None,
    reason_code: str | None = None,
    before: DeviceStateEvidence | None = None,
    after: DeviceStateEvidence | None = None,
    payload_sha256: str | None = None,
    envelope_sha256: str | None = None,
    body_sha256: str | None = None,
    artifact_path: str | None = None,
    artifact_sha256: str = "3" * 64,
    artifact_size: int = 2,
) -> ExecutionEvidence:
    untrusted = role != ExecutionRole.POSITIVE_CONTROL
    payload = payload_sha256 or (UNTRUSTED_PAYLOAD_HASH if untrusted else TRUSTED_PAYLOAD_HASH)
    envelope = envelope_sha256 or (
        UNTRUSTED_ENVELOPE_HASH if untrusted else TRUSTED_ENVELOPE_HASH
    )
    if role == ExecutionRole.VULNERABLE:
        observed = decision or ObservedDecision.ACCEPTED
        status = http_status or 200
        reason = reason_code or "CHECKSUM_ONLY_ACCEPTED"
        after_state = after or state("9.9.0-test", 1, payload)
        build_id = VULNERABLE_BUILD_ID
    elif role == ExecutionRole.PATCHED:
        observed = decision or ObservedDecision.REJECTED
        status = http_status or 403
        reason = reason_code or "UNTRUSTED_SIGNER"
        after_state = after or state()
        build_id = PATCHED_BUILD_ID
    else:
        observed = decision or ObservedDecision.ACCEPTED
        status = http_status or 200
        reason = reason_code or "TRUSTED_SIGNATURE_ACCEPTED"
        after_state = after or state("1.1.0", 1, payload)
        build_id = PATCHED_BUILD_ID
    raw_path = artifact_path or {
        ExecutionRole.VULNERABLE: "raw/vulnerable.json",
        ExecutionRole.PATCHED: "raw/patched.json",
        ExecutionRole.POSITIVE_CONTROL: "raw/positive-control.json",
    }[role]
    initial = ExecutionEvidence(
        execution_id=f"EX-{role.value}-abcdef12",
        role=role,
        build_id=build_id,
        started_at=STAMP,
        finished_at=STAMP,
        package=PackageEvidence(
            filename=(
                "packages/untrusted-update.json"
                if untrusted
                else "packages/trusted-update.json"
            ),
            sha256=payload,
            envelope_sha256=envelope,
            signer_fingerprint=("b" if untrusted else "d") * 64,
            signer_trust=SignerTrust.UNTRUSTED if untrusted else SignerTrust.TRUSTED,
        ),
        request=RequestEvidence(
            method="POST",
            path="/api/v1/updates",
            content_type="application/json",
            body_sha256=body_sha256 or envelope,
        ),
        response=ResponseEvidence(
            http_status=status,
            decision=observed,
            reason_code=reason,
            body_sha256="e" * 64,
        ),
        device_state_before=before or state(),
        device_state_after=after_state,
        secure_expected_decision=(
            ObservedDecision.ACCEPTED
            if role == ExecutionRole.POSITIVE_CONTROL
            else ObservedDecision.REJECTED
        ),
        observed_decision=observed,
        security_verdict=SecurityVerdict.INCONCLUSIVE,
        artifacts=[
            {
                "path": raw_path,
                "sha256": artifact_sha256,
                "size_bytes": artifact_size,
                "media_type": "application/json",
            }
        ],
    )
    return initial.model_copy(
        update={"security_verdict": calculate_individual_verdict(initial)}
    )


def verified_executions() -> list[ExecutionEvidence]:
    return [
        make_execution(ExecutionRole.VULNERABLE),
        make_execution(ExecutionRole.PATCHED),
        make_execution(ExecutionRole.POSITIVE_CONTROL),
    ]


def build_valid_bundle(bundle_root: Path) -> tuple[EvidenceDocument, str]:
    source = generate_demo_artifacts(bundle_root.parent / "source-runtime")
    untrusted_bytes = source.untrusted_package_path.read_bytes()
    trusted_bytes = source.trusted_package_path.read_bytes()
    untrusted = parse_and_decode_package(untrusted_bytes)
    trusted = parse_and_decode_package(trusted_bytes)

    atomic_write_bytes(bundle_root / "packages/untrusted-update.json", untrusted_bytes)
    atomic_write_bytes(bundle_root / "packages/trusted-update.json", trusted_bytes)
    atomic_write_bytes(
        bundle_root / "trust/trusted-public-key.pem",
        source.trusted_public_key_path.read_bytes(),
    )
    raw_paths = (
        "raw/vulnerable.json",
        "raw/patched.json",
        "raw/positive-control.json",
    )
    atomic_write_text(bundle_root / "run.log", "synthetic deterministic test run\n")

    untrusted_envelope_hash = hashlib.sha256(untrusted_bytes).hexdigest()
    trusted_envelope_hash = hashlib.sha256(trusted_bytes).hexdigest()
    executions = [
        make_execution(
            ExecutionRole.VULNERABLE,
            payload_sha256=untrusted.envelope.manifest.payload_sha256,
            envelope_sha256=untrusted_envelope_hash,
            body_sha256=untrusted_envelope_hash,
        ),
        make_execution(
            ExecutionRole.PATCHED,
            payload_sha256=untrusted.envelope.manifest.payload_sha256,
            envelope_sha256=untrusted_envelope_hash,
            body_sha256=untrusted_envelope_hash,
        ),
        make_execution(
            ExecutionRole.POSITIVE_CONTROL,
            payload_sha256=trusted.envelope.manifest.payload_sha256,
            envelope_sha256=trusted_envelope_hash,
            body_sha256=trusted_envelope_hash,
        ),
    ]
    executions[0].package.signer_fingerprint = untrusted.envelope.signer_fingerprint
    executions[1].package.signer_fingerprint = untrusted.envelope.signer_fingerprint
    executions[2].package.signer_fingerprint = trusted.envelope.signer_fingerprint
    for index, execution in enumerate(executions):
        raw_record = RawScenarioRecord(
            execution_id=execution.execution_id,
            role=execution.role,
            started_at=execution.started_at,
            finished_at=execution.finished_at,
            reset_confirmed=True,
            request=execution.request,
            gateway_response={
                "decision": execution.observed_decision.value,
                "reason_code": execution.response.reason_code,
            },
            device_state_before=execution.device_state_before,
            device_state_after=execution.device_state_after,
        )
        atomic_write_json(
            bundle_root / Path(*raw_paths[index].split("/")),
            raw_record.model_dump(mode="json"),
        )
        executions[index] = execution.model_copy(
            update={
                "artifacts": [
                    artifact_record(bundle_root, raw_paths[index], "application/json")
                ]
            }
        )

    media_types = {
        "packages/trusted-update.json": "application/json",
        "packages/untrusted-update.json": "application/json",
        "raw/patched.json": "application/json",
        "raw/positive-control.json": "application/json",
        "raw/vulnerable.json": "application/json",
        "run.log": "text/plain",
        "trust/trusted-public-key.pem": "application/x-pem-file",
    }
    evidence = EvidenceDocument(
        schema_version="1.1",
        verification_id="FR-20260904T030000000Z-abcdef12",
        created_at=STAMP,
        test_case=TestCaseEvidence(
            case_id="OTA-UNTRUSTED-SIGNER-001",
            title="Synthetic untrusted signer regression",
            security_property="Only a trusted Ed25519 signer may authorize an update.",
            positive_control_case_id="OTA-TRUSTED-SIGNER-001",
        ),
        executions=executions,
        verification_outcome=calculate_verification_outcome(executions),
        bundle_files=[
            artifact_record(bundle_root, path, media_type)
            for path, media_type in media_types.items()
        ],
    )
    write_evidence(bundle_root / "evidence.json", evidence, ROOT / "schemas/evidence.schema.json")
    write_report(bundle_root / "report.html", evidence, "evidence/test-bundle")
    _, digest = write_manifest(bundle_root)
    return evidence, digest
