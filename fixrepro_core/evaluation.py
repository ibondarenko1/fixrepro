"""Deterministic vulnerable and patched OTA policy evaluation."""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum

from .crypto import signer_fingerprint, verify_manifest_signature
from .package import (
    DecodedPackage,
    PackageValidationError,
    parse_and_decode_package,
    verify_payload_integrity,
)


class GatewayRole(StrEnum):
    VULNERABLE = "VULNERABLE"
    PATCHED = "PATCHED"


class Decision(StrEnum):
    ACCEPTED = "ACCEPTED"
    REJECTED = "REJECTED"
    ERROR = "ERROR"


class ReasonCode(StrEnum):
    CHECKSUM_ONLY_ACCEPTED = "CHECKSUM_ONLY_ACCEPTED"
    TRUSTED_SIGNATURE_ACCEPTED = "TRUSTED_SIGNATURE_ACCEPTED"
    UNTRUSTED_SIGNER = "UNTRUSTED_SIGNER"
    PAYLOAD_HASH_MISMATCH = "PAYLOAD_HASH_MISMATCH"
    PAYLOAD_SIZE_MISMATCH = "PAYLOAD_SIZE_MISMATCH"
    SIGNER_FINGERPRINT_MISMATCH = "SIGNER_FINGERPRINT_MISMATCH"
    INVALID_SIGNATURE = "INVALID_SIGNATURE"
    MALFORMED_PACKAGE = "MALFORMED_PACKAGE"
    DEVICE_UNAVAILABLE = "DEVICE_UNAVAILABLE"
    DEVICE_APPLY_FAILED = "DEVICE_APPLY_FAILED"
    TRUST_CONFIGURATION_ERROR = "TRUST_CONFIGURATION_ERROR"


@dataclass(frozen=True)
class PolicyResult:
    decision: Decision
    reason_code: ReasonCode
    package_id: str = ""
    firmware_version: str = ""
    payload_sha256: str = ""
    signer_fingerprint: str = ""


def _rejected_from_error(error: PackageValidationError) -> PolicyResult:
    try:
        reason = ReasonCode(error.reason_code)
    except ValueError:
        reason = ReasonCode.MALFORMED_PACKAGE
    return PolicyResult(decision=Decision.REJECTED, reason_code=reason)


def _package_fields(package: DecodedPackage) -> dict[str, str]:
    envelope = package.envelope
    return {
        "package_id": envelope.manifest.package_id,
        "firmware_version": envelope.manifest.firmware_version,
        "payload_sha256": envelope.manifest.payload_sha256,
        "signer_fingerprint": envelope.signer_fingerprint,
    }


def evaluate_vulnerable_policy(raw_package: bytes) -> PolicyResult:
    """Model the deliberate synthetic flaw: integrity is treated as authorization."""

    try:
        package = parse_and_decode_package(raw_package)
    except PackageValidationError as exc:
        return _rejected_from_error(exc)

    fields = _package_fields(package)
    try:
        verify_payload_integrity(package)
    except PackageValidationError as exc:
        return PolicyResult(
            decision=Decision.REJECTED,
            reason_code=ReasonCode(exc.reason_code),
            **fields,
        )

    # Deliberately vulnerable synthetic behavior: no trust or signature check.
    return PolicyResult(
        decision=Decision.ACCEPTED,
        reason_code=ReasonCode.CHECKSUM_ONLY_ACCEPTED,
        **fields,
    )


def evaluate_patched_policy(raw_package: bytes, trusted_public_key: bytes) -> PolicyResult:
    try:
        package = parse_and_decode_package(raw_package)
    except PackageValidationError as exc:
        return _rejected_from_error(exc)

    fields = _package_fields(package)
    try:
        verify_payload_integrity(package)
    except PackageValidationError as exc:
        return PolicyResult(
            decision=Decision.REJECTED,
            reason_code=ReasonCode(exc.reason_code),
            **fields,
        )

    actual_fingerprint = signer_fingerprint(package.signer_public_key)
    if actual_fingerprint != package.envelope.signer_fingerprint:
        return PolicyResult(
            decision=Decision.REJECTED,
            reason_code=ReasonCode.SIGNER_FINGERPRINT_MISMATCH,
            **fields,
        )
    if package.signer_public_key != trusted_public_key:
        return PolicyResult(
            decision=Decision.REJECTED,
            reason_code=ReasonCode.UNTRUSTED_SIGNER,
            **fields,
        )
    if not verify_manifest_signature(
        package.signer_public_key,
        package.envelope.manifest,
        package.signature,
    ):
        return PolicyResult(
            decision=Decision.REJECTED,
            reason_code=ReasonCode.INVALID_SIGNATURE,
            **fields,
        )

    return PolicyResult(
        decision=Decision.ACCEPTED,
        reason_code=ReasonCode.TRUSTED_SIGNATURE_ACCEPTED,
        **fields,
    )


def http_status_for(result: PolicyResult) -> int:
    if result.decision == Decision.ACCEPTED:
        return 200
    if result.reason_code == ReasonCode.UNTRUSTED_SIGNER:
        return 403
    if result.reason_code in {
        ReasonCode.DEVICE_UNAVAILABLE,
        ReasonCode.DEVICE_APPLY_FAILED,
    }:
        return 502
    if result.reason_code == ReasonCode.TRUST_CONFIGURATION_ERROR:
        return 500
    return 400
