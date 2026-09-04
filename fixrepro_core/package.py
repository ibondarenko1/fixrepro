"""Strict package parsing, decoding, canonicalization, and integrity checks."""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
from dataclasses import dataclass

from pydantic import ValidationError

from .models import Manifest, PackageEnvelope


class PackageValidationError(ValueError):
    """A stable package failure suitable for policy evaluation."""

    def __init__(self, reason_code: str, message: str) -> None:
        super().__init__(message)
        self.reason_code = reason_code


@dataclass(frozen=True)
class DecodedPackage:
    envelope: PackageEnvelope
    payload: bytes
    signer_public_key: bytes
    signature: bytes


def canonical_manifest_bytes(manifest: Manifest) -> bytes:
    """Return the one canonical byte representation used for signing."""

    manifest_dict = manifest.model_dump(mode="json")
    return json.dumps(
        manifest_dict,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")


def strict_b64decode(value: str, field_name: str) -> bytes:
    try:
        return base64.b64decode(value.encode("ascii"), validate=True)
    except (UnicodeEncodeError, binascii.Error, ValueError) as exc:
        raise PackageValidationError(
            "MALFORMED_PACKAGE",
            f"{field_name} is not valid canonical base64",
        ) from exc


def parse_package_bytes(raw: bytes) -> PackageEnvelope:
    try:
        document = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise PackageValidationError("MALFORMED_PACKAGE", "package must be valid UTF-8 JSON") from exc
    try:
        return PackageEnvelope.model_validate(document)
    except ValidationError as exc:
        raise PackageValidationError("MALFORMED_PACKAGE", "package structure is invalid") from exc


def decode_package(envelope: PackageEnvelope) -> DecodedPackage:
    payload = strict_b64decode(envelope.payload_b64, "payload_b64")
    public_key = strict_b64decode(envelope.signer_public_key_b64, "signer_public_key_b64")
    signature = strict_b64decode(envelope.signature_b64, "signature_b64")
    if len(public_key) != 32:
        raise PackageValidationError("MALFORMED_PACKAGE", "Ed25519 public key must be 32 bytes")
    if len(signature) != 64:
        raise PackageValidationError("MALFORMED_PACKAGE", "Ed25519 signature must be 64 bytes")
    return DecodedPackage(
        envelope=envelope,
        payload=payload,
        signer_public_key=public_key,
        signature=signature,
    )


def parse_and_decode_package(raw: bytes) -> DecodedPackage:
    return decode_package(parse_package_bytes(raw))


def verify_payload_integrity(package: DecodedPackage) -> None:
    manifest = package.envelope.manifest
    if len(package.payload) != manifest.payload_size:
        raise PackageValidationError(
            "PAYLOAD_SIZE_MISMATCH",
            "decoded payload length does not match manifest payload_size",
        )
    actual_hash = hashlib.sha256(package.payload).hexdigest()
    if actual_hash != manifest.payload_sha256:
        raise PackageValidationError(
            "PAYLOAD_HASH_MISMATCH",
            "decoded payload SHA-256 does not match the manifest",
        )
