"""Ed25519 public-key helpers for the synthetic package format."""

from __future__ import annotations

import hashlib
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from .models import Manifest
from .package import canonical_manifest_bytes


def raw_public_key(public_key: Ed25519PublicKey) -> bytes:
    return public_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )


def signer_fingerprint(public_key_bytes: bytes) -> str:
    if len(public_key_bytes) != 32:
        raise ValueError("Ed25519 public key must be exactly 32 bytes")
    return hashlib.sha256(public_key_bytes).hexdigest()


def sign_manifest(private_key: Ed25519PrivateKey, manifest: Manifest) -> bytes:
    return private_key.sign(canonical_manifest_bytes(manifest))


def verify_manifest_signature(
    public_key_bytes: bytes,
    manifest: Manifest,
    signature: bytes,
) -> bool:
    try:
        Ed25519PublicKey.from_public_bytes(public_key_bytes).verify(
            signature,
            canonical_manifest_bytes(manifest),
        )
    except (InvalidSignature, ValueError):
        return False
    return True


def public_key_pem(public_key: Ed25519PublicKey) -> bytes:
    return public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )


def load_public_key_bytes(path: Path) -> bytes:
    try:
        loaded = serialization.load_pem_public_key(path.read_bytes())
    except (OSError, ValueError, TypeError) as exc:
        raise ValueError(f"cannot load Ed25519 public key from {path}") from exc
    if not isinstance(loaded, Ed25519PublicKey):
        raise ValueError(f"configured public key at {path} is not Ed25519")
    return raw_public_key(loaded)
