"""Fresh synthetic key and package generation for a local demonstration."""

from __future__ import annotations

import base64
import hashlib
import json
from dataclasses import dataclass
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from .crypto import public_key_pem, raw_public_key, sign_manifest, signer_fingerprint
from .models import Manifest, PackageEnvelope


@dataclass(frozen=True)
class GeneratedArtifacts:
    runtime_dir: Path
    trusted_public_key_path: Path
    untrusted_public_key_path: Path
    untrusted_package_path: Path
    trusted_package_path: Path
    logs_dir: Path


def _create_package(
    private_key: Ed25519PrivateKey,
    package_id: str,
    firmware_version: str,
    payload: bytes,
) -> PackageEnvelope:
    public_key_bytes = raw_public_key(private_key.public_key())
    manifest = Manifest(
        schema_version="1.0",
        package_id=package_id,
        firmware_version=firmware_version,
        payload_sha256=hashlib.sha256(payload).hexdigest(),
        payload_size=len(payload),
        signature_algorithm="Ed25519",
    )
    signature = sign_manifest(private_key, manifest)
    return PackageEnvelope(
        manifest=manifest,
        payload_b64=base64.b64encode(payload).decode("ascii"),
        signer_public_key_b64=base64.b64encode(public_key_bytes).decode("ascii"),
        signer_fingerprint=signer_fingerprint(public_key_bytes),
        signature_b64=base64.b64encode(signature).decode("ascii"),
    )


def _write_package(path: Path, package: PackageEnvelope) -> None:
    document = json.dumps(
        package.model_dump(mode="json"),
        sort_keys=True,
        indent=2,
        ensure_ascii=False,
    )
    path.write_text(document + "\n", encoding="utf-8", newline="\n")


def generate_demo_artifacts(runtime_dir: Path) -> GeneratedArtifacts:
    """Generate public keys and packages; private keys never leave memory."""

    runtime_dir = runtime_dir.resolve()
    keys_dir = runtime_dir / "keys"
    packages_dir = runtime_dir / "packages"
    logs_dir = runtime_dir / "logs"
    keys_dir.mkdir(parents=True, exist_ok=True)
    packages_dir.mkdir(parents=True, exist_ok=True)
    logs_dir.mkdir(parents=True, exist_ok=True)

    trusted_private_key = Ed25519PrivateKey.generate()
    untrusted_private_key = Ed25519PrivateKey.generate()

    trusted_public_key_path = keys_dir / "trusted_public.pem"
    untrusted_public_key_path = keys_dir / "untrusted_public.pem"
    trusted_public_key_path.write_bytes(public_key_pem(trusted_private_key.public_key()))
    untrusted_public_key_path.write_bytes(public_key_pem(untrusted_private_key.public_key()))

    untrusted_package = _create_package(
        untrusted_private_key,
        package_id="ota-untrusted-signer-001",
        firmware_version="9.9.0-test",
        payload=b"FixRepro harmless synthetic test firmware from an untrusted signer.\n",
    )
    trusted_package = _create_package(
        trusted_private_key,
        package_id="ota-trusted-signer-001",
        firmware_version="1.1.0",
        payload=b"FixRepro harmless synthetic test firmware from the trusted signer.\n",
    )

    untrusted_package_path = packages_dir / "untrusted-update.json"
    trusted_package_path = packages_dir / "trusted-update.json"
    _write_package(untrusted_package_path, untrusted_package)
    _write_package(trusted_package_path, trusted_package)

    return GeneratedArtifacts(
        runtime_dir=runtime_dir,
        trusted_public_key_path=trusted_public_key_path,
        untrusted_public_key_path=untrusted_public_key_path,
        untrusted_package_path=untrusted_package_path,
        trusted_package_path=trusted_package_path,
        logs_dir=logs_dir,
    )
