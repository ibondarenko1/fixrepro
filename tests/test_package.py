from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from fixrepro_core.artifacts import GeneratedArtifacts, generate_demo_artifacts
from fixrepro_core.crypto import signer_fingerprint, verify_manifest_signature
from fixrepro_core.models import PackageEnvelope
from fixrepro_core.package import (
    PackageValidationError,
    parse_and_decode_package,
    parse_package_bytes,
)


@pytest.fixture()
def artifacts(tmp_path: Path) -> GeneratedArtifacts:
    return generate_demo_artifacts(tmp_path / "runtime")


def test_generated_packages_conform_to_strict_model(artifacts: GeneratedArtifacts) -> None:
    for path in (artifacts.untrusted_package_path, artifacts.trusted_package_path):
        envelope = parse_package_bytes(path.read_bytes())
        assert isinstance(envelope, PackageEnvelope)


def test_generated_payload_hashes_are_correct(artifacts: GeneratedArtifacts) -> None:
    for path in (artifacts.untrusted_package_path, artifacts.trusted_package_path):
        package = parse_and_decode_package(path.read_bytes())
        assert hashlib.sha256(package.payload).hexdigest() == package.envelope.manifest.payload_sha256


def test_generated_signer_fingerprints_are_correct(artifacts: GeneratedArtifacts) -> None:
    for path in (artifacts.untrusted_package_path, artifacts.trusted_package_path):
        package = parse_and_decode_package(path.read_bytes())
        assert signer_fingerprint(package.signer_public_key) == package.envelope.signer_fingerprint


def test_generated_signatures_verify_with_own_public_keys(artifacts: GeneratedArtifacts) -> None:
    for path in (artifacts.untrusted_package_path, artifacts.trusted_package_path):
        package = parse_and_decode_package(path.read_bytes())
        assert verify_manifest_signature(
            package.signer_public_key,
            package.envelope.manifest,
            package.signature,
        )


def test_strict_package_model_rejects_unknown_fields(artifacts: GeneratedArtifacts) -> None:
    document = json.loads(artifacts.trusted_package_path.read_text(encoding="utf-8"))
    document["unknown_field"] = True
    with pytest.raises(PackageValidationError):
        parse_package_bytes(json.dumps(document).encode("utf-8"))


def test_artifact_generation_never_serializes_a_private_key(artifacts: GeneratedArtifacts) -> None:
    prohibited_suffixes = {".key", ".p12", ".pfx"}
    for path in artifacts.runtime_dir.rglob("*"):
        if not path.is_file():
            continue
        assert path.suffix.lower() not in prohibited_suffixes
        assert b"PRIVATE KEY" not in path.read_bytes()
