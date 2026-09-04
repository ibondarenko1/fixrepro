from __future__ import annotations

import base64
import json
from pathlib import Path

import pytest

from fixrepro_core.artifacts import GeneratedArtifacts, generate_demo_artifacts
from fixrepro_core.crypto import load_public_key_bytes
from fixrepro_core.evaluation import (
    Decision,
    ReasonCode,
    evaluate_patched_policy,
    evaluate_vulnerable_policy,
)


@pytest.fixture()
def generated(tmp_path: Path) -> tuple[GeneratedArtifacts, bytes]:
    artifacts = generate_demo_artifacts(tmp_path / "runtime")
    return artifacts, load_public_key_bytes(artifacts.trusted_public_key_path)


def mutate_package(path: Path, field: str, value: str) -> bytes:
    document = json.loads(path.read_text(encoding="utf-8"))
    document[field] = value
    return json.dumps(document, sort_keys=True, separators=(",", ":")).encode("utf-8")


def package_with_changed_payload(path: Path) -> bytes:
    document = json.loads(path.read_text(encoding="utf-8"))
    payload = bytearray(base64.b64decode(document["payload_b64"], validate=True))
    payload[0] ^= 1
    document["payload_b64"] = base64.b64encode(payload).decode("ascii")
    return json.dumps(document, sort_keys=True, separators=(",", ":")).encode("utf-8")


def test_vulnerable_policy_accepts_valid_untrusted_package(
    generated: tuple[GeneratedArtifacts, bytes],
) -> None:
    artifacts, _ = generated
    result = evaluate_vulnerable_policy(artifacts.untrusted_package_path.read_bytes())
    assert result.decision == Decision.ACCEPTED
    assert result.reason_code == ReasonCode.CHECKSUM_ONLY_ACCEPTED


def test_patched_policy_rejects_same_untrusted_package(
    generated: tuple[GeneratedArtifacts, bytes],
) -> None:
    artifacts, trusted_key = generated
    result = evaluate_patched_policy(artifacts.untrusted_package_path.read_bytes(), trusted_key)
    assert result.decision == Decision.REJECTED
    assert result.reason_code == ReasonCode.UNTRUSTED_SIGNER


def test_patched_policy_accepts_trusted_package(
    generated: tuple[GeneratedArtifacts, bytes],
) -> None:
    artifacts, trusted_key = generated
    result = evaluate_patched_policy(artifacts.trusted_package_path.read_bytes(), trusted_key)
    assert result.decision == Decision.ACCEPTED
    assert result.reason_code == ReasonCode.TRUSTED_SIGNATURE_ACCEPTED


@pytest.mark.parametrize("policy_name", ["vulnerable", "patched"])
def test_both_policies_reject_payload_hash_mismatch(
    generated: tuple[GeneratedArtifacts, bytes],
    policy_name: str,
) -> None:
    artifacts, trusted_key = generated
    package = package_with_changed_payload(artifacts.trusted_package_path)
    result = (
        evaluate_vulnerable_policy(package)
        if policy_name == "vulnerable"
        else evaluate_patched_policy(package, trusted_key)
    )
    assert result.decision == Decision.REJECTED
    assert result.reason_code == ReasonCode.PAYLOAD_HASH_MISMATCH


def test_patched_policy_rejects_invalid_signature(
    generated: tuple[GeneratedArtifacts, bytes],
) -> None:
    artifacts, trusted_key = generated
    invalid_signature = base64.b64encode(bytes(64)).decode("ascii")
    package = mutate_package(artifacts.trusted_package_path, "signature_b64", invalid_signature)
    result = evaluate_patched_policy(package, trusted_key)
    assert result.decision == Decision.REJECTED
    assert result.reason_code == ReasonCode.INVALID_SIGNATURE


def test_patched_policy_rejects_declared_fingerprint_mismatch(
    generated: tuple[GeneratedArtifacts, bytes],
) -> None:
    artifacts, trusted_key = generated
    package = mutate_package(artifacts.trusted_package_path, "signer_fingerprint", "0" * 64)
    result = evaluate_patched_policy(package, trusted_key)
    assert result.decision == Decision.REJECTED
    assert result.reason_code == ReasonCode.SIGNER_FINGERPRINT_MISMATCH
