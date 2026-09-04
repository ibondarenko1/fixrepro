from __future__ import annotations

import json
import os
import shutil
from pathlib import Path

import pytest

from verifier.bundle import (
    atomic_write_json,
    atomic_write_text,
    sha256_file,
    verify_bundle,
)
from verifier.models import VerificationOutcome
from verifier.orchestrator import VerificationOrchestrator

from .phase3_helpers import ROOT, build_valid_bundle


@pytest.fixture()
def valid_bundle(tmp_path: Path) -> Path:
    bundle = tmp_path / "bundle"
    build_valid_bundle(bundle)
    return bundle


def check(bundle: Path):
    return verify_bundle(
        bundle,
        ROOT,
        ROOT / "schemas/evidence.schema.json",
        allow_external=True,
    )


def rewrite_manifest_digest(bundle: Path) -> None:
    digest = sha256_file(bundle / "manifest.json")
    atomic_write_text(bundle / "manifest.sha256", f"{digest}  manifest.json\n")


def test_bundle_verification_succeeds_for_valid_bundle(valid_bundle: Path) -> None:
    result = check(valid_bundle)
    assert result.valid, result.failures
    assert result.verification_outcome == VerificationOutcome.PATCH_VERIFIED
    assert result.manifest_entry_count == 9


@pytest.mark.parametrize(
    "relative_path",
    ["packages/untrusted-update.json", "evidence.json", "report.html"],
)
def test_bundle_verification_detects_modified_files(
    valid_bundle: Path,
    relative_path: str,
) -> None:
    path = valid_bundle / Path(*relative_path.split("/"))
    path.write_bytes(path.read_bytes() + b"modified")
    result = check(valid_bundle)
    assert not result.valid
    assert any("mismatch" in failure or "invalid" in failure for failure in result.failures)


def test_bundle_verification_detects_modified_manifest(valid_bundle: Path) -> None:
    path = valid_bundle / "manifest.json"
    path.write_bytes(path.read_bytes() + b" ")
    result = check(valid_bundle)
    assert not result.valid
    assert "manifest.json does not match manifest.sha256" in result.failures


@pytest.mark.parametrize("unsafe_path", ["../escape.json", "C:/escape.json"])
def test_bundle_verification_rejects_unsafe_manifest_paths(
    valid_bundle: Path,
    unsafe_path: str,
) -> None:
    manifest = json.loads((valid_bundle / "manifest.json").read_text(encoding="utf-8"))
    manifest["files"][0]["path"] = unsafe_path
    manifest["files"] = sorted(manifest["files"], key=lambda item: item["path"])
    atomic_write_json(valid_bundle / "manifest.json", manifest)
    rewrite_manifest_digest(valid_bundle)
    result = check(valid_bundle)
    assert not result.valid
    assert any("manifest path" in failure for failure in result.failures)


def test_bundle_verification_rejects_symlinked_file_where_supported(
    valid_bundle: Path,
    tmp_path: Path,
) -> None:
    target = tmp_path / "external.txt"
    target.write_text("external\n", encoding="utf-8")
    linked = valid_bundle / "run.log"
    linked.unlink()
    try:
        os.symlink(target, linked)
    except OSError:
        pytest.skip("file symlinks are not available on this host")
    result = check(valid_bundle)
    assert not result.valid
    assert any("symlink" in failure or "unsafe" in failure for failure in result.failures)


def test_bundle_verification_rejects_unexpected_file(valid_bundle: Path) -> None:
    (valid_bundle / "unexpected.txt").write_text("unexpected\n", encoding="utf-8")
    result = check(valid_bundle)
    assert not result.valid
    assert "unexpected unlisted bundle file: unexpected.txt" in result.failures


def test_orchestration_writes_no_private_key(tmp_path: Path) -> None:
    repository = tmp_path / "repository"
    (repository / "cases").mkdir(parents=True)
    (repository / "schemas").mkdir()
    shutil.copy2(ROOT / "cases/ota-untrusted-signer.json", repository / "cases")
    shutil.copy2(ROOT / "cases/ota-trusted-signer.json", repository / "cases")
    shutil.copy2(ROOT / "schemas/evidence.schema.json", repository / "schemas")
    result = VerificationOrchestrator(repository).run()
    assert result.outcome == VerificationOutcome.PATCH_VERIFIED
    for path in repository.rglob("*"):
        if path.is_file():
            assert b"PRIVATE KEY" not in path.read_bytes()
