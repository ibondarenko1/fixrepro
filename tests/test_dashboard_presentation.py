from __future__ import annotations

import json
import shutil
from pathlib import Path

import pytest

from app.models import PresentationSource
from app.presentation import (
    BundleIntegrityError,
    BundleRegistry,
    present_bundle,
)
from verifier.bundle import atomic_write_json, write_manifest

from .phase3_helpers import ROOT, build_valid_bundle


def repository_with_bundle(tmp_path: Path) -> tuple[Path, Path, BundleRegistry]:
    repository = tmp_path / "repository"
    (repository / "schemas").mkdir(parents=True)
    shutil.copy2(ROOT / "schemas/evidence.schema.json", repository / "schemas")
    bundle = repository / "evidence/runs/test-bundle"
    build_valid_bundle(bundle)
    registry = BundleRegistry(repository)
    registry.register_live("JOB-0123abcd", bundle)
    return repository, bundle, registry


def test_presentation_maps_roles_independently_of_evidence_order(tmp_path: Path) -> None:
    repository, bundle, registry = repository_with_bundle(tmp_path)
    evidence_path = bundle / "evidence.json"
    evidence = json.loads(evidence_path.read_text(encoding="utf-8"))
    evidence["executions"] = list(reversed(evidence["executions"]))
    atomic_write_json(evidence_path, evidence)
    write_manifest(bundle)

    result = present_bundle(repository, registry, "JOB-0123abcd", PresentationSource.LIVE)
    assert [scenario.role.value for scenario in result.scenarios] == [
        "VULNERABLE",
        "PATCHED",
        "POSITIVE_CONTROL",
    ]
    assert result.same_input_verified is True


def test_presentation_rejects_bundle_with_modified_evidence(tmp_path: Path) -> None:
    repository, bundle, registry = repository_with_bundle(tmp_path)
    evidence_path = bundle / "evidence.json"
    evidence_path.write_bytes(evidence_path.read_bytes() + b"modified")
    with pytest.raises(BundleIntegrityError):
        present_bundle(repository, registry, "JOB-0123abcd", PresentationSource.LIVE)


def test_presentation_rejects_invalid_bundle(tmp_path: Path) -> None:
    repository = tmp_path / "repository"
    (repository / "schemas").mkdir(parents=True)
    shutil.copy2(ROOT / "schemas/evidence.schema.json", repository / "schemas")
    bundle = repository / "evidence/runs/broken"
    bundle.mkdir(parents=True)
    registry = BundleRegistry(repository)
    registry.register_live("JOB-0123abcd", bundle)
    with pytest.raises(BundleIntegrityError):
        present_bundle(repository, registry, "JOB-0123abcd", PresentationSource.LIVE)


def test_presentation_returns_only_fixed_artifact_links(tmp_path: Path) -> None:
    repository, _, registry = repository_with_bundle(tmp_path)
    result = present_bundle(repository, registry, "JOB-0123abcd", PresentationSource.LIVE)
    links = result.links.model_dump()
    assert set(links) == {"report", "evidence", "manifest", "digest"}
    assert all(path.startswith("/api/v1/bundles/JOB-0123abcd/") for path in links.values())
    assert all(".." not in path for path in links.values())


def test_presentation_exposes_no_payload_or_key_material(tmp_path: Path) -> None:
    repository, _, registry = repository_with_bundle(tmp_path)
    result = present_bundle(repository, registry, "JOB-0123abcd", PresentationSource.LIVE)
    serialized = result.model_dump_json()
    assert "payload_b64" not in serialized
    assert "PUBLIC KEY" not in serialized
    assert "PRIVATE KEY" not in serialized
