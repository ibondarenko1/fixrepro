from __future__ import annotations

import json
from pathlib import Path

import pytest
from pydantic import ValidationError

from verifier.bundle import atomic_write_text, write_manifest
from verifier.evidence import schema_failures
from verifier.models import EvidenceDocument, ExecutionRole
from verifier.report import REQUIRED_REPORT_LABELS, render_report


ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture()
def sample() -> EvidenceDocument:
    return EvidenceDocument.model_validate_json(
        (ROOT / "evidence/sample-evidence.json").read_bytes()
    )


def test_evidence_models_reject_unknown_fields() -> None:
    document = json.loads((ROOT / "evidence/sample-evidence.json").read_text(encoding="utf-8"))
    document["unknown_field"] = True
    with pytest.raises(ValidationError):
        EvidenceDocument.model_validate_json(json.dumps(document).encode("utf-8"))


def test_evidence_model_requires_exactly_one_execution_per_role() -> None:
    document = json.loads((ROOT / "evidence/sample-evidence.json").read_text(encoding="utf-8"))
    document["executions"][1]["role"] = "VULNERABLE"
    document["executions"][1]["execution_id"] = "EX-VULNERABLE-b2c3d4e5"
    with pytest.raises(ValidationError):
        EvidenceDocument.model_validate_json(json.dumps(document).encode("utf-8"))


def test_generated_sample_evidence_conforms_to_json_schema(sample: EvidenceDocument) -> None:
    assert schema_failures(sample, ROOT / "schemas/evidence.schema.json") == []


def test_untrusted_executions_preserve_envelope_and_request_hashes(
    sample: EvidenceDocument,
) -> None:
    by_role = {execution.role: execution for execution in sample.executions}
    vulnerable = by_role[ExecutionRole.VULNERABLE]
    patched = by_role[ExecutionRole.PATCHED]
    assert vulnerable.package.envelope_sha256 == patched.package.envelope_sha256
    assert vulnerable.request.body_sha256 == patched.request.body_sha256


def test_report_generation_escapes_dynamic_html(sample: EvidenceDocument) -> None:
    unsafe = "<script>alert('x') & more</script>"
    modified_case = sample.test_case.model_copy(update={"security_property": unsafe})
    modified = sample.model_copy(update={"test_case": modified_case})
    report = render_report(modified, "evidence/test-bundle")
    assert unsafe not in report
    assert "&lt;script&gt;" in report
    assert "&amp; more" in report


def test_report_contains_all_required_visible_labels(sample: EvidenceDocument) -> None:
    report = render_report(sample, "evidence/test-bundle")
    for label in REQUIRED_REPORT_LABELS:
        assert label in report
    assert "manifest.sha256" in report
    assert "tamper-evident" in report


def test_manifest_generation_is_deterministic_for_unchanged_files(tmp_path: Path) -> None:
    bundle = tmp_path / "bundle"
    atomic_write_text(bundle / "one.txt", "one\n")
    atomic_write_text(bundle / "nested/two.txt", "two\n")
    first_manifest, first_digest = write_manifest(bundle)
    second_manifest, second_digest = write_manifest(bundle)
    assert first_manifest == second_manifest
    assert first_digest == second_digest
