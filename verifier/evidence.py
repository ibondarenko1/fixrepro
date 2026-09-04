"""Evidence identifiers, schema validation, and document serialization."""

from __future__ import annotations

import json
import secrets
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from jsonschema import Draft202012Validator, FormatChecker

from .bundle import atomic_write_json
from .models import EvidenceDocument, ExecutionRole, TestCaseEvidence


def utc_timestamp() -> str:
    return datetime.now(UTC).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def new_verification_id(now: datetime | None = None) -> str:
    current = now.astimezone(UTC) if now is not None else datetime.now(UTC)
    stamp = current.strftime("%Y%m%dT%H%M%S%f")[:-3] + "Z"
    return f"FR-{stamp}-{secrets.token_hex(4)}"


def new_execution_id(role: ExecutionRole) -> str:
    return f"EX-{role.value}-{secrets.token_hex(4)}"


def load_test_case(repository_root: Path) -> TestCaseEvidence:
    untrusted_path = repository_root / "cases" / "ota-untrusted-signer.json"
    trusted_path = repository_root / "cases" / "ota-trusted-signer.json"
    try:
        untrusted: dict[str, Any] = json.loads(untrusted_path.read_text(encoding="utf-8"))
        trusted: dict[str, Any] = json.loads(trusted_path.read_text(encoding="utf-8"))
        return TestCaseEvidence(
            case_id=str(untrusted["case_id"]),
            title=str(untrusted["title"]),
            security_property=str(untrusted["security_property"]),
            positive_control_case_id=str(trusted["case_id"]),
        )
    except (OSError, UnicodeError, json.JSONDecodeError, KeyError, TypeError) as exc:
        raise ValueError(f"could not load fixed verification cases: {exc}") from exc


def schema_failures(document: EvidenceDocument, schema_path: Path) -> list[str]:
    schema = json.loads(schema_path.read_text(encoding="utf-8"))
    Draft202012Validator.check_schema(schema)
    validator = Draft202012Validator(schema, format_checker=FormatChecker())
    serialized = document.model_dump(mode="json")
    return [
        f"{'.'.join(str(part) for part in error.absolute_path) or 'root'}: {error.message}"
        for error in sorted(
            validator.iter_errors(serialized),
            key=lambda item: list(item.absolute_path),
        )
    ]


def write_evidence(
    path: Path,
    document: EvidenceDocument,
    schema_path: Path,
) -> None:
    failures = schema_failures(document, schema_path)
    if failures:
        raise ValueError("evidence does not conform to schema: " + "; ".join(failures))
    atomic_write_json(path, document.model_dump(mode="json"))
