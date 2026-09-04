#!/usr/bin/env python3
"""Validate the FixRepro Phase 1 scaffold using only the standard library."""

from __future__ import annotations

import json
import re
import subprocess
import sys
from datetime import datetime
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]

REQUIRED_FILES = (
    "README.md",
    "PROJECT_SPEC.md",
    "DEVELOPMENT_LOG.md",
    "SECURITY.md",
    "LICENSE",
    ".gitignore",
    ".gitattributes",
    "app/.gitkeep",
    "verifier/__init__.py",
    "targets/vulnerable/.gitkeep",
    "targets/patched/.gitkeep",
    "device/.gitkeep",
    "tests/.gitkeep",
    "reports/.gitkeep",
    "scripts/validate_scaffold.py",
    "cases/ota-untrusted-signer.json",
    "cases/ota-trusted-signer.json",
    "schemas/evidence.schema.json",
    "evidence/sample-evidence.json",
    "docs/ARCHITECTURE.md",
    "docs/DEMO_FLOW.md",
    "docs/THREAT_MODEL.md",
    "docs/JUDGING_MAP.md",
    "docs/DEVPOST_COPY.md",
    "devpost/overview.json",
)

SHA256_RE = re.compile(r"^[a-f0-9]{64}$")
PRIVATE_KEY_SUFFIXES = {".key", ".p12", ".pfx"}
PRIVATE_KEY_NAMES = {"id_" + "rsa", "id_" + "ed25519"}
FORBIDDEN_STRINGS = (
    "V" + "INCE",
    "G" + "HSA-",
    "C" + "VE-",
    "SUMMIT " + "AI TECH",
)


def load_json(relative_path: str, failures: list[str]) -> dict[str, Any]:
    path = ROOT / relative_path
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        failures.append(f"{relative_path}: cannot parse JSON: {exc}")
        return {}
    if not isinstance(value, dict):
        failures.append(f"{relative_path}: top-level JSON value must be an object")
        return {}
    return value


def expect_equal(
    failures: list[str],
    label: str,
    actual: Any,
    expected: Any,
) -> None:
    if actual != expected:
        failures.append(f"{label}: expected {expected!r}, found {actual!r}")


def validate_required_files(failures: list[str]) -> None:
    for relative_path in REQUIRED_FILES:
        if relative_path == "app/.gitkeep" and (ROOT / "app" / "__init__.py").is_file():
            continue
        if not (ROOT / relative_path).is_file():
            failures.append(f"missing required file: {relative_path}")


def validate_all_json(failures: list[str]) -> int:
    count = 0
    ignored_parts = {".git", ".venv", ".runtime", "__pycache__"}
    for path in sorted(ROOT.rglob("*.json")):
        relative = path.relative_to(ROOT)
        if (
            relative.parts[:2] == ("evidence", "runs")
            or any(part in ignored_parts or part.endswith(".egg-info") for part in path.parts)
        ):
            continue
        count += 1
        try:
            json.loads(path.read_text(encoding="utf-8"))
        except (OSError, UnicodeError, json.JSONDecodeError) as exc:
            failures.append(f"{path.relative_to(ROOT)}: invalid JSON: {exc}")
    return count


def validate_cases(failures: list[str]) -> None:
    untrusted = load_json("cases/ota-untrusted-signer.json", failures)
    trusted = load_json("cases/ota-trusted-signer.json", failures)

    case_ids = [untrusted.get("case_id"), trusted.get("case_id")]
    if None in case_ids or len(set(case_ids)) != 2:
        failures.append("case IDs must be present and unique")

    untrusted_contract = {
        "case_id": "OTA-UNTRUSTED-SIGNER-001",
        "signer_trust": "UNTRUSTED",
        "secure_expected_decision": "REJECTED",
        "vulnerable_expected_observation": "ACCEPTED",
        "patched_expected_observation": "REJECTED",
        "initial_device_version": "1.0.0",
        "vulnerable_result_version": "9.9.0-test",
        "patched_result_version": "1.0.0",
    }
    trusted_contract = {
        "case_id": "OTA-TRUSTED-SIGNER-001",
        "control_type": "POSITIVE_CONTROL",
        "signer_trust": "TRUSTED",
        "secure_expected_decision": "ACCEPTED",
        "patched_expected_observation": "ACCEPTED",
        "initial_device_version": "1.0.0",
        "expected_result_version": "1.1.0",
    }
    for key, expected in untrusted_contract.items():
        expect_equal(failures, f"untrusted case {key}", untrusted.get(key), expected)
    for key, expected in trusted_contract.items():
        expect_equal(failures, f"trusted case {key}", trusted.get(key), expected)


def validate_devpost(failures: list[str]) -> None:
    overview = load_json("devpost/overview.json", failures)
    limits = {
        "project_name": 60,
        "elevator_pitch": 200,
        "problem_statement": 255,
    }
    for field, limit in limits.items():
        value = overview.get(field)
        if not isinstance(value, str):
            failures.append(f"devpost {field}: must be a string")
        elif len(value) > limit:
            failures.append(f"devpost {field}: {len(value)} characters exceeds {limit}")

    expect_equal(failures, "devpost project_name", overview.get("project_name"), "FixRepro")
    if overview.get("submission_status") not in {"draft", "ready_for_manual_devpost_entry"}:
        failures.append("devpost submission_status must not claim an actual submission")
    implementation_status = overview.get("implementation_status")
    if implementation_status not in {"phase_1_scaffold", "phase_5a_submission_package"}:
        failures.append("devpost implementation_status is not a recognized repository phase")
    if implementation_status == "phase_5a_submission_package":
        expect_equal(failures, "devpost technologies_planned", overview.get("technologies_planned"), [])


def validate_schema(failures: list[str]) -> None:
    schema = load_json("schemas/evidence.schema.json", failures)
    expect_equal(
        failures,
        "evidence schema draft",
        schema.get("$schema"),
        "https://json-schema.org/draft/2020-12/schema",
    )
    expect_equal(
        failures,
        "evidence schema version",
        schema.get("properties", {}).get("schema_version", {}).get("const"),
        "1.1",
    )
    required = {
        "schema_version",
        "verification_id",
        "created_at",
        "test_case",
        "executions",
        "verification_outcome",
        "bundle_files",
    }
    declared = schema.get("required")
    if not isinstance(declared, list) or not required.issubset(declared):
        failures.append("evidence schema: required top-level fields are incomplete")


def walk_hashes(value: Any, path: str = "sample") -> list[tuple[str, Any]]:
    found: list[tuple[str, Any]] = []
    if isinstance(value, dict):
        for key, child in value.items():
            child_path = f"{path}.{key}"
            if (
                child is not None
                and (key == "sha256" or key.endswith("_sha256") or key == "signer_fingerprint")
            ):
                found.append((child_path, child))
            found.extend(walk_hashes(child, child_path))
    elif isinstance(value, list):
        for index, child in enumerate(value):
            found.extend(walk_hashes(child, f"{path}[{index}]"))
    return found


def is_utc_datetime(value: Any) -> bool:
    if not isinstance(value, str) or not value.endswith("Z"):
        return False
    try:
        datetime.fromisoformat(value.removesuffix("Z") + "+00:00")
    except ValueError:
        return False
    return True


def validate_sample(failures: list[str]) -> None:
    sample = load_json("evidence/sample-evidence.json", failures)
    required = {
        "schema_version",
        "verification_id",
        "created_at",
        "test_case",
        "executions",
        "verification_outcome",
        "bundle_files",
    }
    missing = sorted(required - set(sample))
    if missing:
        failures.append(f"sample evidence: missing top-level fields: {', '.join(missing)}")

    executions = sample.get("executions")
    if not isinstance(executions, list):
        failures.append("sample evidence: executions must be an array")
        return

    expected_roles = {"VULNERABLE", "PATCHED", "POSITIVE_CONTROL"}
    roles = [item.get("role") for item in executions if isinstance(item, dict)]
    if len(executions) != 3 or len(roles) != 3 or set(roles) != expected_roles or len(set(roles)) != 3:
        failures.append("sample evidence: exactly one execution is required for each of VULNERABLE, PATCHED, and POSITIVE_CONTROL")
        return

    by_role = {item["role"]: item for item in executions}
    expected = {
        "VULNERABLE": ("ACCEPTED", "FAIL", "1.0.0", "9.9.0-test", "UNTRUSTED"),
        "PATCHED": ("REJECTED", "PASS", "1.0.0", "1.0.0", "UNTRUSTED"),
        "POSITIVE_CONTROL": ("ACCEPTED", "PASS", "1.0.0", "1.1.0", "TRUSTED"),
    }
    for role, (decision, verdict, before, after, trust) in expected.items():
        execution = by_role[role]
        expect_equal(failures, f"{role} observed_decision", execution.get("observed_decision"), decision)
        expect_equal(failures, f"{role} security_verdict", execution.get("security_verdict"), verdict)
        expect_equal(
            failures,
            f"{role} initial version",
            execution.get("device_state_before", {}).get("firmware_version"),
            before,
        )
        expect_equal(
            failures,
            f"{role} result version",
            execution.get("device_state_after", {}).get("firmware_version"),
            after,
        )
        expect_equal(
            failures,
            f"{role} signer trust",
            execution.get("package", {}).get("signer_trust"),
            trust,
        )
        for field in ("started_at", "finished_at"):
            if not is_utc_datetime(execution.get(field)):
                failures.append(f"{role} {field}: must be an ISO 8601 UTC date-time")

    vulnerable_hash = by_role["VULNERABLE"].get("package", {}).get("sha256")
    patched_hash = by_role["PATCHED"].get("package", {}).get("sha256")
    expect_equal(
        failures,
        "vulnerable and patched package SHA-256",
        patched_hash,
        vulnerable_hash,
    )
    vulnerable_envelope = by_role["VULNERABLE"].get("package", {}).get("envelope_sha256")
    patched_envelope = by_role["PATCHED"].get("package", {}).get("envelope_sha256")
    vulnerable_body = by_role["VULNERABLE"].get("request", {}).get("body_sha256")
    patched_body = by_role["PATCHED"].get("request", {}).get("body_sha256")
    expect_equal(failures, "vulnerable and patched envelope SHA-256", patched_envelope, vulnerable_envelope)
    expect_equal(failures, "vulnerable and patched request body SHA-256", patched_body, vulnerable_body)
    expect_equal(failures, "vulnerable envelope and request body SHA-256", vulnerable_body, vulnerable_envelope)
    expect_equal(
        failures,
        "verification_outcome",
        sample.get("verification_outcome"),
        "PATCH_VERIFIED",
    )
    if not is_utc_datetime(sample.get("created_at")):
        failures.append("sample evidence created_at: must be an ISO 8601 UTC date-time")

    hashes = walk_hashes(sample)
    if not hashes:
        failures.append("sample evidence: no SHA-256 values found")
    for path, value in hashes:
        if not isinstance(value, str) or not SHA256_RE.fullmatch(value):
            failures.append(f"{path}: must be 64 lowercase hexadecimal characters")


def project_files() -> list[Path]:
    try:
        result = subprocess.run(
            ["git", "ls-files", "--cached"],
            cwd=ROOT,
            check=False,
            capture_output=True,
            text=True,
            encoding="utf-8",
        )
    except OSError:
        result = None
    if result is not None and result.returncode == 0 and result.stdout.strip():
        return [ROOT / line for line in result.stdout.splitlines() if line]
    return [path for path in ROOT.rglob("*") if path.is_file() and ".git" not in path.parts]


def validate_content_boundaries(failures: list[str]) -> None:
    files = project_files()
    for path in files:
        relative = path.relative_to(ROOT)
        lowered_name = path.name.casefold()
        if path.suffix.casefold() in PRIVATE_KEY_SUFFIXES or lowered_name in PRIVATE_KEY_NAMES:
            failures.append(f"prohibited private-key filename: {relative}")
        try:
            content = path.read_text(encoding="utf-8")
        except (OSError, UnicodeError):
            continue
        folded = content.casefold()
        for forbidden in FORBIDDEN_STRINGS:
            if forbidden.casefold() in folded:
                failures.append(f"forbidden disclosure string in {relative}: {forbidden}")


def main() -> int:
    failures: list[str] = []
    validate_required_files(failures)
    json_count = validate_all_json(failures)
    validate_cases(failures)
    validate_devpost(failures)
    validate_schema(failures)
    validate_sample(failures)
    validate_content_boundaries(failures)

    if failures:
        print(f"FAIL: FixRepro Phase 1 scaffold has {len(failures)} error(s):")
        for failure in failures:
            print(f"- {failure}")
        return 1

    print("PASS: FixRepro Phase 1 scaffold is valid.")
    print(f"Checked {len(REQUIRED_FILES)} required files and {json_count} JSON documents.")
    print("Case contracts, evidence outcomes, SHA-256 formats, content boundaries, and Devpost limits passed.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
