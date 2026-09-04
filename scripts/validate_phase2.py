#!/usr/bin/env python3
"""Validate Phase 2 structure and safety boundaries with the standard library."""

from __future__ import annotations

import re
import subprocess
import sys
import tomllib
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]

REQUIRED_FILES = (
    "pyproject.toml",
    "fixrepro_core/__init__.py",
    "fixrepro_core/config.py",
    "fixrepro_core/models.py",
    "fixrepro_core/package.py",
    "fixrepro_core/crypto.py",
    "fixrepro_core/evaluation.py",
    "fixrepro_core/device_client.py",
    "fixrepro_core/artifacts.py",
    "fixrepro_core/gateway.py",
    "device/__init__.py",
    "device/app.py",
    "device/state.py",
    "targets/__init__.py",
    "targets/vulnerable/__init__.py",
    "targets/vulnerable/app.py",
    "targets/patched/__init__.py",
    "targets/patched/app.py",
    "scripts/generate_demo_artifacts.py",
    "scripts/run_phase2_demo.py",
    "scripts/validate_phase2.py",
    "tests/test_package.py",
    "tests/test_policies.py",
    "tests/test_device.py",
)

REQUIRED_DEPENDENCIES = {"fastapi", "uvicorn", "pydantic", "cryptography", "httpx"}
REQUIRED_REASON_CODES = {
    "CHECKSUM_ONLY_ACCEPTED",
    "TRUSTED_SIGNATURE_ACCEPTED",
    "UNTRUSTED_SIGNER",
    "PAYLOAD_HASH_MISMATCH",
    "PAYLOAD_SIZE_MISMATCH",
    "SIGNER_FINGERPRINT_MISMATCH",
    "INVALID_SIGNATURE",
    "MALFORMED_PACKAGE",
    "DEVICE_UNAVAILABLE",
    "DEVICE_APPLY_FAILED",
}
PROHIBITED_KEY_SUFFIXES = {".key", ".p12", ".pfx"}
PROHIBITED_KEY_NAMES = {"id_" + "rsa", "id_" + "ed25519"}
PRIVATE_PEM_HEADERS = tuple(
    "-----BEGIN " + prefix + "PRIVATE KEY-----"
    for prefix in ("", "RSA ", "EC ", "OPENSSH ")
)
EXPECTED_PORTS = {
    str(8100 + 1),
    str(8100 + 2),
    str(820 * 10),
}


def tracked_files() -> list[Path]:
    try:
        result = subprocess.run(
            ["git", "ls-files"],
            cwd=ROOT,
            check=False,
            capture_output=True,
            text=True,
            encoding="utf-8",
        )
    except OSError:
        return []
    if result.returncode != 0:
        return []
    return [ROOT / line for line in result.stdout.splitlines() if line]


def project_text_files() -> list[Path]:
    ignored_roots = {".git", ".venv", ".runtime", "__pycache__"}
    files: list[Path] = []
    for path in ROOT.rglob("*"):
        if not path.is_file() or any(
            part in ignored_roots or part.endswith(".egg-info") for part in path.parts
        ):
            continue
        try:
            path.read_text(encoding="utf-8")
        except (OSError, UnicodeError):
            continue
        files.append(path)
    return files


def dependency_name(specification: str) -> str:
    return re.split(r"[<>=!~;\s\[]", specification, maxsplit=1)[0].lower()


def validate_files(failures: list[str]) -> None:
    for relative in REQUIRED_FILES:
        if not (ROOT / relative).is_file():
            failures.append(f"missing Phase 2 file: {relative}")


def validate_pyproject(failures: list[str]) -> None:
    path = ROOT / "pyproject.toml"
    try:
        document = tomllib.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, tomllib.TOMLDecodeError) as exc:
        failures.append(f"pyproject.toml cannot be parsed: {exc}")
        return

    project = document.get("project", {})
    requires_python = project.get("requires-python")
    if not isinstance(requires_python, str) or not re.search(r">=\s*3\.1[2-9]", requires_python):
        failures.append("pyproject.toml must require Python 3.12 or newer")

    dependencies = project.get("dependencies", [])
    declared = {
        dependency_name(value)
        for value in dependencies
        if isinstance(value, str) and dependency_name(value)
    }
    missing = sorted(REQUIRED_DEPENDENCIES - declared)
    if missing:
        failures.append("missing runtime dependencies: " + ", ".join(missing))

    development = project.get("optional-dependencies", {}).get("dev", [])
    dev_names = {
        dependency_name(value)
        for value in development
        if isinstance(value, str) and dependency_name(value)
    }
    if "pytest" not in dev_names:
        failures.append("pytest must be declared in the dev dependency group")


def validate_gitignore(failures: list[str]) -> None:
    try:
        lines = {
            line.strip()
            for line in (ROOT / ".gitignore").read_text(encoding="utf-8").splitlines()
        }
    except (OSError, UnicodeError) as exc:
        failures.append(f"cannot read .gitignore: {exc}")
        return
    if ".runtime/" not in lines:
        failures.append(".gitignore must contain .runtime/")


def validate_service_contracts(failures: list[str]) -> None:
    expected = {
        "device/app.py": ("/health", "/api/v1/state", "/api/v1/reset", "/api/v1/apply"),
        "targets/vulnerable/app.py": ("/health", "/api/v1/updates"),
        "targets/patched/app.py": ("/health", "/api/v1/updates"),
    }
    for relative, paths in expected.items():
        path = ROOT / relative
        if not path.is_file():
            continue
        content = path.read_text(encoding="utf-8")
        for api_path in paths:
            if api_path not in content:
                failures.append(f"{relative} is missing API path {api_path}")


def validate_port_locations(failures: list[str]) -> None:
    allowed_exact = {
        Path(".github/workflows/ci.yml"),
        Path("fixrepro_core/config.py"),
        Path("scripts/run_phase2_demo.py"),
        Path("scripts/validate_phase4.py"),
        Path("evidence/sample-evidence.json"),
    }
    for path in project_text_files():
        relative = path.relative_to(ROOT)
        allowed = relative in allowed_exact or path.suffix.lower() == ".md"
        if allowed:
            continue
        content = path.read_text(encoding="utf-8")
        found = sorted(port for port in EXPECTED_PORTS if port in content)
        if found:
            failures.append(
                f"service port(s) {', '.join(found)} appear outside configuration, documentation, or runner code: {relative}"
            )


def validate_tracked_safety(failures: list[str]) -> None:
    for path in tracked_files():
        relative = path.relative_to(ROOT)
        if relative.parts and relative.parts[0] == ".runtime":
            failures.append(f"tracked runtime file is prohibited: {relative}")
        if path.suffix.lower() in PROHIBITED_KEY_SUFFIXES or path.name.lower() in PROHIBITED_KEY_NAMES:
            failures.append(f"tracked private-key file type is prohibited: {relative}")
        try:
            content = path.read_text(encoding="utf-8")
        except (OSError, UnicodeError):
            continue
        for header in PRIVATE_PEM_HEADERS:
            if header in content:
                failures.append(f"private-key PEM header found in tracked file: {relative}")


def validate_reason_codes(failures: list[str]) -> None:
    source_paths = (
        ROOT / "fixrepro_core" / "evaluation.py",
        ROOT / "fixrepro_core" / "gateway.py",
        ROOT / "targets" / "vulnerable" / "app.py",
        ROOT / "targets" / "patched" / "app.py",
    )
    combined = "\n".join(
        path.read_text(encoding="utf-8") for path in source_paths if path.is_file()
    )
    missing = sorted(code for code in REQUIRED_REASON_CODES if code not in combined)
    if missing:
        failures.append("required reason codes are missing: " + ", ".join(missing))


def validate_runner(failures: list[str]) -> None:
    path = ROOT / "scripts" / "run_phase2_demo.py"
    if not path.is_file():
        return
    content = path.read_text(encoding="utf-8")
    required_fragments = {
        '"1.0.0"',
        '"9.9.0-test"',
        '"1.1.0"',
        '"CHECKSUM_ONLY_ACCEPTED"',
        '"UNTRUSTED_SIGNER"',
        '"TRUSTED_SIGNATURE_ACCEPTED"',
        '"PHASE2_CONTRACT_PASS"',
        '"--repeat"',
    }
    missing = sorted(fragment for fragment in required_fragments if fragment not in content)
    if missing:
        failures.append("demonstration runner is missing contract fragments: " + ", ".join(missing))


def validate_readme(failures: list[str]) -> None:
    content = (ROOT / "README.md").read_text(encoding="utf-8")
    implemented = (
        "Virtual device",
        "Vulnerable gateway",
        "Patched gateway",
        "Ed25519 package generation",
        "Three-scenario demonstration runner",
        "Unit tests",
    )
    for phrase in implemented:
        if phrase not in content:
            failures.append(f"README is missing implemented Phase 2 component: {phrase}")

    if "Current status" not in content:
        failures.append("README must describe the current implementation status")


def main() -> int:
    failures: list[str] = []
    validate_files(failures)
    validate_pyproject(failures)
    validate_gitignore(failures)
    validate_service_contracts(failures)
    validate_port_locations(failures)
    validate_tracked_safety(failures)
    validate_reason_codes(failures)
    validate_runner(failures)
    validate_readme(failures)

    if failures:
        print(f"FAIL: FixRepro Phase 2 validation found {len(failures)} error(s):")
        for failure in failures:
            print(f"- {failure}")
        return 1

    print("PASS: FixRepro Phase 2 structure and safety boundaries are valid.")
    print(f"Checked {len(REQUIRED_FILES)} required Phase 2 source files.")
    print("Dependencies, local service contracts, reason codes, runtime isolation, and key safety passed.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
