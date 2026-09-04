#!/usr/bin/env python3
"""Validate Phase 3 structure and safety using only the standard library."""

from __future__ import annotations

import re
import subprocess
import sys
import tomllib
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
REQUIRED_FILES = (
    "verifier/__init__.py",
    "verifier/models.py",
    "verifier/verdicts.py",
    "verifier/processes.py",
    "verifier/orchestrator.py",
    "verifier/evidence.py",
    "verifier/bundle.py",
    "verifier/report.py",
    "scripts/run_verification.py",
    "scripts/verify_bundle.py",
    "scripts/validate_phase3.py",
    "docs/EVIDENCE_FORMAT.md",
    "docs/VERIFICATION_LOGIC.md",
)
REQUIRED_REPORT_LABELS = (
    "UNSAFE BEHAVIOR REPRODUCED",
    "PATCH BLOCKED SAME INPUT",
    "LEGITIMATE UPDATE PRESERVED",
    "PATCH VERIFIED",
)
REQUIRED_OUTCOMES = ("PATCH_VERIFIED", "PATCH_NOT_VERIFIED", "INCONCLUSIVE")
PRIVATE_KEY_SUFFIXES = {".key", ".p12", ".pfx"}
PRIVATE_HEADERS = tuple(
    "-----BEGIN " + prefix + "PRIVATE KEY-----"
    for prefix in ("", "RSA ", "EC ", "OPENSSH ", "ENCRYPTED ")
)
FORBIDDEN_STRINGS = (
    "V" + "INCE",
    "G" + "HSA-",
    "C" + "VE-",
    "SUMMIT " + "AI TECH",
)
WINDOWS_PROFILE_PATTERN = r"(?i)" + "C:" + r"\\Users\\[^\\\s]+"


def run_git(*arguments: str) -> subprocess.CompletedProcess[str] | None:
    try:
        return subprocess.run(
            ["git", *arguments],
            cwd=ROOT,
            check=False,
            capture_output=True,
            text=True,
            encoding="utf-8",
        )
    except OSError:
        return None


def tracked_files() -> list[Path]:
    result = run_git("ls-files")
    if result is None or result.returncode != 0:
        return []
    return [ROOT / line for line in result.stdout.splitlines() if line]


def dependency_name(specification: str) -> str:
    return re.split(r"[<>=!~;\s\[]", specification, maxsplit=1)[0].lower()


def validate_files(failures: list[str]) -> None:
    for relative in REQUIRED_FILES:
        if not (ROOT / relative).is_file():
            failures.append(f"missing Phase 3 file: {relative}")
    if (ROOT / "verifier" / ".gitkeep").exists():
        failures.append("verifier/.gitkeep must be removed after source files exist")


def validate_configuration(failures: list[str]) -> None:
    try:
        document = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    except (OSError, UnicodeError, tomllib.TOMLDecodeError) as exc:
        failures.append(f"pyproject.toml cannot be parsed: {exc}")
        return
    dependencies = {
        dependency_name(value)
        for value in document.get("project", {}).get("dependencies", [])
        if isinstance(value, str)
    }
    if "jsonschema" not in dependencies:
        failures.append("jsonschema must be declared as a runtime dependency")
    include = document.get("tool", {}).get("setuptools", {}).get("packages", {}).get("find", {}).get("include", [])
    if not any(isinstance(value, str) and value.startswith("verifier") for value in include):
        failures.append("setuptools package discovery must include verifier")


def validate_ignore_rules(failures: list[str]) -> None:
    lines = {
        line.strip()
        for line in (ROOT / ".gitignore").read_text(encoding="utf-8").splitlines()
    }
    if "evidence/runs/" not in lines:
        failures.append("evidence/runs/ must remain ignored")
    for probe in (
        "evidence/demo-bundle/report.html",
        "evidence/demo-bundle/trust/trusted-public-key.pem",
    ):
        check_demo = run_git("check-ignore", probe)
        if check_demo is not None and check_demo.returncode == 0:
            failures.append(f"tracked demo bundle file must not be ignored: {probe}")


def validate_tracked_safety(failures: list[str]) -> None:
    for path in tracked_files():
        relative = path.relative_to(ROOT)
        if relative.parts[:2] == ("evidence", "runs"):
            failures.append(f"tracked generated run is prohibited: {relative}")
        if path.suffix.casefold() in PRIVATE_KEY_SUFFIXES:
            failures.append(f"tracked private-key extension is prohibited: {relative}")
        try:
            content = path.read_text(encoding="utf-8")
        except (OSError, UnicodeError):
            continue
        for header in PRIVATE_HEADERS:
            if re.search(rf"(?m)^{re.escape(header)}\r?$", content):
                failures.append(f"private-key PEM header found: {relative}")
        folded = content.casefold()
        for forbidden in FORBIDDEN_STRINGS:
            if forbidden.casefold() in folded:
                failures.append(f"forbidden private or real-vulnerability material in {relative}")
        if re.search(WINDOWS_PROFILE_PATTERN, content):
            failures.append(f"hard-coded user profile path found: {relative}")


def validate_report(failures: list[str]) -> None:
    source = (ROOT / "verifier" / "report.py").read_text(encoding="utf-8")
    for value in ("http://", "https://", "<script", "url("):
        if value.casefold() in source.casefold():
            failures.append(f"report generator contains an external dependency marker: {value}")
    for label in REQUIRED_REPORT_LABELS:
        if label not in source:
            failures.append(f"report generator is missing visible label: {label}")


def validate_source_contracts(failures: list[str]) -> None:
    models = (ROOT / "verifier" / "models.py").read_text(encoding="utf-8")
    verdicts = (ROOT / "verifier" / "verdicts.py").read_text(encoding="utf-8")
    bundle = (ROOT / "verifier" / "bundle.py").read_text(encoding="utf-8")
    verifier_cli = (ROOT / "scripts" / "verify_bundle.py").read_text(encoding="utf-8")
    combined = "\n".join((models, verdicts, bundle, verifier_cli))
    for outcome in REQUIRED_OUTCOMES:
        if outcome not in combined:
            failures.append(f"required outcome is missing from Phase 3 source: {outcome}")
    if "calculate_verification_outcome" not in bundle:
        failures.append("bundle verifier must recompute deterministic verdicts")
    if "MANIFEST_NAME, MANIFEST_DIGEST_NAME" not in bundle:
        failures.append("bundle manifest generation must exclude both manifest files")
    run_cli = (ROOT / "scripts" / "run_verification.py").read_text(encoding="utf-8")
    if "ROOT = Path(__file__).resolve().parents[1]" not in run_cli:
        failures.append("run_verification.py must anchor paths to the repository")
    if "ROOT = Path(__file__).resolve().parents[1]" not in verifier_cli:
        failures.append("verify_bundle.py must anchor paths to the repository")


def validate_readme(failures: list[str]) -> None:
    content = (ROOT / "README.md").read_text(encoding="utf-8")
    implemented = (
        "Verification orchestrator",
        "Evidence bundle",
        "HTML report",
        "Bundle verification",
    )
    unimplemented = ("GitHub Actions",)
    for phrase in implemented:
        if phrase not in content:
            failures.append(f"README is missing implemented Phase 3 feature: {phrase}")
    planned = content.partition("## Not implemented yet")[2]
    for phrase in unimplemented:
        if phrase not in planned:
            failures.append(f"README must keep unimplemented feature in the planned section: {phrase}")


def main() -> int:
    failures: list[str] = []
    validate_files(failures)
    validate_configuration(failures)
    validate_ignore_rules(failures)
    validate_tracked_safety(failures)
    validate_report(failures)
    validate_source_contracts(failures)
    validate_readme(failures)
    if failures:
        print(f"FAIL: FixRepro Phase 3 validation found {len(failures)} error(s):")
        for failure in failures:
            print(f"- {failure}")
        return 1
    print("PASS: FixRepro Phase 3 structure and safety boundaries are valid.")
    print(f"Checked {len(REQUIRED_FILES)} required Phase 3 files.")
    print("Evidence, report, manifest, verifier, packaging, and safety contracts passed.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
