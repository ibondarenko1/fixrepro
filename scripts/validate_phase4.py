#!/usr/bin/env python3
"""Validate the Phase 4 dashboard and container safety contracts."""

from __future__ import annotations

import re
import subprocess
import sys
import tomllib
from html.parser import HTMLParser
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
REQUIRED_FILES = (
    "app/__init__.py",
    "app/main.py",
    "app/models.py",
    "app/jobs.py",
    "app/presentation.py",
    "app/security.py",
    "app/static/index.html",
    "app/static/styles.css",
    "app/static/app.js",
    "scripts/run_dashboard.py",
    "scripts/run_phase4_smoke.py",
    "scripts/validate_phase4.py",
    "docs/DASHBOARD.md",
    "docs/DOCKER.md",
    "Dockerfile",
    "docker-compose.yml",
    ".dockerignore",
)
REQUIRED_PATHS = (
    '"/"',
    '"/health"',
    '"/api/v1/demo"',
    '"/api/v1/verifications"',
    '"/api/v1/verifications/{job_id}"',
    '"/api/v1/bundles/{bundle_id}/report"',
    '"/api/v1/bundles/{bundle_id}/evidence"',
    '"/api/v1/bundles/{bundle_id}/manifest"',
    '"/api/v1/bundles/{bundle_id}/digest"',
)
REQUIRED_COPY = (
    "FixRepro",
    "Prove the patch. Preserve the feature.",
    "FixRepro replays the exact same security input against vulnerable and patched IoT builds, verifies that legitimate behavior still works, and publishes tamper-evident evidence.",
    "Run live verification",
    "Load verified demo",
    "PATCH VERIFIED",
    "UNSAFE BEHAVIOR REPRODUCED",
    "PATCH BLOCKED SAME INPUT",
    "LEGITIMATE UPDATE PRESERVED",
    "Exact same input replayed",
    "Tamper-evident evidence bundle",
    "What this result proves",
)
TEST_IDS = (
    "overall-outcome",
    "source-indicator",
    "run-verification",
    "load-demo",
    "live-status",
    "vulnerable-card",
    "patched-card",
    "positive-control-card",
    "same-input-status",
    "envelope-sha256",
    "request-sha256",
    "manifest-sha256",
    "report-link",
    "evidence-link",
    "manifest-link",
    "digest-link",
    "error-message",
)
ALLOWED_DEPENDENCIES = {
    "fastapi",
    "uvicorn",
    "pydantic",
    "cryptography",
    "httpx",
    "jsonschema",
}
PRIVATE_SUFFIXES = {".key", ".p12", ".pfx"}
PRIVATE_HEADERS = tuple(
    "-----BEGIN " + prefix + "PRIVATE KEY-----"
    for prefix in ("", "RSA ", "EC ", "OPENSSH ", "ENCRYPTED ")
)
FORBIDDEN_MATERIAL = (
    "V" + "INCE",
    "G" + "HSA-",
    "C" + "VE-",
    "SUMMIT " + "AI TECH",
)
WINDOWS_PROFILE_PATTERN = r"(?i)" + "C:" + r"\\Users\\[^\\\s]+"


class IndexInspector(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.html_language: str | None = None
        self.h1_count = 0

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        attributes = dict(attrs)
        if tag == "html":
            self.html_language = attributes.get("lang")
        if tag == "h1":
            self.h1_count += 1


def dependency_name(specification: str) -> str:
    return re.split(r"[<>=!~;\s\[]", specification, maxsplit=1)[0].lower()


def project_files() -> list[Path]:
    try:
        result = subprocess.run(
            ["git", "ls-files", "--cached", "--others", "--exclude-standard"],
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


def validate_files(failures: list[str]) -> None:
    for relative in REQUIRED_FILES:
        if not (ROOT / relative).is_file():
            failures.append(f"missing Phase 4 file: {relative}")
    if (ROOT / "app" / ".gitkeep").exists():
        failures.append("app/.gitkeep must be removed after application source exists")


def validate_pyproject(failures: list[str]) -> None:
    try:
        document = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    except (OSError, UnicodeError, tomllib.TOMLDecodeError) as exc:
        failures.append(f"pyproject.toml cannot be parsed: {exc}")
        return
    project = document.get("project", {})
    if project.get("version") != "0.4.0":
        failures.append("project version must be 0.4.0")
    dependencies = {
        dependency_name(value)
        for value in project.get("dependencies", [])
        if isinstance(value, str)
    }
    unexpected = sorted(dependencies - ALLOWED_DEPENDENCIES)
    if unexpected:
        failures.append("unnecessary Phase 4 dependencies were added: " + ", ".join(unexpected))
    include = (
        document.get("tool", {})
        .get("setuptools", {})
        .get("packages", {})
        .get("find", {})
        .get("include", [])
    )
    if not any(isinstance(value, str) and value.startswith("app") for value in include):
        failures.append("setuptools package discovery must include app")


def validate_application(failures: list[str]) -> None:
    source = (ROOT / "app" / "main.py").read_text(encoding="utf-8")
    combined = "\n".join(
        (ROOT / "app" / name).read_text(encoding="utf-8")
        for name in ("main.py", "jobs.py", "presentation.py", "security.py")
    )
    for path in REQUIRED_PATHS:
        if path not in source:
            failures.append(f"dashboard route is missing: {path}")
    if "CORSMiddleware" in combined or "allow_origins" in combined:
        failures.append("CORS middleware is prohibited")
    if re.search(r'@application\.(?:get|post)\([^\n]*\{(?:path|filename|file_path)\}', source):
        failures.append("generic arbitrary-file routes are prohibited")
    if "UploadFile" in combined or "/upload" in combined:
        failures.append("upload endpoints are prohibited")
    if "output_argument=" in (ROOT / "app" / "jobs.py").read_text(encoding="utf-8"):
        failures.append("dashboard jobs must not provide a browser-controlled output path")
    security = (ROOT / "app" / "security.py").read_text(encoding="utf-8")
    if "script-src 'self'" not in security or "frame-ancestors 'none'" not in security:
        failures.append("normal dashboard CSP is incomplete")
    dashboard_block = security.partition("DASHBOARD_CSP")[2].partition("REPORT_CSP")[0]
    if "script-src 'unsafe-inline'" in dashboard_block:
        failures.append("normal dashboard CSP must not allow inline scripts")
    report_block = security.partition("REPORT_CSP")[2].partition("class SecurityHeadersMiddleware")[0]
    if "style-src 'unsafe-inline'" not in report_block or "script-src" in report_block:
        failures.append("report CSP must allow inline style and no script")


def validate_frontend(failures: list[str]) -> None:
    index = (ROOT / "app" / "static" / "index.html").read_text(encoding="utf-8")
    css = (ROOT / "app" / "static" / "styles.css").read_text(encoding="utf-8")
    script = (ROOT / "app" / "static" / "app.js").read_text(encoding="utf-8")
    presentation = (ROOT / "app" / "presentation.py").read_text(encoding="utf-8")
    for phrase in REQUIRED_COPY:
        if phrase not in index and phrase not in script and phrase not in presentation:
            failures.append(f"dashboard copy is missing: {phrase}")
    for test_id in TEST_IDS:
        if f'data-testid="{test_id}"' not in index:
            failures.append(f"dashboard test selector is missing: {test_id}")
    inspector = IndexInspector()
    inspector.feed(index)
    if inspector.html_language != "en":
        failures.append('index.html must set lang="en"')
    if inspector.h1_count != 1:
        failures.append("index.html must contain exactly one h1")
    for path, content in (("index.html", index), ("styles.css", css), ("app.js", script)):
        if re.search(r"(?i)(?:https?:)?//[a-z]", content):
            failures.append(f"static frontend file contains an external URL: {path}")
    prohibited = (
        ("inner" + "HTML", "dynamic HTML assignment"),
        ("insertAdjacent" + "HTML", "adjacent HTML insertion"),
        ("ev" + "al(", "dynamic evaluation"),
        ("new " + "Function", "dynamic function construction"),
    )
    for marker, label in prohibited:
        if marker in script:
            failures.append(f"app.js contains prohibited {label}")


def validate_docker(failures: list[str]) -> None:
    dockerfile = (ROOT / "Dockerfile").read_text(encoding="utf-8")
    compose = (ROOT / "docker-compose.yml").read_text(encoding="utf-8")
    ignore = {
        line.strip()
        for line in (ROOT / ".dockerignore").read_text(encoding="utf-8").splitlines()
        if line.strip() and not line.lstrip().startswith("#")
    }
    if "FROM python:3.12-slim" not in dockerfile:
        failures.append("Dockerfile must use python:3.12-slim")
    if not re.search(r"(?m)^USER\s+(?:10001(?::10001)?|fixrepro)\s*$", dockerfile):
        failures.append("Dockerfile must switch to a non-root user")
    if ".[dev]" in dockerfile:
        failures.append("Dockerfile must not install development dependencies")
    if 'scripts/run_dashboard.py", "--host", "0.0.0.0", "--port", "8000"' not in dockerfile:
        failures.append("Dockerfile must run the dashboard in guarded container mode")
    published = re.findall(r'"([^"]+:\d+:\d+)"', compose)
    if published != ["127.0.0.1:8000:8000"]:
        failures.append("Compose must publish only 127.0.0.1:8000:8000")
    child_ports = tuple(str(8100 + offset) for offset in (1, 2)) + (str(820 * 10),)
    for port in child_ports:
        if re.search(rf"(?m)^\s*-\s*\"?[^\n]*:{port}(?::|\"|$)", compose):
            failures.append(f"Compose must not publish child service port {port}")
    if re.search(r"(?m)^\s*privileged\s*:\s*true", compose, re.IGNORECASE):
        failures.append("Compose must not use privileged mode")
    if re.search(r"(?m)^\s*network_mode\s*:\s*host", compose, re.IGNORECASE):
        failures.append("Compose must not use host networking")
    required_ignores = {".git", ".venv", ".runtime", "evidence/runs"}
    missing = sorted(required_ignores - ignore)
    if missing:
        failures.append(".dockerignore is missing: " + ", ".join(missing))
    if "evidence/demo-bundle" in ignore or "evidence" in ignore:
        failures.append(".dockerignore must include the tracked demo bundle")
    if "*.pem" in ignore and "!evidence/demo-bundle/trust/trusted-public-key.pem" not in ignore:
        failures.append("the tracked demo public key must not be excluded from Docker")


def validate_safety(failures: list[str]) -> None:
    for path in project_files():
        relative = path.relative_to(ROOT)
        if path.suffix.casefold() in PRIVATE_SUFFIXES:
            failures.append(f"private-key extension is prohibited: {relative}")
        try:
            content = path.read_text(encoding="utf-8")
        except (OSError, UnicodeError):
            continue
        for header in PRIVATE_HEADERS:
            if re.search(rf"(?m)^{re.escape(header)}\r?$", content):
                failures.append(f"private-key PEM header found: {relative}")
        folded = content.casefold()
        for marker in FORBIDDEN_MATERIAL:
            if marker.casefold() in folded:
                failures.append(f"real or private vulnerability material found: {relative}")
        if re.search(WINDOWS_PROFILE_PATTERN, content):
            failures.append(f"hard-coded Windows profile path found: {relative}")


def validate_readme(failures: list[str]) -> None:
    content = (ROOT / "README.md").read_text(encoding="utf-8")
    implemented = (
        "Web dashboard",
        "Control API",
        "Verified demo-bundle loading",
        "Background live verification",
        "Safe artifact serving",
        "Docker Compose",
        "GitHub Actions",
    )
    for phrase in implemented:
        if phrase not in content:
            failures.append(f"README is missing implemented Phase 4 feature: {phrase}")
    for stale_phrase in ("Implemented Phase 4 product", "Phase 5A", "Final video recording"):
        if stale_phrase in content:
            failures.append(f"README contains stale internal status language: {stale_phrase}")


def main() -> int:
    failures: list[str] = []
    validate_files(failures)
    validate_pyproject(failures)
    validate_application(failures)
    validate_frontend(failures)
    validate_docker(failures)
    validate_safety(failures)
    validate_readme(failures)
    if failures:
        print(f"FAIL: FixRepro Phase 4 validation found {len(failures)} error(s):")
        for failure in failures:
            print(f"- {failure}")
        return 1
    print("PASS: FixRepro Phase 4 dashboard and container contracts are valid.")
    print(f"Checked {len(REQUIRED_FILES)} required Phase 4 files.")
    print("Routes, frontend, CSP, Docker topology, and safety boundaries passed.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
