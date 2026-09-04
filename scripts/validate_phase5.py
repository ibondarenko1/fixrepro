#!/usr/bin/env python3
"""Validate the frozen Phase 5A submission package with the standard library."""

from __future__ import annotations

import json
import re
import struct
import subprocess
import sys
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
EXPECTED_DEMO_DIGEST = "10fd80148896935b10fd1ccfd056e345d9a4537dff35473c4a025b9dbcab0204"
PNG_SIGNATURE = b"\x89PNG\r\n\x1a\n"
SCREENSHOTS = {
    "docs/submission/screenshots/01-dashboard-overview.png": (1440, 1000),
    "docs/submission/screenshots/02-dashboard-full.png": (1440, 2600),
    "docs/submission/screenshots/03-verification-report.png": (1440, 2000),
    "docs/submission/screenshots/04-mobile-dashboard.png": (390, 844),
}
REQUIRED_FILES = (
    ".github/workflows/ci.yml",
    "scripts/capture_submission_screenshots.py",
    "scripts/validate_phase5.py",
    "devpost/final_submission.json",
    "docs/submission/README.md",
    "docs/submission/DEVPOST_FINAL.md",
    "docs/submission/VIDEO_SCRIPT.md",
    "docs/submission/VIDEO_SHOT_LIST.md",
    "docs/submission/CAPTIONS.srt",
    "docs/submission/JUDGE_QA.md",
    "docs/submission/SCREENSHOTS.md",
    "docs/submission/SUBMISSION_CHECKLIST.md",
    *SCREENSHOTS,
)
TECHNOLOGIES = {
    "Python 3.12",
    "FastAPI",
    "Pydantic",
    "Ed25519",
    "cryptography",
    "HTTPX",
    "JSON Schema Draft 2020-12",
    "pytest",
    "Plain HTML",
    "CSS",
    "JavaScript",
    "Docker",
    "Docker Compose",
    "GitHub Actions",
}
DEVPOST_SECTIONS = (
    "Project name",
    "Tagline",
    "Inspiration",
    "What it does",
    "How it works",
    "How we built it",
    "Challenges",
    "Accomplishments",
    "What we learned",
    "What is next",
    "Built with",
    "Try it out",
    "Development declaration",
    "Safety and limitations",
    "Suggested screenshot captions",
)
PRIVATE_SUFFIXES = {".key", ".p12", ".pfx"}
VIDEO_SUFFIXES = {".mp4", ".mov", ".avi", ".mkv", ".webm"}
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


def load_json(relative: str, failures: list[str]) -> dict[str, Any]:
    try:
        value = json.loads((ROOT / relative).read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        failures.append(f"{relative} is invalid JSON: {exc}")
        return {}
    if not isinstance(value, dict):
        failures.append(f"{relative} must contain a JSON object")
        return {}
    return value


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
            failures.append(f"missing Phase 5A file: {relative}")


def validate_metadata(failures: list[str]) -> None:
    overview = load_json("devpost/overview.json", failures)
    final = load_json("devpost/final_submission.json", failures)
    if overview.get("implementation_status") == "phase_1_scaffold":
        failures.append("Devpost implementation status still claims Phase 1")
    submission = overview.get("submission_status")
    if submission != "ready_for_manual_devpost_entry":
        failures.append("submission status must remain ready for manual entry")
    if overview.get("technologies_planned") != []:
        failures.append("technologies_planned must be empty")
    technologies = overview.get("technologies_used")
    if not isinstance(technologies, list) or set(technologies) != TECHNOLOGIES:
        failures.append("technologies_used must list exactly the implemented stack")
    for field, limit in (("project_name", 60), ("elevator_pitch", 200), ("problem_statement", 255)):
        value = overview.get(field)
        if not isinstance(value, str) or len(value) > limit:
            failures.append(f"{field} must be a string of no more than {limit} characters")
    if overview.get("screenshot_files") != list(SCREENSHOTS):
        failures.append("overview screenshot_files must list the four screenshots in order")
    if final.get("image_files") != list(SCREENSHOTS):
        failures.append("final submission image_files must list the four screenshots in order")
    if final.get("video_status") != "script_ready_recording_pending":
        failures.append("final submission must not claim that a video exists")


def validate_screenshots(failures: list[str]) -> None:
    for relative, expected in SCREENSHOTS.items():
        path = ROOT / relative
        if not path.is_file():
            continue
        content = path.read_bytes()
        if len(content) < 24 or not content.startswith(PNG_SIGNATURE) or content[12:16] != b"IHDR":
            failures.append(f"invalid PNG structure: {relative}")
            continue
        dimensions = struct.unpack(">II", content[16:24])
        if any(abs(actual - target) > 16 for actual, target in zip(dimensions, expected, strict=True)):
            failures.append(f"{relative} has dimensions {dimensions}, expected approximately {expected}")
        if len(content) < 20_000:
            failures.append(f"screenshot is too small to contain useful content: {relative}")
        if len(content) >= 5 * 1024 * 1024:
            failures.append(f"screenshot exceeds 5 MB: {relative}")


def validate_readme(failures: list[str]) -> None:
    content = (ROOT / "README.md").read_text(encoding="utf-8")
    if "docs/submission/screenshots/01-dashboard-overview.png" not in content:
        failures.append("README must display the dashboard overview screenshot")
    if "actions/workflows/ci.yml/badge.svg" not in content:
        failures.append("README must contain the CI badge")


def validate_workflow(failures: list[str]) -> None:
    path = ROOT / ".github/workflows/ci.yml"
    if not path.is_file():
        return
    content = path.read_text(encoding="utf-8")
    actions = re.findall(r"(?m)^\s*uses:\s*([^\s]+)", content)
    allowed = {"actions/checkout@v4", "actions/setup-python@v5"}
    if set(actions) - allowed:
        failures.append("CI uses an unapproved action: " + ", ".join(sorted(set(actions) - allowed)))
    if "pull_request_target" in content:
        failures.append("CI must not use pull_request_target")
    if re.search(r"(?i)(?:secrets\.|\$\{\{\s*secrets)", content):
        failures.append("CI must not reference repository secrets")
    if not re.search(r"(?ms)^permissions:\s*\n\s+contents:\s*read\s*$", content):
        failures.append("CI permissions must be contents: read")
    if not re.search(r"(?m)^\s{2}quality:\s*$", content) or not re.search(r"(?m)^\s{2}docker:\s*$", content):
        failures.append("CI must define quality and docker jobs")
    for validator in (
        "validate_scaffold.py",
        "validate_phase2.py",
        "validate_phase3.py",
        "validate_phase4.py",
        "validate_phase5.py",
    ):
        if validator not in content:
            failures.append(f"CI does not run {validator}")
    for marker in ("python -m pytest -q", "verify_bundle.py evidence/demo-bundle", "run_phase4_smoke.py"):
        if marker not in content:
            failures.append(f"CI is missing required command: {marker}")
    if not re.search(r"(?ms)name:\s*Stop containers.*?if:\s*always\(\)", content):
        failures.append("Docker cleanup must use an always condition")
    prohibited = ("docker push", "gh release", "deploy", "registry login")
    for marker in prohibited:
        if marker in content.casefold():
            failures.append(f"CI contains prohibited publish or deployment marker: {marker}")


def validate_copy(failures: list[str]) -> None:
    devpost = (ROOT / "docs/submission/DEVPOST_FINAL.md").read_text(encoding="utf-8")
    for section in DEVPOST_SECTIONS:
        if f"## {section}" not in devpost:
            failures.append(f"DEVPOST_FINAL.md is missing section: {section}")
    combined = "\n".join(
        (ROOT / relative).read_text(encoding="utf-8")
        for relative in REQUIRED_FILES
        if relative.endswith((".md", ".srt", ".json", ".yml", ".py"))
        and (ROOT / relative).is_file()
    )
    placeholders = ("TO" + "DO", "T" + "BD", "lorem" + " ipsum", "IN" + "SERT")
    if any(re.search(rf"(?i)\b{re.escape(marker)}\b", combined) for marker in placeholders):
        failures.append("submission package contains a placeholder marker")


def script_word_count() -> int:
    content = (ROOT / "docs/submission/VIDEO_SCRIPT.md").read_text(encoding="utf-8")
    spoken = "\n".join(line for line in content.splitlines() if not line.startswith("#"))
    return len(re.findall(r"\b[\w'-]+\b", spoken, flags=re.UNICODE))


def parse_srt_timestamp(value: str) -> int:
    hours, minutes, rest = value.split(":")
    seconds, milliseconds = rest.split(",")
    return (((int(hours) * 60 + int(minutes)) * 60) + int(seconds)) * 1000 + int(milliseconds)


def validate_video_materials(failures: list[str]) -> None:
    words = script_word_count()
    if not 190 <= words <= 220:
        failures.append(f"video script contains {words} words; expected 190 to 220")
    script = (ROOT / "docs/submission/VIDEO_SCRIPT.md").read_text(encoding="utf-8")
    if re.search(r"\b(?:C" + "VE|G" + "HSA)-", script, re.IGNORECASE):
        failures.append("video script contains a real vulnerability identifier")

    blocks = re.split(r"\r?\n\r?\n", (ROOT / "docs/submission/CAPTIONS.srt").read_text(encoding="utf-8").strip())
    previous_end = -1
    caption_lines: list[str] = []
    for index, block in enumerate(blocks, start=1):
        lines = block.splitlines()
        if len(lines) < 3 or lines[0] != str(index):
            failures.append(f"SRT cue {index} is malformed or misnumbered")
            continue
        match = re.fullmatch(r"(\d{2}:\d{2}:\d{2},\d{3}) --> (\d{2}:\d{2}:\d{2},\d{3})", lines[1])
        if not match:
            failures.append(f"SRT cue {index} has an invalid timestamp")
            continue
        start = parse_srt_timestamp(match.group(1))
        end = parse_srt_timestamp(match.group(2))
        if start < previous_end or end <= start:
            failures.append(f"SRT cue {index} timestamps are out of order")
        if len(lines[2:]) > 2:
            failures.append(f"SRT cue {index} has more than two text lines")
        caption_lines.extend(lines[2:])
        previous_end = end
    if previous_end > parse_srt_timestamp("00:02:20,000"):
        failures.append("SRT ends after 00:02:20,000")
    spoken_script = " ".join(
        line
        for line in script.splitlines()
        if line and not line.startswith("#")
    )
    normalize = lambda value: re.findall(r"[a-z0-9]+", value.casefold())
    if normalize(spoken_script) != normalize(" ".join(caption_lines)):
        failures.append("SRT text must match the spoken video script")


def validate_submission_docs(failures: list[str]) -> None:
    screenshots = (ROOT / "docs/submission/SCREENSHOTS.md").read_text(encoding="utf-8")
    for relative in SCREENSHOTS:
        if Path(relative).name not in screenshots:
            failures.append(f"SCREENSHOTS.md does not document {Path(relative).name}")
    checklist = (ROOT / "docs/submission/SUBMISSION_CHECKLIST.md").read_text(encoding="utf-8")
    for deadline in ("11:00 PDT on September 5, 2026", "14:00 PDT"):
        if deadline not in checklist:
            failures.append(f"submission checklist is missing deadline: {deadline}")


def validate_repository_safety(failures: list[str]) -> None:
    digest = (ROOT / "evidence/demo-bundle/manifest.sha256").read_text(encoding="utf-8").strip()
    if digest != f"{EXPECTED_DEMO_DIGEST}  manifest.json":
        failures.append("tracked demo-bundle digest changed")
    for path in project_files():
        relative = path.relative_to(ROOT)
        if path.suffix.casefold() in VIDEO_SUFFIXES:
            failures.append(f"video binary must not be tracked: {relative}")
        if path.suffix.casefold() in PRIVATE_SUFFIXES:
            failures.append(f"private-key extension must not be tracked: {relative}")
        if path.stat().st_size > 10 * 1024 * 1024:
            failures.append(f"tracked or pending file exceeds 10 MB: {relative}")
        try:
            content = path.read_text(encoding="utf-8")
        except (OSError, UnicodeError):
            continue
        for header in PRIVATE_HEADERS:
            if header in content:
                failures.append(f"private-key PEM header found: {relative}")
        folded = content.casefold()
        for marker in FORBIDDEN_MATERIAL:
            if marker.casefold() in folded:
                failures.append(f"real vendor or private disclosure material found: {relative}")
        if re.search(WINDOWS_PROFILE_PATTERN, content):
            failures.append(f"absolute local user path found: {relative}")
        prohibited_assurance = "tamper" + "-proof"
        if prohibited_assurance in folded:
            failures.append(f"evidence uses the prohibited absolute-integrity term: {relative}")
    combined_docs = "\n".join(
        path.read_text(encoding="utf-8")
        for path in project_files()
        if path.suffix.casefold() in {".md", ".json"}
        and path.is_file()
        and path.stat().st_size < 2_000_000
    ).casefold()
    for marker in ("cloud deployment is live", "public dashboard is live", "deployed at http"):
        if marker in combined_docs:
            failures.append(f"submission package claims a cloud deployment: {marker}")


def main() -> int:
    failures: list[str] = []
    validate_files(failures)
    validate_metadata(failures)
    validate_screenshots(failures)
    validate_readme(failures)
    validate_workflow(failures)
    validate_copy(failures)
    validate_video_materials(failures)
    validate_submission_docs(failures)
    validate_repository_safety(failures)
    if failures:
        print(f"FAIL: FixRepro Phase 5A validation found {len(failures)} error(s):")
        for failure in failures:
            print(f"- {failure}")
        return 1
    print("PASS: FixRepro Phase 5A submission package is valid.")
    print(f"Checked {len(REQUIRED_FILES)} required files and {len(SCREENSHOTS)} PNG screenshots.")
    print(f"Video script word count: {script_word_count()}.")
    print("Metadata, CI, captions, demo digest, and release safety boundaries passed.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
