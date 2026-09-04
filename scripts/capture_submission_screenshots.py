#!/usr/bin/env python3
"""Capture public submission screenshots from the real localhost dashboard."""

from __future__ import annotations

import json
import os
import shutil
import socket
import struct
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request
from dataclasses import dataclass
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
HOST = "127.0.0.1"
PORT = 8000
BASE_URL = f"http://{HOST}:{PORT}"
LOG_PATH = ROOT / ".runtime" / "logs" / "submission-screenshots-dashboard.log"
OUTPUT_ROOT = ROOT / "docs" / "submission" / "screenshots"
PNG_SIGNATURE = b"\x89PNG\r\n\x1a\n"
REQUIRED_DOM_TEXT = (
    "PATCH VERIFIED",
    "UNSAFE BEHAVIOR REPRODUCED",
    "PATCH BLOCKED SAME INPUT",
    "LEGITIMATE UPDATE PRESERVED",
)


@dataclass(frozen=True)
class ScreenshotSpec:
    filename: str
    url: str
    width: int
    height: int
    browser_width: int | None = None
    browser_height: int | None = None
    device_scale_factor: float = 1.0


SCREENSHOTS = (
    ScreenshotSpec("01-dashboard-overview.png", f"{BASE_URL}/", 1440, 1000),
    ScreenshotSpec("02-dashboard-full.png", f"{BASE_URL}/", 1440, 2600),
    ScreenshotSpec(
        "03-verification-report.png",
        f"{BASE_URL}/api/v1/bundles/demo/report",
        1440,
        2000,
    ),
    # Chromium enforces a 500 CSS-pixel minimum in CLI headless mode. Rendering
    # the existing mobile breakpoint at 500 CSS pixels and scaling the captured
    # surface produces the requested 390x844 public image without cropping.
    ScreenshotSpec(
        "04-mobile-dashboard.png",
        f"{BASE_URL}/",
        390,
        844,
        browser_width=500,
        browser_height=1082,
        device_scale_factor=0.78,
    ),
)


class CaptureError(RuntimeError):
    """Raised when safe screenshot capture cannot complete."""


def port_accepts_connections(port: int) -> bool:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
        probe.settimeout(0.25)
        return probe.connect_ex((HOST, port)) == 0


def browser_candidates() -> list[Path]:
    candidates: list[Path] = []
    for name in (
        "msedge",
        "msedge.exe",
        "chrome",
        "chrome.exe",
        "google-chrome",
        "chromium",
        "chromium-browser",
    ):
        resolved = shutil.which(name)
        if resolved:
            candidates.append(Path(resolved))

    program_roots = [
        os.environ.get("ProgramFiles"),
        os.environ.get("ProgramFiles(x86)"),
    ]
    relative_candidates = (
        Path("Microsoft/Edge/Application/msedge.exe"),
        Path("Google/Chrome/Application/chrome.exe"),
        Path("Chromium/Application/chrome.exe"),
    )
    for root in program_roots:
        if not root:
            continue
        for relative in relative_candidates:
            candidates.append(Path(root) / relative)

    unique: list[Path] = []
    seen: set[str] = set()
    for candidate in candidates:
        key = str(candidate).casefold()
        if key not in seen and candidate.is_file():
            seen.add(key)
            unique.append(candidate)
    return unique


def request_json(path: str) -> dict[str, object]:
    request = urllib.request.Request(
        f"{BASE_URL}{path}",
        headers={"Accept": "application/json"},
        method="GET",
    )
    with urllib.request.urlopen(request, timeout=5) as response:
        value = json.loads(response.read().decode("utf-8"))
    if not isinstance(value, dict):
        raise CaptureError(f"{path} did not return a JSON object")
    return value


def wait_for_dashboard(process: subprocess.Popen[str]) -> None:
    deadline = time.monotonic() + 30
    last_error = "no response"
    while time.monotonic() < deadline:
        if process.poll() is not None:
            raise CaptureError(f"dashboard exited with status {process.returncode}; see {LOG_PATH}")
        try:
            health = request_json("/health")
            if health.get("status") == "ok":
                return
            last_error = f"unexpected health response: {health}"
        except (OSError, UnicodeError, json.JSONDecodeError, urllib.error.URLError) as exc:
            last_error = str(exc)
        time.sleep(0.25)
    raise CaptureError(f"dashboard did not become healthy: {last_error}")


def browser_flags(profile: Path, *, headless_mode: str) -> list[str]:
    return [
        f"--headless={headless_mode}" if headless_mode else "--headless",
        "--disable-gpu",
        "--disable-background-networking",
        "--disable-component-update",
        "--disable-default-apps",
        "--disable-sync",
        "--metrics-recording-only",
        "--no-first-run",
        "--no-default-browser-check",
        "--hide-scrollbars",
        "--safebrowsing-disable-auto-update",
        "--virtual-time-budget=10000",
        f"--user-data-dir={profile}",
    ]


def run_browser(
    browser: Path,
    profile: Path,
    arguments: list[str],
) -> subprocess.CompletedProcess[str]:
    modern = subprocess.run(
        [str(browser), *browser_flags(profile, headless_mode="new"), *arguments],
        cwd=ROOT,
        check=False,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=45,
        shell=False,
    )
    if modern.returncode == 0:
        return modern
    legacy = subprocess.run(
        [str(browser), *browser_flags(profile, headless_mode=""), *arguments],
        cwd=ROOT,
        check=False,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=45,
        shell=False,
    )
    return legacy


def validate_rendered_dashboard(browser: Path, profile: Path) -> None:
    result = run_browser(browser, profile, ["--dump-dom", f"{BASE_URL}/"])
    if result.returncode != 0:
        raise CaptureError(f"browser DOM validation failed: {result.stderr.strip()}")
    missing = [text for text in REQUIRED_DOM_TEXT if text not in result.stdout]
    if missing:
        raise CaptureError("rendered dashboard is missing: " + ", ".join(missing))


def png_dimensions(path: Path) -> tuple[int, int]:
    content = path.read_bytes()
    if len(content) < 24 or not content.startswith(PNG_SIGNATURE):
        raise CaptureError(f"invalid PNG header: {path.relative_to(ROOT).as_posix()}")
    if content[12:16] != b"IHDR":
        raise CaptureError(f"missing PNG IHDR: {path.relative_to(ROOT).as_posix()}")
    return struct.unpack(">II", content[16:24])


def capture(browser: Path, profile: Path, spec: ScreenshotSpec) -> None:
    output = OUTPUT_ROOT / spec.filename
    browser_width = spec.browser_width or spec.width
    browser_height = spec.browser_height or spec.height
    result = run_browser(
        browser,
        profile,
        [
            f"--window-size={browser_width},{browser_height}",
            f"--force-device-scale-factor={spec.device_scale_factor}",
            f"--screenshot={output.resolve()}",
            spec.url,
        ],
    )
    if result.returncode != 0 or not output.is_file():
        raise CaptureError(f"browser failed to capture {spec.filename}: {result.stderr.strip()}")
    width, height = png_dimensions(output)
    if abs(width - spec.width) > 16 or abs(height - spec.height) > 16:
        raise CaptureError(
            f"{spec.filename} dimensions were {width}x{height}; expected {spec.width}x{spec.height}"
        )
    size = output.stat().st_size
    if size < 20_000 or size >= 5 * 1024 * 1024:
        raise CaptureError(f"{spec.filename} has unexpected size: {size} bytes")
    print(f"CAPTURED={output.relative_to(ROOT).as_posix()} {width}x{height} {size} bytes")


def wait_for_port_closed() -> None:
    deadline = time.monotonic() + 10
    while time.monotonic() < deadline:
        if not port_accepts_connections(PORT):
            return
        time.sleep(0.2)
    raise CaptureError("dashboard port 8000 remained open after capture")


def main() -> int:
    if Path.cwd().resolve() != ROOT:
        print("Run this script from the repository root.", file=sys.stderr)
        return 1
    if port_accepts_connections(PORT):
        print("Port 8000 is occupied; no process was terminated.", file=sys.stderr)
        return 1
    browsers = browser_candidates()
    if not browsers:
        print("Microsoft Edge or Google Chrome was not found in approved locations.", file=sys.stderr)
        return 1

    OUTPUT_ROOT.mkdir(parents=True, exist_ok=True)
    LOG_PATH.parent.mkdir(parents=True, exist_ok=True)
    runtime_profiles = ROOT / ".runtime" / "browser-profiles"
    runtime_profiles.mkdir(parents=True, exist_ok=True)

    process: subprocess.Popen[str] | None = None
    failure: Exception | None = None
    try:
        with LOG_PATH.open("w", encoding="utf-8", newline="\n") as log_handle:
            process = subprocess.Popen(
                [sys.executable, "scripts/run_dashboard.py", "--host", HOST, "--port", str(PORT)],
                cwd=ROOT,
                stdout=log_handle,
                stderr=subprocess.STDOUT,
                text=True,
                shell=False,
            )
            wait_for_dashboard(process)
            demo = request_json("/api/v1/demo")
            if demo.get("verification_outcome") != "PATCH_VERIFIED":
                raise CaptureError("tracked demo outcome is not PATCH_VERIFIED")
            if demo.get("same_input_verified") is not True:
                raise CaptureError("tracked demo does not confirm exact same-input replay")
            with tempfile.TemporaryDirectory(prefix="capture-", dir=runtime_profiles) as temporary:
                profile = Path(temporary)
                browser = browsers[0]
                validate_rendered_dashboard(browser, profile)
                for spec in SCREENSHOTS:
                    capture(browser, profile, spec)
    except (CaptureError, OSError, subprocess.SubprocessError, urllib.error.URLError) as exc:
        failure = exc
    finally:
        if process is not None and process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=15)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=5)
        try:
            wait_for_port_closed()
        except CaptureError as exc:
            if failure is None:
                failure = exc

    if failure is not None:
        print(f"SUBMISSION_SCREENSHOTS_FAIL={failure}", file=sys.stderr)
        print(f"DASHBOARD_LOG={LOG_PATH.relative_to(ROOT).as_posix()}", file=sys.stderr)
        return 1
    print("SUBMISSION_SCREENSHOTS_PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
