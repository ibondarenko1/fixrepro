from __future__ import annotations

import re
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
INDEX = ROOT / "app/static/index.html"
SCRIPT = ROOT / "app/static/app.js"


def test_root_page_contains_required_headings_and_single_h1() -> None:
    content = INDEX.read_text(encoding="utf-8")
    assert content.count("<h1") == 1
    assert "Prove the patch. Preserve the feature." in content
    assert "Exact same input replayed" in content
    assert "Tamper-evident evidence bundle" in content
    assert "What this result proves" in content
    assert "Waiting for verified evidence" in content
    assert "EVIDENCE UNAVAILABLE" not in content


def test_root_page_contains_all_stable_test_selectors() -> None:
    content = INDEX.read_text(encoding="utf-8")
    expected = {
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
    }
    assert all(f'data-testid="{value}"' in content for value in expected)


def test_static_html_uses_only_local_assets() -> None:
    content = INDEX.read_text(encoding="utf-8")
    assert 'href="/static/styles.css"' in content
    assert 'src="/static/app.js"' in content
    assert re.search(r"(?i)(?:https?:)?//[a-z]", content) is None
    assert "<style" not in content
    assert re.search(r"<script(?![^>]*\bsrc=)", content) is None


def test_static_html_has_accessible_structure() -> None:
    content = INDEX.read_text(encoding="utf-8")
    for marker in ('<html lang="en">', "skip-link", "aria-live=", "<main", "<section", "<article", "<nav", "<footer"):
        assert marker in content


def test_javascript_avoids_dynamic_html_sinks() -> None:
    content = SCRIPT.read_text(encoding="utf-8")
    assert "inner" + "HTML" not in content
    assert "insertAdjacent" + "HTML" not in content
    assert "ev" + "al(" not in content
    assert "new " + "Function" not in content


def test_javascript_uses_no_browser_persistent_storage() -> None:
    content = SCRIPT.read_text(encoding="utf-8")
    assert "local" + "Storage" not in content
    assert "session" + "Storage" not in content
    assert "document.cookie" not in content


def test_javascript_sends_only_fixed_verification_action() -> None:
    content = SCRIPT.read_text(encoding="utf-8")
    assert '"X-FixRepro-Action": "run-verification"' in content
    assert "JSON.stringify({})" in content
    assert "textContent" in content
