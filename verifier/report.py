"""Self-contained HTML report rendering from finalized evidence."""

from __future__ import annotations

from html import escape
from pathlib import Path

from .bundle import atomic_write_text
from .models import (
    EvidenceDocument,
    ExecutionEvidence,
    ExecutionRole,
    ObservedDecision,
    SecurityVerdict,
    VerificationOutcome,
)


REQUIRED_REPORT_LABELS = (
    "UNSAFE BEHAVIOR REPRODUCED",
    "PATCH BLOCKED SAME INPUT",
    "LEGITIMATE UPDATE PRESERVED",
    "PATCH VERIFIED",
)


def _execution(evidence: EvidenceDocument, role: ExecutionRole) -> ExecutionEvidence:
    return next(item for item in evidence.executions if item.role == role)


def _cell(value: object) -> str:
    return escape(str(value), quote=True)


def _verification_command(bundle_relative_path: str) -> str:
    if any(character.isspace() for character in bundle_relative_path):
        argument = f'"{bundle_relative_path}"'
    else:
        argument = bundle_relative_path
    return f"python scripts/verify_bundle.py {argument}"


def render_report(evidence: EvidenceDocument, bundle_relative_path: str) -> str:
    """Render evidence only; no tests or network operations occur here."""

    vulnerable = _execution(evidence, ExecutionRole.VULNERABLE)
    patched = _execution(evidence, ExecutionRole.PATCHED)
    positive = _execution(evidence, ExecutionRole.POSITIVE_CONTROL)
    command = _verification_command(bundle_relative_path)
    same_input = (
        vulnerable.package.envelope_sha256 == patched.package.envelope_sha256
        and vulnerable.request.body_sha256 == patched.request.body_sha256
    )
    artifacts = "".join(
        "<tr>"
        f"<td><code>{_cell(item.path)}</code></td>"
        f"<td>{_cell(item.media_type)}</td>"
        f"<td>{item.size_bytes}</td>"
        f"<td><code>{_cell(item.sha256)}</code></td>"
        "</tr>"
        for item in evidence.bundle_files
    )
    outcome_label = {
        VerificationOutcome.PATCH_VERIFIED: "PATCH VERIFIED",
        VerificationOutcome.PATCH_NOT_VERIFIED: "PATCH NOT VERIFIED",
        VerificationOutcome.INCONCLUSIVE: "INCONCLUSIVE",
    }[evidence.verification_outcome]
    vulnerable_label = (
        REQUIRED_REPORT_LABELS[0]
        if vulnerable.security_verdict == SecurityVerdict.FAIL
        else "UNSAFE BASELINE NOT REPRODUCED"
    )
    patched_label = (
        REQUIRED_REPORT_LABELS[1]
        if patched.observed_decision == ObservedDecision.REJECTED
        and patched.security_verdict == SecurityVerdict.PASS
        else "PATCH DID NOT BLOCK SAME INPUT"
    )
    positive_label = (
        REQUIRED_REPORT_LABELS[2]
        if positive.observed_decision == ObservedDecision.ACCEPTED
        and positive.security_verdict == SecurityVerdict.PASS
        else "LEGITIMATE UPDATE NOT PRESERVED"
    )

    def result_card(
        label: str,
        title: str,
        execution: ExecutionEvidence,
        tone: str,
    ) -> str:
        return f"""
        <article class="card {tone}">
          <p class="status"><span aria-hidden="true">●</span> {_cell(label)}</p>
          <h3>{_cell(title)}</h3>
          <dl>
            <div><dt>Build</dt><dd>{_cell(execution.build_id)}</dd></div>
            <div><dt>Decision</dt><dd>{_cell(execution.observed_decision)}</dd></div>
            <div><dt>Reason</dt><dd>{_cell(execution.response.reason_code)}</dd></div>
            <div><dt>Device</dt><dd>{_cell(execution.device_state_before.firmware_version)} → {_cell(execution.device_state_after.firmware_version)}</dd></div>
            <div><dt>Verdict</dt><dd>{_cell(execution.security_verdict)}</dd></div>
          </dl>
        </article>"""

    document = f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>FixRepro verification report</title>
  <style>
    :root {{ color-scheme: light; --ink:#17202a; --muted:#536273; --line:#d9e1e8; --surface:#f5f7f9; --pass:#12633a; --warn:#8a3b12; --accent:#174ea6; }}
    * {{ box-sizing:border-box; }}
    body {{ margin:0; font:16px/1.5 system-ui,sans-serif; color:var(--ink); background:#fff; }}
    main {{ width:min(1120px,100%); margin:auto; padding:clamp(20px,4vw,52px); }}
    h1 {{ margin:.15rem 0; font-size:clamp(2rem,6vw,4rem); line-height:1; }}
    h2 {{ margin-top:2.25rem; }}
    .eyebrow,.status {{ font-weight:800; letter-spacing:.05em; text-transform:uppercase; }}
    .hero {{ border-bottom:4px solid var(--accent); padding-bottom:1.5rem; }}
    .outcome {{ display:inline-block; margin:1rem 0; padding:.55rem .8rem; color:#fff; background:var(--pass); border-radius:.35rem; font-weight:900; }}
    .meta {{ color:var(--muted); overflow-wrap:anywhere; }}
    .grid {{ display:grid; grid-template-columns:repeat(3,minmax(0,1fr)); gap:1rem; }}
    .card {{ border:1px solid var(--line); border-top:7px solid var(--pass); border-radius:.6rem; padding:1rem; background:var(--surface); }}
    .card.unsafe {{ border-top-color:var(--warn); }}
    .card h3 {{ margin:.2rem 0 .8rem; }}
    .card .status {{ font-size:.8rem; }}
    .card.unsafe .status {{ color:var(--warn); }}
    .card.safe .status {{ color:var(--pass); }}
    dl div {{ display:grid; grid-template-columns:6rem 1fr; gap:.5rem; border-top:1px solid var(--line); padding:.45rem 0; }}
    dt {{ font-weight:700; }} dd {{ margin:0; overflow-wrap:anywhere; }}
    code {{ font-family:ui-monospace,monospace; overflow-wrap:anywhere; }}
    .proof {{ border-left:5px solid var(--accent); padding:1rem 1.2rem; background:#eef4ff; }}
    table {{ width:100%; border-collapse:collapse; font-size:.9rem; }}
    th,td {{ text-align:left; vertical-align:top; padding:.6rem; border:1px solid var(--line); overflow-wrap:anywhere; }}
    th {{ background:var(--surface); }}
    .table-wrap {{ overflow-x:auto; }}
    @media (max-width:760px) {{ .grid {{ grid-template-columns:1fr; }} main {{ padding:20px; }} }}
  </style>
</head>
<body>
<main>
  <header class="hero">
    <p class="eyebrow">Reproducible Security Patch Verification.</p>
    <h1>FixRepro</h1>
    <p class="outcome" role="status"><span aria-hidden="true">●</span> {_cell(outcome_label)}</p>
    <p class="meta">Verification ID: <code>{_cell(evidence.verification_id)}</code><br>Created: {_cell(evidence.created_at)}</p>
    <p><strong>Tested security property:</strong> {_cell(evidence.test_case.security_property)}</p>
  </header>

  <h2>Result at a glance</h2>
  <section class="grid" aria-label="Verification results">
    {result_card(vulnerable_label, "Vulnerable baseline", vulnerable, "unsafe")}
    {result_card(patched_label, "Patched security test", patched, "safe")}
    {result_card(positive_label, "Trusted positive control", positive, "safe")}
  </section>

  <h2>Same-input proof</h2>
  <div class="proof">
    <p><strong>{"The exact same package bytes were replayed." if same_input else "The package replay hashes do not match."}</strong></p>
    <p>Full untrusted package envelope SHA-256:<br><code>{_cell(vulnerable.package.envelope_sha256)}</code></p>
    <p>The trusted positive control was {_cell(positive.observed_decision)} and changed the device to {_cell(positive.device_state_after.firmware_version)}.</p>
  </div>

  <h2>Evidence artifacts</h2>
  <div class="table-wrap"><table>
    <thead><tr><th>Path</th><th>Media type</th><th>Bytes</th><th>SHA-256</th></tr></thead>
    <tbody>{artifacts}</tbody>
  </table></div>

  <h2>Bundle root digest</h2>
  <p>The final bundle digest is stored in <code>manifest.sha256</code>. It is intentionally not embedded here because <code>report.html</code> is itself covered by <code>manifest.json</code>.</p>
  <p>Verify this bundle locally with:</p>
  <pre><code>{_cell(command)}</code></pre>

  <h2>Safety scope</h2>
  <p>This is a controlled synthetic IoT OTA demonstration. It uses localhost services, harmless test firmware, generated in-memory signing identities, and deterministic observations. It does not test external systems or real vendor firmware.</p>

  <h2>Limitations</h2>
  <p>PATCH VERIFIED applies only to this defined regression case under the recorded test conditions. It does not show that every vulnerability is fixed or that the build is generally secure.</p>
  <p>The bundle is tamper-evident when its published manifest digest is retained separately. It is not a substitute for an externally trusted digital signature or independent laboratory validation.</p>
</main>
</body>
</html>
"""
    return "\n".join(line.rstrip() for line in document.splitlines()) + "\n"


def write_report(
    path: Path,
    evidence: EvidenceDocument,
    bundle_relative_path: str,
) -> None:
    atomic_write_text(path, render_report(evidence, bundle_relative_path))
