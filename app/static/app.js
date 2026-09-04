"use strict";

const expectedRoles = ["VULNERABLE", "PATCHED", "POSITIVE_CONTROL"];
const outcomeLabels = {
  PATCH_VERIFIED: "PATCH VERIFIED",
  PATCH_NOT_VERIFIED: "PATCH NOT VERIFIED",
  INCONCLUSIVE: "INCONCLUSIVE",
};
const hashPattern = /^[a-f0-9]{64}$/;
const jobPattern = /^JOB-[a-f0-9]{8}$/;
const statusPathPattern = /^\/api\/v1\/verifications\/JOB-[a-f0-9]{8}$/;

const elements = {
  runButton: document.getElementById("run-verification"),
  demoButton: document.getElementById("load-demo"),
  source: document.getElementById("source-indicator"),
  outcome: document.getElementById("overall-outcome"),
  outcomeSymbol: document.getElementById("outcome-symbol"),
  integrityStatus: document.getElementById("bundle-integrity-status"),
  resultHeading: document.getElementById("result-heading"),
  verificationId: document.getElementById("verification-id"),
  createdAt: document.getElementById("created-at"),
  liveStatus: document.getElementById("live-status"),
  error: document.getElementById("error-message"),
  sameInput: document.getElementById("same-input-status"),
  envelopeHash: document.getElementById("envelope-sha256"),
  requestHash: document.getElementById("request-sha256"),
  manifestHash: document.getElementById("manifest-sha256"),
  manifestCount: document.getElementById("manifest-entry-count"),
  property: document.getElementById("security-property"),
  limitation: document.getElementById("limitation-text"),
  safety: document.getElementById("safety-scope"),
  links: {
    report: document.getElementById("report-link"),
    evidence: document.getElementById("evidence-link"),
    manifest: document.getElementById("manifest-link"),
    digest: document.getElementById("digest-link"),
  },
};

let activeJobId = null;
let hasValidResult = false;

function isObject(value) {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function requireString(value, label) {
  if (typeof value !== "string" || value.length === 0) {
    throw new Error(`Missing or invalid ${label}.`);
  }
  return value;
}

function requireInteger(value, label) {
  if (!Number.isInteger(value) || value < 0) {
    throw new Error(`Missing or invalid ${label}.`);
  }
  return value;
}

function requireHash(value, label) {
  const checked = requireString(value, label);
  if (!hashPattern.test(checked)) {
    throw new Error(`Invalid ${label}.`);
  }
  return checked;
}

function requireArtifactLink(value, label) {
  const checked = requireString(value, label);
  if (!checked.startsWith("/api/v1/bundles/") || checked.includes("..") || checked.includes(":")) {
    throw new Error(`Invalid ${label}.`);
  }
  return checked;
}

function validateScenario(value) {
  if (!isObject(value) || !expectedRoles.includes(value.role)) {
    throw new Error("A scenario role is missing or invalid.");
  }
  return {
    role: value.role,
    visibleLabel: requireString(value.visible_label, "scenario label"),
    buildId: requireString(value.build_id, "build ID"),
    httpStatus: requireInteger(value.http_status, "HTTP status"),
    decision: requireString(value.observed_decision, "decision"),
    reason: requireString(value.reason_code, "reason code"),
    verdict: requireString(value.security_verdict, "security verdict"),
    beforeVersion: requireString(value.firmware_version_before, "initial firmware version"),
    afterVersion: requireString(value.firmware_version_after, "result firmware version"),
    beforeCounter: requireInteger(value.update_counter_before, "initial update counter"),
    afterCounter: requireInteger(value.update_counter_after, "result update counter"),
  };
}

function validatePresentation(value) {
  if (!isObject(value) || !Array.isArray(value.scenarios) || value.scenarios.length !== 3) {
    throw new Error("The server returned an incomplete verification result.");
  }
  const scenarios = value.scenarios.map(validateScenario);
  const roles = new Set(scenarios.map((scenario) => scenario.role));
  if (expectedRoles.some((role) => !roles.has(role)) || roles.size !== 3) {
    throw new Error("The verification result must contain each scenario exactly once.");
  }
  if (!isObject(value.links)) {
    throw new Error("The verification result has no artifact links.");
  }
  if (value.same_input_verified !== true) {
    throw new Error("The verification result does not prove an exact same-input replay.");
  }
  const outcome = requireString(value.verification_outcome, "verification outcome");
  if (!Object.hasOwn(outcomeLabels, outcome)) {
    throw new Error("The verification outcome is not recognized.");
  }
  return {
    source: value.source,
    verificationId: requireString(value.verification_id, "verification ID"),
    outcome,
    createdAt: requireString(value.created_at, "creation time"),
    property: requireString(value.security_property, "security property"),
    sameInput: value.same_input_verified,
    envelopeHash: requireHash(value.untrusted_envelope_sha256, "envelope SHA-256"),
    requestHash: requireHash(value.untrusted_request_body_sha256, "request SHA-256"),
    manifestHash: requireHash(value.bundle_manifest_sha256, "manifest SHA-256"),
    manifestCount: requireInteger(value.manifest_entry_count, "manifest entry count"),
    scenarios,
    links: {
      report: requireArtifactLink(value.links.report, "report link"),
      evidence: requireArtifactLink(value.links.evidence, "evidence link"),
      manifest: requireArtifactLink(value.links.manifest, "manifest link"),
      digest: requireArtifactLink(value.links.digest, "digest link"),
    },
    safety: requireString(value.safety_scope, "safety scope"),
    limitation: requireString(value.limitation, "limitation"),
  };
}

function setStatus(message, running) {
  elements.liveStatus.textContent = message;
  elements.liveStatus.classList.toggle("is-running", running);
}

function showError(message) {
  elements.error.textContent = message;
  elements.error.hidden = false;
}

function clearError() {
  elements.error.textContent = "";
  elements.error.hidden = true;
}

function setScenarioField(card, field, value) {
  const target = card.querySelector(`[data-field="${field}"]`);
  if (target === null) {
    throw new Error(`Dashboard field ${field} is unavailable.`);
  }
  target.textContent = value;
}

function renderScenario(scenario) {
  const card = document.querySelector(`[data-role="${scenario.role}"]`);
  if (card === null) {
    throw new Error(`Dashboard card ${scenario.role} is unavailable.`);
  }
  const symbol = card.querySelector(".scenario-status > span:first-child");
  if (symbol === null) {
    throw new Error(`Dashboard status symbol ${scenario.role} is unavailable.`);
  }
  symbol.textContent = scenario.verdict === "PASS" ? "✓" : scenario.verdict === "FAIL" ? "!" : "?";
  setScenarioField(card, "visible_label", scenario.visibleLabel);
  setScenarioField(card, "firmware_version_before", scenario.beforeVersion);
  setScenarioField(card, "firmware_version_after", scenario.afterVersion);
  setScenarioField(card, "observed_decision", scenario.decision);
  setScenarioField(card, "reason_code", scenario.reason);
  setScenarioField(card, "security_verdict", scenario.verdict);
  setScenarioField(card, "build_id", scenario.buildId);
  setScenarioField(card, "counter_transition", `${scenario.beforeCounter} → ${scenario.afterCounter}`);
}

function renderPresentation(raw, sourceText, moveFocus) {
  const result = validatePresentation(raw);
  elements.source.textContent = sourceText;
  elements.outcome.textContent = outcomeLabels[result.outcome];
  elements.outcomeSymbol.textContent = result.outcome === "PATCH_VERIFIED" ? "✓" : result.outcome === "INCONCLUSIVE" ? "?" : "!";
  elements.integrityStatus.textContent = "✓ Evidence independently verified";
  elements.verificationId.textContent = result.verificationId;
  elements.createdAt.textContent = result.createdAt;
  elements.property.textContent = result.property;
  elements.envelopeHash.textContent = result.envelopeHash;
  elements.requestHash.textContent = result.requestHash;
  elements.manifestHash.textContent = result.manifestHash;
  elements.manifestCount.textContent = String(result.manifestCount);
  elements.sameInput.textContent = "✓ Envelope and request hashes match across Scenario A and Scenario B";
  elements.safety.textContent = result.safety;
  elements.limitation.textContent = result.limitation;
  result.scenarios.forEach(renderScenario);
  Object.entries(result.links).forEach(([name, path]) => {
    elements.links[name].href = path;
  });
  hasValidResult = true;
  if (moveFocus) {
    elements.resultHeading.focus();
  }
}

async function parseResponse(response) {
  let body;
  try {
    body = await response.json();
  } catch (_error) {
    throw new Error(`Server returned HTTP ${response.status} without valid JSON.`);
  }
  if (!response.ok) {
    const message = isObject(body.error) && typeof body.error.message === "string"
      ? body.error.message
      : `Request failed with HTTP ${response.status}.`;
    throw new Error(message);
  }
  return body;
}

async function loadDemo(announce) {
  clearError();
  elements.demoButton.disabled = true;
  setStatus("Verifying the tracked demonstration bundle…", true);
  try {
    const response = await fetch("/api/v1/demo", { method: "GET", cache: "no-store" });
    const body = await parseResponse(response);
    renderPresentation(body, "Verified demo bundle", false);
    setStatus(
      announce ? "Verified demo bundle loaded." : "Verified demo bundle loaded automatically.",
      false,
    );
  } catch (error) {
    showError(error instanceof Error ? error.message : "The verified demo bundle could not be loaded.");
    if (!hasValidResult) {
      elements.source.textContent = "No verified evidence loaded";
      elements.outcome.textContent = "EVIDENCE UNAVAILABLE";
      elements.outcomeSymbol.textContent = "!";
      elements.integrityStatus.textContent = "! Bundle has not been verified";
    }
    setStatus("Demo unavailable. Live verification remains available.", false);
  } finally {
    elements.demoButton.disabled = false;
  }
}

function wait(milliseconds) {
  return new Promise((resolve) => window.setTimeout(resolve, milliseconds));
}

async function pollJob(statusUrl, jobId) {
  const deadline = Date.now() + 120000;
  while (Date.now() < deadline) {
    await wait(700);
    const response = await fetch(statusUrl, { method: "GET", cache: "no-store" });
    const body = await parseResponse(response);
    if (!isObject(body) || body.job_id !== jobId || typeof body.status !== "string") {
      throw new Error("The server returned an invalid job status.");
    }
    if (body.status === "COMPLETED") {
      renderPresentation(body.result, "Live local verification", true);
      setStatus(`Job ${jobId} completed with a deterministic evidence bundle.`, false);
      return;
    }
    if (body.status === "FAILED") {
      const message = isObject(body.error) && typeof body.error.message === "string"
        ? body.error.message
        : "The live verification failed operationally.";
      throw new Error(message);
    }
    if (body.status !== "RUNNING" && body.status !== "QUEUED") {
      throw new Error("The server returned an unknown job state.");
    }
    setStatus(`Running deterministic verification… Job ${jobId}`, true);
  }
  throw new Error("The live verification did not finish within the browser timeout.");
}

async function runVerification() {
  clearError();
  elements.runButton.disabled = true;
  setStatus("Starting deterministic verification…", true);
  try {
    const response = await fetch("/api/v1/verifications", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "X-FixRepro-Action": "run-verification",
      },
      body: JSON.stringify({}),
    });
    const body = await parseResponse(response);
    if (!isObject(body) || !jobPattern.test(body.job_id) || !statusPathPattern.test(body.status_url)) {
      throw new Error("The server returned an invalid job identifier.");
    }
    activeJobId = body.job_id;
    setStatus(`Running deterministic verification… Job ${activeJobId}`, true);
    await pollJob(body.status_url, activeJobId);
  } catch (error) {
    showError(error instanceof Error ? error.message : "The live verification request failed.");
    const suffix = activeJobId === null ? "" : ` Job ${activeJobId}.`;
    setStatus(`Live verification stopped.${suffix}`, false);
  } finally {
    activeJobId = null;
    elements.runButton.disabled = false;
  }
}

elements.runButton.addEventListener("click", runVerification);
elements.demoButton.addEventListener("click", () => loadDemo(true));
loadDemo(false);
