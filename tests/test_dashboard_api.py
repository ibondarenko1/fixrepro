from __future__ import annotations

import json
import shutil
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from app.main import create_app
from app.models import (
    JobStatus,
    JobStatusResponse,
    StartVerificationResponse,
)
from app.presentation import BundleRegistry
from verifier.evidence import utc_timestamp


ROOT = Path(__file__).resolve().parents[1]
EXPECTED_DIGEST = "10fd80148896935b10fd1ccfd056e345d9a4537dff35473c4a025b9dbcab0204"


class FakeJobManager:
    def __init__(self, repository_root: Path) -> None:
        self.bundle_registry = BundleRegistry(repository_root)
        self.job = JobStatusResponse(
            job_id="JOB-0123abcd",
            status=JobStatus.RUNNING,
            created_at=utc_timestamp(),
            started_at=utc_timestamp(),
        )
        self.shutdown_called = False

    def start_job(self) -> StartVerificationResponse:
        return StartVerificationResponse(
            job_id=self.job.job_id,
            status=JobStatus.RUNNING,
            status_url=f"/api/v1/verifications/{self.job.job_id}",
        )

    def get_job(self, job_id: str) -> JobStatusResponse | None:
        return self.job if job_id == self.job.job_id else None

    def shutdown(self, *, wait: bool = True) -> None:
        self.shutdown_called = wait


@pytest.fixture()
def client() -> TestClient:
    manager = FakeJobManager(ROOT)
    with TestClient(create_app(ROOT, manager)) as test_client:
        yield test_client


def copy_repository_shell(tmp_path: Path) -> Path:
    repository = tmp_path / "repository"
    shutil.copytree(ROOT / "app", repository / "app")
    shutil.copytree(ROOT / "schemas", repository / "schemas")
    shutil.copytree(ROOT / "cases", repository / "cases")
    shutil.copytree(ROOT / "evidence/demo-bundle", repository / "evidence/demo-bundle")
    return repository


def test_application_factory_creates_app_from_repository_root() -> None:
    application = create_app(ROOT, FakeJobManager(ROOT))
    assert application.title == "FixRepro dashboard"
    assert application.state.repository_root == ROOT.resolve()


def test_application_factory_fails_for_missing_required_files(tmp_path: Path) -> None:
    with pytest.raises(RuntimeError, match="required repository files"):
        create_app(tmp_path, FakeJobManager(tmp_path))


def test_health_returns_expected_service_and_version(client: TestClient) -> None:
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json() == {
        "status": "ok",
        "service": "fixrepro-dashboard",
        "version": "0.4.0",
    }


def test_root_and_static_assets_are_served_locally(client: TestClient) -> None:
    root = client.get("/")
    css = client.get("/static/styles.css")
    script = client.get("/static/app.js")
    assert root.status_code == css.status_code == script.status_code == 200
    assert root.headers["content-type"].startswith("text/html")
    assert css.headers["content-type"].startswith("text/css")
    assert "javascript" in script.headers["content-type"]


def test_demo_returns_verified_three_scenario_presentation(client: TestClient) -> None:
    response = client.get("/api/v1/demo")
    assert response.status_code == 200
    body = response.json()
    assert body["verification_outcome"] == "PATCH_VERIFIED"
    assert body["source"] == "DEMO"
    assert body["same_input_verified"] is True
    assert body["bundle_manifest_sha256"] == EXPECTED_DIGEST
    assert {item["role"] for item in body["scenarios"]} == {
        "VULNERABLE",
        "PATCHED",
        "POSITIVE_CONTROL",
    }


def test_demo_response_contains_no_absolute_repository_path(client: TestClient) -> None:
    response_text = json.dumps(client.get("/api/v1/demo").json())
    assert str(ROOT) not in response_text
    assert "C:\\\\" not in response_text


@pytest.mark.parametrize("artifact", ["report", "evidence", "manifest", "digest"])
def test_artifact_endpoints_serve_only_allowed_files(client: TestClient, artifact: str) -> None:
    response = client.get(f"/api/v1/bundles/demo/{artifact}")
    assert response.status_code == 200


def test_artifact_endpoint_does_not_serve_package_files(client: TestClient) -> None:
    response = client.get("/api/v1/bundles/demo/packages/untrusted-update.json")
    assert response.status_code == 404


def test_unknown_bundle_id_returns_stable_404(client: TestClient) -> None:
    response = client.get("/api/v1/bundles/unknown/report")
    assert response.status_code == 404
    assert response.json()["error"]["code"] == "BUNDLE_NOT_FOUND"


def test_unknown_job_id_returns_stable_404(client: TestClient) -> None:
    response = client.get("/api/v1/verifications/JOB-deadbeef")
    assert response.status_code == 404
    assert response.json()["error"]["code"] == "JOB_NOT_FOUND"


def test_verification_start_accepts_only_empty_object(client: TestClient) -> None:
    response = client.post(
        "/api/v1/verifications",
        json={},
        headers={"X-FixRepro-Action": "run-verification"},
    )
    assert response.status_code == 202
    assert response.json()["status"] == "RUNNING"


@pytest.mark.parametrize("payload", [{"target": "local"}, [], None, "value"])
def test_verification_start_rejects_nonempty_or_nonobject_json(
    client: TestClient,
    payload: object,
) -> None:
    response = client.post(
        "/api/v1/verifications",
        json=payload,
        headers={"X-FixRepro-Action": "run-verification"},
    )
    assert response.status_code == 400
    assert response.json()["error"]["code"] == "INVALID_REQUEST"


def test_verification_start_rejects_wrong_content_type(client: TestClient) -> None:
    response = client.post(
        "/api/v1/verifications",
        content="{}",
        headers={
            "Content-Type": "text/plain",
            "X-FixRepro-Action": "run-verification",
        },
    )
    assert response.status_code == 400
    assert response.json()["error"]["code"] == "INVALID_REQUEST"


@pytest.mark.parametrize("header", [None, "wrong-action"])
def test_verification_start_requires_exact_action_header(
    client: TestClient,
    header: str | None,
) -> None:
    headers = {} if header is None else {"X-FixRepro-Action": header}
    response = client.post("/api/v1/verifications", json={}, headers=headers)
    assert response.status_code == 400
    assert response.json()["error"]["code"] == "ACTION_HEADER_REQUIRED"


def test_normal_security_headers_and_no_cors(client: TestClient) -> None:
    response = client.get("/")
    assert "script-src 'self'" in response.headers["content-security-policy"]
    assert "script-src 'unsafe-inline'" not in response.headers["content-security-policy"]
    assert response.headers["x-content-type-options"] == "nosniff"
    assert response.headers["x-frame-options"] == "DENY"
    assert response.headers["referrer-policy"] == "no-referrer"
    assert response.headers["cross-origin-opener-policy"] == "same-origin"
    assert response.headers["cache-control"] == "no-store"
    assert "access-control-allow-origin" not in response.headers
    assert "set-cookie" not in response.headers


def test_report_uses_restricted_inline_style_csp(client: TestClient) -> None:
    response = client.get("/api/v1/bundles/demo/report")
    csp = response.headers["content-security-policy"]
    assert response.status_code == 200
    assert "style-src 'unsafe-inline'" in csp
    assert "script-src" not in csp
    assert "<script" not in response.text.lower()


def test_known_bundle_invalidation_blocks_artifact(tmp_path: Path) -> None:
    repository = copy_repository_shell(tmp_path)
    manager = FakeJobManager(repository)
    with TestClient(create_app(repository, manager)) as temporary_client:
        assert temporary_client.get("/api/v1/demo").status_code == 200
        evidence = repository / "evidence/demo-bundle/evidence.json"
        evidence.write_bytes(evidence.read_bytes() + b"modified")
        response = temporary_client.get("/api/v1/bundles/demo/evidence")
    assert response.status_code == 409
    assert response.json()["error"]["code"] == "BUNDLE_INTEGRITY_FAILURE"
