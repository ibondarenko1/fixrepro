"""FastAPI application factory for the judge-facing FixRepro dashboard."""

from __future__ import annotations

import json
import logging
from contextlib import asynccontextmanager
from pathlib import Path
from typing import AsyncIterator

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import ValidationError

from .jobs import (
    VerificationAlreadyRunningError,
    VerificationJobManager,
    VerificationManagerShuttingDownError,
)
from .models import (
    BundlePresentation,
    ErrorDetail,
    ErrorResponse,
    HealthResponse,
    JobStatusResponse,
    PresentationSource,
    StartVerificationRequest,
    StartVerificationResponse,
)
from .presentation import (
    BundleIntegrityError,
    BundleNotFoundError,
    BundleRegistry,
    present_bundle,
    verify_registered_bundle,
)
from .security import SecurityHeadersMiddleware


LOGGER = logging.getLogger(__name__)
VERSION = "0.4.0"
ALLOWED_ARTIFACTS = {
    "report": ("report.html", "text/html"),
    "evidence": ("evidence.json", "application/json"),
    "manifest": ("manifest.json", "application/json"),
    "digest": ("manifest.sha256", "text/plain"),
}


def resolve_repository_root() -> Path:
    return Path(__file__).resolve().parents[1]


def _error(status_code: int, code: str, message: str) -> JSONResponse:
    payload = ErrorResponse(error=ErrorDetail(code=code, message=message))
    return JSONResponse(status_code=status_code, content=payload.model_dump(mode="json"))


def _validate_repository(repository_root: Path) -> tuple[Path, Path]:
    root = repository_root.resolve()
    static = root / "app" / "static"
    required = (
        static / "index.html",
        static / "styles.css",
        static / "app.js",
        root / "schemas" / "evidence.schema.json",
        root / "cases" / "ota-untrusted-signer.json",
        root / "cases" / "ota-trusted-signer.json",
    )
    missing = [path.relative_to(root).as_posix() for path in required if not path.is_file()]
    if missing:
        raise RuntimeError("required repository files are missing: " + ", ".join(missing))
    return root, static


def create_app(
    repository_root: Path,
    job_manager: VerificationJobManager | None = None,
) -> FastAPI:
    root, static_directory = _validate_repository(repository_root)
    registry = (
        job_manager.bundle_registry
        if job_manager is not None
        else BundleRegistry(root)
    )
    manager = job_manager or VerificationJobManager(root, registry)

    @asynccontextmanager
    async def lifespan(_: FastAPI) -> AsyncIterator[None]:
        yield
        manager.shutdown(wait=True)

    application = FastAPI(
        title="FixRepro dashboard",
        version=VERSION,
        docs_url=None,
        redoc_url=None,
        openapi_url=None,
        lifespan=lifespan,
    )
    application.state.repository_root = root
    application.state.bundle_registry = registry
    application.state.job_manager = manager
    application.add_middleware(SecurityHeadersMiddleware)
    application.mount("/static", StaticFiles(directory=static_directory), name="static")

    @application.exception_handler(RequestValidationError)
    async def validation_error_handler(
        _: Request,
        __: RequestValidationError,
    ) -> JSONResponse:
        return _error(400, "INVALID_REQUEST", "The request did not match the API contract.")

    @application.exception_handler(Exception)
    async def internal_error_handler(_: Request, exc: Exception) -> JSONResponse:
        LOGGER.exception("Unhandled dashboard request error", exc_info=exc)
        return _error(500, "INTERNAL_ERROR", "An internal error prevented the request.")

    @application.get("/", include_in_schema=False)
    async def root_page() -> FileResponse:
        return FileResponse(static_directory / "index.html", media_type="text/html")

    @application.get("/health", response_model=HealthResponse)
    async def health() -> HealthResponse:
        return HealthResponse()

    @application.get("/api/v1/demo", response_model=BundlePresentation)
    async def demo() -> BundlePresentation | JSONResponse:
        try:
            return present_bundle(root, registry, "demo", PresentationSource.DEMO)
        except (BundleNotFoundError, BundleIntegrityError, OSError, ValueError):
            return _error(
                503,
                "DEMO_BUNDLE_UNAVAILABLE",
                "The verified demonstration bundle is unavailable.",
            )

    @application.post(
        "/api/v1/verifications",
        response_model=StartVerificationResponse,
        status_code=202,
    )
    async def start_verification(request: Request) -> StartVerificationResponse | JSONResponse:
        content_type = request.headers.get("content-type", "").split(";", 1)[0].strip().lower()
        if content_type != "application/json":
            return _error(400, "INVALID_REQUEST", "Content-Type must be application/json.")
        if request.headers.get("x-fixrepro-action") != "run-verification":
            return _error(
                400,
                "ACTION_HEADER_REQUIRED",
                "X-FixRepro-Action must be run-verification.",
            )
        try:
            raw = await request.body()
            parsed = json.loads(raw)
            if not isinstance(parsed, dict):
                raise ValueError("request body must be an object")
            StartVerificationRequest.model_validate(parsed)
        except (UnicodeError, json.JSONDecodeError, ValidationError, ValueError):
            return _error(400, "INVALID_REQUEST", "The request body must be an empty JSON object.")
        try:
            return manager.start_job()
        except VerificationAlreadyRunningError:
            return _error(
                409,
                "VERIFICATION_ALREADY_RUNNING",
                "A deterministic verification is already running.",
            )
        except VerificationManagerShuttingDownError:
            return _error(
                503,
                "VERIFICATION_START_FAILED",
                "The dashboard is shutting down and cannot start a verification.",
            )
        except RuntimeError:
            LOGGER.exception("Could not start verification worker")
            return _error(
                500,
                "VERIFICATION_START_FAILED",
                "The verification worker could not be started.",
            )

    @application.get(
        "/api/v1/verifications/{job_id}",
        response_model=JobStatusResponse,
    )
    async def verification_status(job_id: str) -> JobStatusResponse | JSONResponse:
        result = manager.get_job(job_id)
        if result is None:
            return _error(404, "JOB_NOT_FOUND", "The verification job was not found.")
        return result

    def artifact_response(bundle_id: str, artifact: str) -> FileResponse | JSONResponse:
        try:
            bundle_path, _ = verify_registered_bundle(root, registry, bundle_id)
        except BundleNotFoundError:
            return _error(404, "BUNDLE_NOT_FOUND", "The evidence bundle was not found.")
        except (BundleIntegrityError, OSError, ValueError):
            return _error(
                409,
                "BUNDLE_INTEGRITY_FAILURE",
                "The evidence bundle no longer passes integrity verification.",
            )
        filename, media_type = ALLOWED_ARTIFACTS[artifact]
        path = bundle_path / filename
        if not path.is_file() or path.is_symlink() or path.resolve().parent != bundle_path:
            return _error(
                409,
                "BUNDLE_INTEGRITY_FAILURE",
                "The requested evidence artifact is unavailable.",
            )
        return FileResponse(path, media_type=media_type)

    @application.get("/api/v1/bundles/{bundle_id}/report", response_model=None)
    async def bundle_report(bundle_id: str) -> FileResponse | JSONResponse:
        return artifact_response(bundle_id, "report")

    @application.get("/api/v1/bundles/{bundle_id}/evidence", response_model=None)
    async def bundle_evidence(bundle_id: str) -> FileResponse | JSONResponse:
        return artifact_response(bundle_id, "evidence")

    @application.get("/api/v1/bundles/{bundle_id}/manifest", response_model=None)
    async def bundle_manifest(bundle_id: str) -> FileResponse | JSONResponse:
        return artifact_response(bundle_id, "manifest")

    @application.get("/api/v1/bundles/{bundle_id}/digest", response_model=None)
    async def bundle_digest(bundle_id: str) -> FileResponse | JSONResponse:
        return artifact_response(bundle_id, "digest")

    return application


app = create_app(resolve_repository_root())
