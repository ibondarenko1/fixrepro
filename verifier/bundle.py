"""Atomic bundle writing, manifest creation, publication, and verification."""

from __future__ import annotations

import hashlib
import json
import os
import re
import secrets
import shutil
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any

from jsonschema import Draft202012Validator, FormatChecker, SchemaError
from pydantic import ValidationError

from fixrepro_core.crypto import (
    load_public_key_bytes,
    signer_fingerprint,
    verify_manifest_signature,
)
from fixrepro_core.package import (
    PackageValidationError,
    parse_and_decode_package,
    verify_payload_integrity,
)

from .models import (
    ArtifactRecord,
    BundleManifest,
    EvidenceDocument,
    ExecutionRole,
    ManifestEntry,
    RawScenarioRecord,
    SignerTrust,
    VerificationOutcome,
)
from .verdicts import (
    calculate_verification_outcome,
    evidence_consistency_failures,
)


MANIFEST_NAME = "manifest.json"
MANIFEST_DIGEST_NAME = "manifest.sha256"
MANIFEST_DIGEST_RE = re.compile(r"^([a-f0-9]{64})  manifest\.json\n$")
EXPECTED_EVIDENCE_ARTIFACTS = {
    "packages/untrusted-update.json",
    "packages/trusted-update.json",
    "raw/vulnerable.json",
    "raw/patched.json",
    "raw/positive-control.json",
    "trust/trusted-public-key.pem",
    "run.log",
}


class BundleError(RuntimeError):
    """A bundle cannot be safely generated or published."""


@dataclass(frozen=True)
class BundleVerificationResult:
    valid: bool
    failures: tuple[str, ...]
    verification_outcome: VerificationOutcome | None
    manifest_sha256: str | None
    manifest_entry_count: int


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def atomic_write_bytes(path: Path, content: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.{secrets.token_hex(6)}.tmp")
    try:
        with temporary.open("wb") as handle:
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        temporary.replace(path)
    finally:
        if temporary.exists():
            temporary.unlink()


def atomic_write_text(path: Path, content: str) -> None:
    atomic_write_bytes(path, content.encode("utf-8"))


def deterministic_json_bytes(value: Any) -> bytes:
    return (
        json.dumps(
            value,
            sort_keys=True,
            indent=2,
            ensure_ascii=False,
            allow_nan=False,
        )
        + "\n"
    ).encode("utf-8")


def atomic_write_json(path: Path, value: Any) -> None:
    atomic_write_bytes(path, deterministic_json_bytes(value))


def artifact_record(bundle_root: Path, relative_path: str, media_type: str) -> ArtifactRecord:
    path = bundle_root / Path(*PurePosixPath(relative_path).parts)
    return ArtifactRecord(
        path=relative_path,
        sha256=sha256_file(path),
        size_bytes=path.stat().st_size,
        media_type=media_type,
    )


def _manifest_entries(bundle_root: Path) -> list[ManifestEntry]:
    entries: list[ManifestEntry] = []
    for path in sorted(bundle_root.rglob("*")):
        if not path.is_file():
            continue
        if path.is_symlink():
            raise BundleError(f"bundle file may not be a symlink: {path.name}")
        relative = path.relative_to(bundle_root).as_posix()
        if relative in {MANIFEST_NAME, MANIFEST_DIGEST_NAME}:
            continue
        entries.append(
            ManifestEntry(
                path=relative,
                sha256=sha256_file(path),
                size_bytes=path.stat().st_size,
            )
        )
    return entries


def write_manifest(bundle_root: Path) -> tuple[BundleManifest, str]:
    manifest = BundleManifest(schema_version="1.0.0", files=_manifest_entries(bundle_root))
    manifest_path = bundle_root / MANIFEST_NAME
    atomic_write_json(manifest_path, manifest.model_dump(mode="json"))
    digest = sha256_file(manifest_path)
    atomic_write_text(bundle_root / MANIFEST_DIGEST_NAME, f"{digest}  {MANIFEST_NAME}\n")
    return manifest, digest


def _reject_json_constant(value: str) -> None:
    raise ValueError(f"non-finite JSON value is prohibited: {value}")


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def load_strict_json(path: Path) -> Any:
    return json.loads(
        path.read_text(encoding="utf-8"),
        parse_constant=_reject_json_constant,
        object_pairs_hook=_reject_duplicate_keys,
    )


def _safe_relative_path(value: str) -> tuple[PurePosixPath | None, str | None]:
    if "\\" in value:
        return None, "must use POSIX separators"
    if re.match(r"^[A-Za-z]:", value):
        return None, "must not use a drive letter"
    path = PurePosixPath(value)
    if path.is_absolute():
        return None, "must not be absolute"
    if not path.parts or ".." in path.parts or "." in path.parts:
        return None, "contains an unsafe path component"
    if path.as_posix() != value:
        return None, "is not a normalized relative POSIX path"
    return path, None


def _all_bundle_files(bundle_root: Path, failures: list[str]) -> set[str]:
    found: set[str] = set()
    for directory, directory_names, file_names in os.walk(bundle_root, followlinks=False):
        base = Path(directory)
        for name in list(directory_names):
            path = base / name
            if path.is_symlink():
                failures.append(
                    f"symlinked directory is prohibited: {path.relative_to(bundle_root).as_posix()}"
                )
        for name in file_names:
            path = base / name
            relative = path.relative_to(bundle_root).as_posix()
            found.add(relative)
            if path.is_symlink():
                failures.append(f"symlinked file is prohibited: {relative}")
    return found


def _record_failures(
    record: ArtifactRecord,
    bundle_root: Path,
    manifest_paths: set[str],
) -> list[str]:
    failures: list[str] = []
    safe_path, path_error = _safe_relative_path(record.path)
    if path_error is not None or safe_path is None:
        return [f"evidence artifact path {record.path!r} {path_error}"]
    if record.path not in manifest_paths:
        failures.append(f"evidence artifact is not listed in manifest: {record.path}")
    path = bundle_root / Path(*safe_path.parts)
    if not path.is_file() or path.is_symlink():
        failures.append(f"evidence artifact is missing or unsafe: {record.path}")
        return failures
    if path.stat().st_size != record.size_bytes:
        failures.append(f"evidence artifact size mismatch: {record.path}")
    if sha256_file(path) != record.sha256:
        failures.append(f"evidence artifact SHA-256 mismatch: {record.path}")
    return failures


def _package_record_failures(
    execution: Any,
    bundle_root: Path,
    manifest_paths: set[str],
) -> list[str]:
    failures: list[str] = []
    filename = execution.package.filename
    safe_path, path_error = _safe_relative_path(filename)
    if path_error is not None or safe_path is None:
        return [f"package path {filename!r} {path_error}"]
    if filename not in manifest_paths:
        failures.append(f"package is not listed in manifest: {filename}")
    path = bundle_root / Path(*safe_path.parts)
    if not path.is_file() or path.is_symlink():
        failures.append(f"package is missing or unsafe: {filename}")
        return failures
    raw = path.read_bytes()
    if sha256_bytes(raw) != execution.package.envelope_sha256:
        failures.append(f"package envelope SHA-256 mismatch: {filename}")
    try:
        package = parse_and_decode_package(raw)
        verify_payload_integrity(package)
    except PackageValidationError as exc:
        failures.append(f"package validation failed for {filename}: {exc}")
        return failures
    if package.envelope.manifest.payload_sha256 != execution.package.sha256:
        failures.append(f"package payload SHA-256 evidence mismatch: {filename}")
    if signer_fingerprint(package.signer_public_key) != execution.package.signer_fingerprint:
        failures.append(f"package signer fingerprint evidence mismatch: {filename}")
    if not verify_manifest_signature(
        package.signer_public_key,
        package.envelope.manifest,
        package.signature,
    ):
        failures.append(f"package signature does not verify with its declared public key: {filename}")
    return failures


def _raw_record_failures(execution: Any, bundle_root: Path) -> list[str]:
    expected_path = {
        ExecutionRole.VULNERABLE: "raw/vulnerable.json",
        ExecutionRole.PATCHED: "raw/patched.json",
        ExecutionRole.POSITIVE_CONTROL: "raw/positive-control.json",
    }[execution.role]
    if len(execution.artifacts) != 1 or execution.artifacts[0].path != expected_path:
        return [f"{execution.role} must reference exactly {expected_path}"]
    path = bundle_root / Path(*expected_path.split("/"))
    try:
        record = RawScenarioRecord.model_validate_json(path.read_bytes())
    except (OSError, ValidationError) as exc:
        return [f"raw scenario record is invalid for {execution.role}: {exc}"]
    failures: list[str] = []
    comparisons = (
        ("execution ID", record.execution_id, execution.execution_id),
        ("role", record.role, execution.role),
        ("start time", record.started_at, execution.started_at),
        ("finish time", record.finished_at, execution.finished_at),
        ("request", record.request, execution.request),
        ("device state before", record.device_state_before, execution.device_state_before),
        ("device state after", record.device_state_after, execution.device_state_after),
    )
    for label, actual, expected in comparisons:
        if actual != expected:
            failures.append(f"{execution.role} raw {label} does not match evidence.json")
    if not record.reset_confirmed:
        failures.append(f"{execution.role} raw record does not confirm device reset")
    if record.gateway_response.get("decision") != execution.observed_decision:
        failures.append(f"{execution.role} raw gateway decision does not match evidence.json")
    if record.gateway_response.get("reason_code") != execution.response.reason_code:
        failures.append(f"{execution.role} raw gateway reason does not match evidence.json")
    return failures


def verify_bundle(
    bundle_root: Path,
    repository_root: Path,
    schema_path: Path,
    *,
    allow_external: bool = False,
) -> BundleVerificationResult:
    """Verify the complete bundle without changing any file."""

    failures: list[str] = []
    outcome: VerificationOutcome | None = None
    digest: str | None = None
    manifest_entry_count = 0

    if not bundle_root.is_dir():
        return BundleVerificationResult(False, ("supplied bundle path is not a directory",), None, None, 0)
    if bundle_root.is_symlink():
        return BundleVerificationResult(False, ("bundle directory may not be a symlink",), None, None, 0)

    resolved_root = bundle_root.resolve()
    resolved_repository = repository_root.resolve()
    if not allow_external and not resolved_root.is_relative_to(resolved_repository):
        failures.append("bundle directory is outside the repository")

    actual_files = _all_bundle_files(bundle_root, failures)
    digest_path = bundle_root / MANIFEST_DIGEST_NAME
    manifest_path = bundle_root / MANIFEST_NAME
    digest_text = ""
    if not digest_path.is_file() or digest_path.is_symlink():
        failures.append("manifest.sha256 is missing or unsafe")
    else:
        try:
            digest_text = digest_path.read_text(encoding="ascii")
        except (OSError, UnicodeError) as exc:
            failures.append(f"manifest.sha256 cannot be read: {exc}")
        match = MANIFEST_DIGEST_RE.fullmatch(digest_text)
        if match is None:
            failures.append("manifest.sha256 has an invalid format")
        else:
            digest = match.group(1)

    manifest: BundleManifest | None = None
    if not manifest_path.is_file() or manifest_path.is_symlink():
        failures.append("manifest.json is missing or unsafe")
    else:
        actual_manifest_digest = sha256_file(manifest_path)
        if digest is not None and actual_manifest_digest != digest:
            failures.append("manifest.json does not match manifest.sha256")
        try:
            manifest_document = load_strict_json(manifest_path)
            manifest = BundleManifest.model_validate(manifest_document)
        except (OSError, UnicodeError, ValueError, ValidationError) as exc:
            failures.append(f"manifest.json is invalid strict JSON: {exc}")

    manifest_paths: set[str] = set()
    if manifest is not None:
        manifest_entry_count = len(manifest.files)
        for entry in manifest.files:
            if entry.path in {MANIFEST_NAME, MANIFEST_DIGEST_NAME}:
                failures.append(f"manifest must not list itself or its digest: {entry.path}")
                continue
            safe_path, path_error = _safe_relative_path(entry.path)
            if path_error is not None or safe_path is None:
                failures.append(f"manifest path {entry.path!r} {path_error}")
                continue
            manifest_paths.add(entry.path)
            path = bundle_root / Path(*safe_path.parts)
            if not path.is_file() or path.is_symlink():
                failures.append(f"listed file is missing or unsafe: {entry.path}")
                continue
            if path.stat().st_size != entry.size_bytes:
                failures.append(f"listed file size mismatch: {entry.path}")
            if sha256_file(path) != entry.sha256:
                failures.append(f"listed file SHA-256 mismatch: {entry.path}")

        expected_files = manifest_paths | {MANIFEST_NAME, MANIFEST_DIGEST_NAME}
        for extra in sorted(actual_files - expected_files):
            failures.append(f"unexpected unlisted bundle file: {extra}")
        for missing in sorted(expected_files - actual_files):
            failures.append(f"expected bundle file is missing: {missing}")

    evidence: EvidenceDocument | None = None
    evidence_path = bundle_root / "evidence.json"
    if not evidence_path.is_file() or evidence_path.is_symlink():
        failures.append("evidence.json is missing or unsafe")
    else:
        try:
            evidence_document = load_strict_json(evidence_path)
        except (OSError, UnicodeError, ValueError) as exc:
            failures.append(f"evidence.json is invalid strict JSON: {exc}")
            evidence_document = None
        if evidence_document is not None:
            try:
                schema = load_strict_json(schema_path)
                Draft202012Validator.check_schema(schema)
                validator = Draft202012Validator(schema, format_checker=FormatChecker())
                schema_errors = sorted(
                    validator.iter_errors(evidence_document),
                    key=lambda error: list(error.absolute_path),
                )
                for error in schema_errors:
                    location = ".".join(str(part) for part in error.absolute_path) or "root"
                    failures.append(f"evidence schema error at {location}: {error.message}")
            except (OSError, UnicodeError, ValueError, SchemaError) as exc:
                failures.append(f"evidence schema cannot be applied: {exc}")
            try:
                evidence = EvidenceDocument.model_validate_json(evidence_path.read_bytes())
            except ValidationError as exc:
                failures.append(f"evidence.json violates the strict evidence model: {exc}")

    if evidence is not None:
        roles = [execution.role for execution in evidence.executions]
        if len(roles) != 3 or len(set(roles)) != 3:
            failures.append("evidence must contain exactly one execution for each role")
        vulnerable = next(
            (item for item in evidence.executions if item.role == "VULNERABLE"), None
        )
        patched = next((item for item in evidence.executions if item.role == "PATCHED"), None)
        if vulnerable is not None and patched is not None:
            if vulnerable.package.envelope_sha256 != patched.package.envelope_sha256:
                failures.append("vulnerable and patched envelope SHA-256 values differ")
            if vulnerable.request.body_sha256 != patched.request.body_sha256:
                failures.append("vulnerable and patched request body SHA-256 values differ")

        failures.extend(evidence_consistency_failures(evidence.executions))
        outcome = calculate_verification_outcome(evidence.executions)
        if evidence.verification_outcome != outcome:
            failures.append(
                "stored verification outcome does not match the recomputed outcome"
            )

        evidence_paths = {record.path for record in evidence.bundle_files}
        if evidence_paths != EXPECTED_EVIDENCE_ARTIFACTS:
            failures.append("evidence bundle_files does not contain the required seven artifacts")
        for record in evidence.bundle_files:
            failures.extend(_record_failures(record, bundle_root, manifest_paths))
        for execution in evidence.executions:
            failures.extend(_package_record_failures(execution, bundle_root, manifest_paths))
            failures.extend(_raw_record_failures(execution, bundle_root))
            for record in execution.artifacts:
                failures.extend(_record_failures(record, bundle_root, manifest_paths))

        by_role = {execution.role: execution for execution in evidence.executions}
        vulnerable_execution = by_role.get(ExecutionRole.VULNERABLE)
        patched_execution = by_role.get(ExecutionRole.PATCHED)
        positive_execution = by_role.get(ExecutionRole.POSITIVE_CONTROL)
        if vulnerable_execution is not None and vulnerable_execution.package.signer_trust != SignerTrust.UNTRUSTED:
            failures.append("vulnerable execution signer trust must be UNTRUSTED")
        if patched_execution is not None and patched_execution.package.signer_trust != SignerTrust.UNTRUSTED:
            failures.append("patched execution signer trust must be UNTRUSTED")
        if positive_execution is not None and positive_execution.package.signer_trust != SignerTrust.TRUSTED:
            failures.append("positive-control signer trust must be TRUSTED")
        trusted_key_path = bundle_root / "trust" / "trusted-public-key.pem"
        if positive_execution is not None and trusted_key_path.is_file() and not trusted_key_path.is_symlink():
            try:
                trusted_key = load_public_key_bytes(trusted_key_path)
                trusted_package_path = bundle_root / "packages" / "trusted-update.json"
                trusted_package = parse_and_decode_package(trusted_package_path.read_bytes())
                if trusted_package.signer_public_key != trusted_key:
                    failures.append("trusted package signer does not match trusted-public-key.pem")
                untrusted_package_path = bundle_root / "packages" / "untrusted-update.json"
                untrusted_package = parse_and_decode_package(untrusted_package_path.read_bytes())
                if untrusted_package.signer_public_key == trusted_key:
                    failures.append("untrusted package unexpectedly uses the trusted public key")
            except (OSError, ValueError, PackageValidationError) as exc:
                failures.append(f"bundle trust material cannot be validated: {exc}")

    if "report.html" not in manifest_paths or not (bundle_root / "report.html").is_file():
        failures.append("report.html is missing or not listed in the manifest")

    return BundleVerificationResult(
        valid=not failures,
        failures=tuple(failures),
        verification_outcome=outcome,
        manifest_sha256=digest,
        manifest_entry_count=manifest_entry_count,
    )


def publish_directory(staged: Path, destination: Path, *, replace: bool) -> None:
    """Publish a verified staged directory without leaving a partial replacement."""

    destination.parent.mkdir(parents=True, exist_ok=True)
    if destination.exists() and not replace:
        raise BundleError(f"output directory already exists: {destination}")
    if destination.is_symlink():
        raise BundleError("output directory may not be a symlink")
    if not destination.exists():
        staged.replace(destination)
        return

    backup = destination.with_name(f".{destination.name}.{secrets.token_hex(6)}.backup")
    destination.replace(backup)
    try:
        staged.replace(destination)
    except OSError as exc:
        backup.replace(destination)
        raise BundleError(f"could not publish replacement bundle: {exc}") from exc
    shutil.rmtree(backup)
