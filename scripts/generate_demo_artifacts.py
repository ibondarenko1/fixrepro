#!/usr/bin/env python3
"""Generate fresh public keys and harmless synthetic OTA packages."""

from __future__ import annotations

from pathlib import Path

from fixrepro_core.artifacts import generate_demo_artifacts


ROOT = Path(__file__).resolve().parents[1]


def main() -> int:
    artifacts = generate_demo_artifacts(ROOT / ".runtime")
    print(f"Generated synthetic runtime artifacts under: {artifacts.runtime_dir}")
    print(f"Trusted public key: {artifacts.trusted_public_key_path}")
    print(f"Untrusted public key: {artifacts.untrusted_public_key_path}")
    print(f"Untrusted package: {artifacts.untrusted_package_path}")
    print(f"Trusted package: {artifacts.trusted_package_path}")
    print("No private key was serialized.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
