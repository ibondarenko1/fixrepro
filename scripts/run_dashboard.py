#!/usr/bin/env python3
"""Run the FixRepro judge-facing dashboard on an approved local bind."""

from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import uvicorn

from app.main import create_app


LOCAL_HOST = "127.0.0.1"
CONTAINER_HOST = "0.0.0.0"


def valid_port(value: str) -> int:
    try:
        port = int(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("port must be an integer") from exc
    if not 1 <= port <= 65535:
        raise argparse.ArgumentTypeError("port must be between 1 and 65535")
    return port


def validate_host(host: str, container_mode: bool) -> str:
    if host == LOCAL_HOST:
        return host
    if host == CONTAINER_HOST and container_mode:
        return host
    raise ValueError(
        "host must be 127.0.0.1; 0.0.0.0 is allowed only when "
        "FIXREPRO_CONTAINER_MODE is exactly 1"
    )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--host", default=LOCAL_HOST)
    parser.add_argument("--port", type=valid_port, default=8000)
    args = parser.parse_args()
    container_mode = os.environ.get("FIXREPRO_CONTAINER_MODE") == "1"
    try:
        host = validate_host(args.host, container_mode)
        dashboard = create_app(ROOT)
    except (RuntimeError, ValueError) as exc:
        print(f"DASHBOARD_START_ERROR={exc}", file=sys.stderr)
        return 1
    visible_host = LOCAL_HOST if host == CONTAINER_HOST else host
    print(f"FixRepro dashboard: http://{visible_host}:{args.port}", flush=True)
    uvicorn.run(
        dashboard,
        host=host,
        port=args.port,
        access_log=False,
        log_level="info",
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
