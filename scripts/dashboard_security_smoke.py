#!/usr/bin/env python
from __future__ import annotations

import argparse
import json
import sys
import urllib.error
import urllib.parse
import urllib.request
from typing import Any


def _request(
    method: str,
    url: str,
    *,
    timeout: float,
    headers: dict[str, str] | None = None,
    payload: dict[str, Any] | None = None,
) -> tuple[int, str]:
    request_headers = dict(headers or {})
    body: bytes | None = None
    if payload is not None:
        body = json.dumps(payload, ensure_ascii=True).encode("utf-8")
        request_headers.setdefault("content-type", "application/json")

    req = urllib.request.Request(url=url, data=body, headers=request_headers, method=method.upper())
    try:
        with urllib.request.urlopen(req, timeout=timeout) as response:
            return int(response.status), response.read().decode("utf-8", errors="replace")
    except urllib.error.HTTPError as exc:
        body_text = ""
        try:
            body_text = exc.read().decode("utf-8", errors="replace")
        except Exception:
            body_text = ""
        return int(exc.code), body_text


def _with_token(base_url: str, token: str) -> str:
    token_q = urllib.parse.quote(token, safe="")
    separator = "&" if "?" in base_url else "?"
    return f"{base_url}{separator}token={token_q}"


def _expect_status(label: str, actual: int, expected: int, body: str) -> None:
    if int(actual) == int(expected):
        print(f"PASS {label}: status={actual}")
        return

    print(f"FAIL {label}: expected={expected} actual={actual}")
    body_preview = body.strip().replace("\n", " ")
    if len(body_preview) > 300:
        body_preview = body_preview[:300] + "..."
    print(f"BODY {label}: {body_preview}")
    raise SystemExit(1)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Dashboard security smoke checks for token and RBAC enforcement.")
    parser.add_argument("--host", default="127.0.0.1", help="Dashboard host.")
    parser.add_argument("--port", type=int, default=8000, help="Dashboard port.")
    parser.add_argument("--view-token", required=True, help="Dashboard API token used for read endpoints.")
    parser.add_argument("--action-token", required=True, help="Dashboard action token used for write endpoints.")
    parser.add_argument("--timeout", type=float, default=5.0, help="HTTP timeout seconds.")
    parser.add_argument("--actor", default="security-smoke", help="Actor label used for write calls.")
    args = parser.parse_args(argv)

    base = f"http://{args.host}:{args.port}"

    status_code, body = _request("GET", f"{base}/api/realtime", timeout=args.timeout)
    _expect_status("realtime_without_token", status_code, 401, body)

    status_code, body = _request(
        "GET",
        _with_token(f"{base}/api/realtime", args.view_token),
        timeout=args.timeout,
    )
    _expect_status("realtime_with_view_token", status_code, 200, body)

    status_code, body = _request(
        "GET",
        _with_token(f"{base}/api/incidents", args.view_token),
        timeout=args.timeout,
    )
    _expect_status("incidents_with_view_token", status_code, 200, body)

    bulk_payload = {
        "incident_ids": [1],
        "status": "triage",
        "reason": "security smoke check",
    }

    wrong_action_headers = {
        "x-nids-token": args.view_token,
        "x-nids-actor": args.actor,
        "x-nids-role": "analyst",
    }
    status_code, body = _request(
        "POST",
        _with_token(f"{base}/api/incidents/bulk", args.view_token),
        timeout=args.timeout,
        headers=wrong_action_headers,
        payload=bulk_payload,
    )
    _expect_status("bulk_wrong_action_token", status_code, 401, body)

    viewer_headers = {
        "x-nids-token": args.action_token,
        "x-nids-actor": args.actor,
        "x-nids-role": "viewer",
    }
    status_code, body = _request(
        "POST",
        _with_token(f"{base}/api/incidents/bulk", args.view_token),
        timeout=args.timeout,
        headers=viewer_headers,
        payload=bulk_payload,
    )
    _expect_status("bulk_forbidden_role", status_code, 403, body)

    analyst_headers = {
        "x-nids-token": args.action_token,
        "x-nids-actor": args.actor,
        "x-nids-role": "analyst",
    }
    status_code, body = _request(
        "POST",
        _with_token(f"{base}/api/incidents/bulk", args.view_token),
        timeout=args.timeout,
        headers=analyst_headers,
        payload=bulk_payload,
    )
    _expect_status("bulk_authorized", status_code, 200, body)

    print("Security smoke checks completed successfully.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
