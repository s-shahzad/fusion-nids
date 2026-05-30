#!/usr/bin/env python
from __future__ import annotations

import argparse
import socket
import ssl
from dataclasses import dataclass
from datetime import datetime, timezone
from urllib.parse import urlparse


@dataclass
class TLSSnapshot:
    host: str
    port: int
    tls_version: str
    cipher: str
    valid_from: datetime
    valid_until: datetime
    days_remaining: float


def _parse_cert_time(value: str) -> datetime:
    try:
        parsed = datetime.strptime(value, "%b %d %H:%M:%S %Y %Z")
    except ValueError:
        parsed = datetime.strptime(value, "%b %d %H:%M:%S %Y GMT")
    return parsed.replace(tzinfo=timezone.utc)


def _parse_https_target(url: str) -> tuple[str, int]:
    parsed = urlparse(str(url).strip())
    scheme = str(parsed.scheme or "").lower()
    if scheme != "https":
        raise ValueError("Target URL must use https scheme")

    host = str(parsed.hostname or "").strip()
    if host == "":
        raise ValueError("Target URL must include a hostname")

    port = int(parsed.port or 443)
    if port <= 0 or port > 65535:
        raise ValueError("Target URL has an invalid port")

    return host, port


def _collect_tls_snapshot(host: str, port: int, timeout: float) -> TLSSnapshot:
    context = ssl.create_default_context()
    with socket.create_connection((host, int(port)), timeout=float(timeout)) as tcp_sock:
        with context.wrap_socket(tcp_sock, server_hostname=host) as tls_sock:
            cert = tls_sock.getpeercert()
            if not cert:
                raise RuntimeError("Peer certificate was not presented")

            not_before = str(cert.get("notBefore") or "").strip()
            not_after = str(cert.get("notAfter") or "").strip()
            if not_before == "" or not_after == "":
                raise RuntimeError("Peer certificate is missing notBefore/notAfter fields")

            valid_from = _parse_cert_time(not_before)
            valid_until = _parse_cert_time(not_after)
            now_utc = datetime.now(timezone.utc)
            days_remaining = (valid_until - now_utc).total_seconds() / 86400.0

            cipher_info = tls_sock.cipher() or ("", "", 0)
            return TLSSnapshot(
                host=host,
                port=int(port),
                tls_version=str(tls_sock.version() or ""),
                cipher=str(cipher_info[0] or ""),
                valid_from=valid_from,
                valid_until=valid_until,
                days_remaining=days_remaining,
            )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Audit TLS certificate and protocol properties for an HTTPS endpoint."
    )
    parser.add_argument("--url", required=True, help="HTTPS URL to audit (for example: https://nids.example.com).")
    parser.add_argument("--timeout", type=float, default=5.0, help="Socket timeout in seconds.")
    parser.add_argument(
        "--min-days-valid",
        type=float,
        default=14.0,
        help="Fail if cert validity remaining is below this threshold in days.",
    )
    parser.add_argument(
        "--allow-legacy-tls",
        action="store_true",
        help="Allow TLS versions older than TLS 1.2.",
    )
    args = parser.parse_args(argv)

    try:
        host, port = _parse_https_target(str(args.url))
    except Exception as exc:
        print(f"FAIL tls_target: {exc}")
        return 1

    try:
        snapshot = _collect_tls_snapshot(host=host, port=port, timeout=float(args.timeout))
    except ssl.SSLCertVerificationError as exc:
        print(f"FAIL tls_verification: {exc}")
        return 1
    except ssl.SSLError as exc:
        print(f"FAIL tls_handshake: {exc}")
        return 1
    except socket.timeout:
        print(f"FAIL tls_timeout: unable to connect to {host}:{port} within {float(args.timeout):.1f}s")
        return 1
    except Exception as exc:
        print(f"FAIL tls_connect: {exc}")
        return 1

    failures: list[str] = []
    if not args.allow_legacy_tls and snapshot.tls_version not in {"TLSv1.2", "TLSv1.3"}:
        failures.append(f"tls_version_too_old({snapshot.tls_version})")

    if snapshot.days_remaining < float(args.min_days_valid):
        failures.append(
            f"certificate_expiry_window_too_small({snapshot.days_remaining:.2f}<{float(args.min_days_valid):.2f})"
        )

    print(f"host={snapshot.host} port={snapshot.port}")
    print(f"tls_version={snapshot.tls_version} cipher={snapshot.cipher}")
    print(
        "certificate_validity "
        f"not_before={snapshot.valid_from.isoformat()} "
        f"not_after={snapshot.valid_until.isoformat()} "
        f"days_remaining={snapshot.days_remaining:.2f}"
    )

    if failures:
        print("FAIL tls_audit: " + ",".join(failures))
        return 1

    print("PASS tls_audit")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
