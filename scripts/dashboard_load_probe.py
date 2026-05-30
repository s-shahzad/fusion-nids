#!/usr/bin/env python
from __future__ import annotations

import argparse
import statistics
import time
import urllib.error
import urllib.parse
import urllib.request


def _request(url: str, timeout: float) -> int:
    request = urllib.request.Request(url=url, method="GET")
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            response.read()
            return int(response.status)
    except urllib.error.HTTPError as exc:
        return int(exc.code)
    except Exception:
        return 0


def _percentile(sorted_values: list[float], p: float) -> float:
    if not sorted_values:
        return 0.0
    if p <= 0:
        return sorted_values[0]
    if p >= 100:
        return sorted_values[-1]
    rank = (p / 100.0) * (len(sorted_values) - 1)
    lower = int(rank)
    upper = min(lower + 1, len(sorted_values) - 1)
    fraction = rank - lower
    return sorted_values[lower] * (1.0 - fraction) + sorted_values[upper] * fraction


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Lightweight dashboard HTTP latency probe.")
    parser.add_argument("--host", default="127.0.0.1", help="Dashboard host.")
    parser.add_argument("--port", type=int, default=8000, help="Dashboard port.")
    parser.add_argument("--path", default="/api/realtime", help="Endpoint path to probe.")
    parser.add_argument("--token", default="", help="Optional API token query value.")
    parser.add_argument("--requests", type=int, default=120, help="Total probe requests (including warmup).")
    parser.add_argument("--warmup", type=int, default=10, help="Warmup requests excluded from latency stats.")
    parser.add_argument("--timeout", type=float, default=5.0, help="HTTP timeout in seconds.")
    parser.add_argument("--p95-max-ms", type=float, default=750.0, help="Fail if p95 latency exceeds this threshold.")
    parser.add_argument("--max-error-rate", type=float, default=0.01, help="Fail if HTTP error rate exceeds this ratio.")
    args = parser.parse_args(argv)

    total_requests = max(1, int(args.requests))
    warmup_count = max(0, min(int(args.warmup), total_requests - 1))

    base = f"http://{args.host}:{args.port}{args.path}"
    if args.token:
        token_q = urllib.parse.quote(str(args.token), safe="")
        sep = "&" if "?" in base else "?"
        url = f"{base}{sep}token={token_q}"
    else:
        url = base

    latencies_ms: list[float] = []
    status_counts: dict[int, int] = {}

    for idx in range(total_requests):
        started = time.perf_counter()
        status_code = _request(url=url, timeout=float(args.timeout))
        elapsed_ms = (time.perf_counter() - started) * 1000.0
        status_counts[status_code] = int(status_counts.get(status_code, 0)) + 1
        if idx >= warmup_count:
            latencies_ms.append(elapsed_ms)

    sample_count = len(latencies_ms)
    if sample_count <= 0:
        print("FAIL load_probe: no samples collected")
        return 1

    sorted_latencies = sorted(latencies_ms)
    p50 = _percentile(sorted_latencies, 50.0)
    p95 = _percentile(sorted_latencies, 95.0)
    p99 = _percentile(sorted_latencies, 99.0)
    avg = float(statistics.mean(sorted_latencies))
    min_ms = float(sorted_latencies[0])
    max_ms = float(sorted_latencies[-1])

    success_count = sum(count for status, count in status_counts.items() if 200 <= int(status) < 300)
    error_count = total_requests - success_count
    error_rate = float(error_count) / float(total_requests)

    print(f"endpoint={url}")
    print(f"requests_total={total_requests} warmup={warmup_count} samples={sample_count}")
    print(f"status_counts={status_counts}")
    print(
        "latency_ms "
        f"min={min_ms:.2f} avg={avg:.2f} p50={p50:.2f} p95={p95:.2f} p99={p99:.2f} max={max_ms:.2f}"
    )
    print(f"error_rate={error_rate:.4f} threshold={float(args.max_error_rate):.4f}")

    failures: list[str] = []
    if p95 > float(args.p95_max_ms):
        failures.append(f"p95_latency_exceeded({p95:.2f}>{float(args.p95_max_ms):.2f})")
    if error_rate > float(args.max_error_rate):
        failures.append(f"error_rate_exceeded({error_rate:.4f}>{float(args.max_error_rate):.4f})")

    if failures:
        print("FAIL load_probe: " + ",".join(failures))
        return 1

    print("PASS load_probe")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
