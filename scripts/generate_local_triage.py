from __future__ import annotations

import argparse
import json
import os
import re
import sqlite3
import subprocess
import sys
import uuid
from collections import Counter
from pathlib import Path
from typing import Any


REPO_ROOT = Path(__file__).resolve().parents[1]
CANONICAL_TRIAGE_CMD = REPO_ROOT / "scripts" / "run_nids_triage_agent.cmd"
MAX_ALERTS = 8
MAX_FLOWS = 0
MAX_REPORT_CHARS = 0
MAX_DIGEST_CHARS = 900
MAX_TRIAGE_ALERTS = 3
MAX_NOTABLE_ALERTS = 3
TRIAGE_PROCESS_TIMEOUT_SEC = 6
TRIAGE_FIELDS = (
    "alert_summary",
    "severity_assessment",
    "likely_cause",
    "recommended_action",
)
SEVERITY_PRIORITY = {
    "critical": 5,
    "high": 4,
    "medium": 3,
    "low": 2,
    "info": 1,
    "unknown": 0,
}


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Generate narrow local AI triage text files from an existing NIDS run/output directory."
    )
    parser.add_argument(
        "run_path",
        help="Path to an existing NIDS run/output directory containing alerts.jsonl, flows.jsonl, nids.db, and optional report files.",
    )
    parser.add_argument(
        "--out-dir",
        help="Optional output directory for triage files. Defaults to <run_path>/triage.",
    )
    return parser.parse_args()


def read_jsonl(path: Path, limit: int | None = None) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    if not path.exists():
        return rows
    with path.open("r", encoding="utf-8") as handle:
        for line in handle:
            line = line.strip()
            if not line:
                continue
            try:
                rows.append(json.loads(line))
            except json.JSONDecodeError:
                continue
            if limit is not None and len(rows) >= limit:
                break
    return rows


def query_db_summary(path: Path) -> dict[str, Any]:
    summary: dict[str, Any] = {
        "table_counts": {},
        "top_rules": [],
        "severity_counts": {},
        "engine_counts": {},
    }
    if not path.exists():
        return summary
    with sqlite3.connect(path) as conn:
        cur = conn.cursor()
        for table in ("alerts", "flows", "metrics", "incident_actions", "suppression_rules"):
            try:
                count = cur.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]
                summary["table_counts"][table] = int(count)
            except sqlite3.Error:
                continue
        try:
            summary["top_rules"] = cur.execute(
                "SELECT rule_name, COUNT(*) AS c FROM alerts GROUP BY rule_name ORDER BY c DESC, rule_name ASC LIMIT 8"
            ).fetchall()
            summary["severity_counts"] = dict(
                cur.execute("SELECT severity, COUNT(*) FROM alerts GROUP BY severity ORDER BY COUNT(*) DESC").fetchall()
            )
            summary["engine_counts"] = dict(
                cur.execute("SELECT engine, COUNT(*) FROM alerts GROUP BY engine ORDER BY COUNT(*) DESC").fetchall()
            )
        except sqlite3.Error:
            pass
    return summary


def find_report_files(run_dir: Path) -> list[Path]:
    candidates = sorted(
        [
            path
            for path in run_dir.iterdir()
            if path.is_file() and path.suffix.lower() in {".md", ".txt", ".json"}
            and path.name not in {"alerts.jsonl", "flows.jsonl", "metrics.jsonl"}
        ]
    )
    return candidates[:6]


def alert_priority(row: dict[str, Any]) -> tuple[float, float, str]:
    severity = str(row.get("severity", "unknown")).lower()
    severity_score = float(SEVERITY_PRIORITY.get(severity, 0))
    raw_score = row.get("fusion_score")
    if raw_score is None:
        raw_score = row.get("supervised_score")
    if raw_score is None:
        raw_score = row.get("unsupervised_score")
    try:
        numeric_score = float(raw_score)
    except (TypeError, ValueError):
        numeric_score = 0.0
    timestamp = str(row.get("timestamp") or "")
    return (severity_score, numeric_score, timestamp)


def dedupe_and_prioritize_alerts(alerts: list[dict[str, Any]]) -> list[dict[str, Any]]:
    ranked = sorted(alerts, key=alert_priority, reverse=True)
    return ranked[:MAX_TRIAGE_ALERTS]


def render_digest(run_dir: Path) -> str:
    alerts_path = run_dir / "alerts.jsonl"
    flows_path = run_dir / "flows.jsonl"
    db_path = run_dir / "nids.db"

    alerts = read_jsonl(alerts_path)
    prioritized_alerts = dedupe_and_prioritize_alerts(alerts)
    flows = read_jsonl(flows_path, limit=MAX_FLOWS)
    db_summary = query_db_summary(db_path)

    severity_counts = Counter(str(row.get("severity", "unknown")) for row in prioritized_alerts)
    engine_counts = Counter(str(row.get("engine", "unknown")) for row in prioritized_alerts)
    src_counts = Counter(str(row.get("src_ip", "unknown")) for row in prioritized_alerts)
    dst_counts = Counter(str(row.get("dst_ip", "unknown")) for row in prioritized_alerts)
    rule_counts = Counter(str(row.get("rule_name", "unknown")) for row in prioritized_alerts)

    lines = [
        f"Run path: {run_dir}",
        f"Alert count: {len(alerts)}",
        f"Alerts selected for triage: {len(prioritized_alerts)}",
        f"Alert severities: {json.dumps(dict(severity_counts.most_common()), sort_keys=True)}",
        f"Top rules: {json.dumps(dict(rule_counts.most_common(3)), sort_keys=True)}",
        "",
        "Top 3 alerts:",
    ]

    for row in prioritized_alerts[:MAX_NOTABLE_ALERTS]:
        lines.append(
            "- "
            + f"{row.get('timestamp')} | {row.get('severity')} | {row.get('engine')} | "
            + f"{row.get('rule_name')} | {row.get('src_ip')} -> {row.get('dst_ip')}:{row.get('dst_port')} "
            + f"{row.get('proto')} | {row.get('summary')}"
        )

    digest = "\n".join(lines)
    if len(digest) > MAX_DIGEST_CHARS:
        digest = digest[:MAX_DIGEST_CHARS]
    return digest


def extract_json_objects(raw: str) -> list[dict[str, Any]]:
    decoder = json.JSONDecoder()
    objects: list[dict[str, Any]] = []
    index = 0
    while index < len(raw):
        while index < len(raw) and raw[index].isspace():
            index += 1
        if index >= len(raw):
            break
        try:
            obj, next_index = decoder.raw_decode(raw, index)
        except json.JSONDecodeError:
            index += 1
            continue
        if isinstance(obj, dict):
            objects.append(obj)
        index = next_index
    return objects


def sanitize_name_part(value: str) -> str:
    text = re.sub(r"[^A-Za-z0-9._-]+", "_", value.strip())
    text = text.strip("._-")
    return text or "run"


def parse_triage_payload(raw: str) -> dict[str, Any]:
    text = raw.strip()
    if not text:
        return {}

    try:
        payload = json.loads(text)
        if isinstance(payload, dict):
            return payload
    except json.JSONDecodeError:
        pass

    objects = extract_json_objects(text)
    for obj in reversed(objects):
        if isinstance(obj, dict):
            return obj
    return {}


def normalize_triage_payload(raw: str) -> dict[str, str]:
    payload = parse_triage_payload(raw)
    normalized = {field: "" for field in TRIAGE_FIELDS}
    aliases = {
        "alert_summary": ("alert_summary", "summary", "alertSummary"),
        "severity_assessment": ("severity_assessment", "severity", "severityAssessment"),
        "likely_cause": ("likely_cause", "cause", "likelyCause"),
        "recommended_action": ("recommended_action", "recommendedAction", "action", "next_steps"),
    }
    for target, keys in aliases.items():
        for key in keys:
            value = payload.get(key)
            if value is not None and str(value).strip():
                normalized[target] = str(value).strip()
                break

    if not any(normalized.values()):
        normalized["alert_summary"] = raw.strip()

    for field in TRIAGE_FIELDS:
        if not normalized[field]:
            normalized[field] = "Unavailable from local AI triage output."
    return normalized


def invoke_nids_triage(prompt: str, session_id: str) -> str:
    if not CANONICAL_TRIAGE_CMD.exists():
        raise FileNotFoundError(f"Canonical triage entrypoint not found: {CANONICAL_TRIAGE_CMD}")

    proc = subprocess.Popen(
        [str(CANONICAL_TRIAGE_CMD), "--json", "--session-id", session_id, "--message", prompt],
        cwd=REPO_ROOT,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        creationflags=getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0),
    )
    timed_out = False
    try:
        stdout, stderr = proc.communicate(timeout=TRIAGE_PROCESS_TIMEOUT_SEC)
    except subprocess.TimeoutExpired as exc:
        timed_out = True
        stdout = exc.stdout or ""
        stderr = exc.stderr or ""
        _terminate_process_tree(proc)
        proc.wait(timeout=5)

    if proc.returncode not in (0, None) and not timed_out:
        raise RuntimeError(stderr.strip() or stdout.strip() or f"nids-triage returned {proc.returncode}")

    objects = extract_json_objects(stdout)
    if not objects:
        text = stdout.strip()
        if text:
            return text
        if timed_out:
            raise RuntimeError(
                f"nids-triage exceeded {TRIAGE_PROCESS_TIMEOUT_SEC}s without returning parsable output"
            )
        raise RuntimeError("No parsable response returned by nids-triage")

    for obj in reversed(objects):
        if any(key in obj for key in TRIAGE_FIELDS):
            return json.dumps(obj, ensure_ascii=True)

    final = objects[-1]
    payloads = final.get("result", {}).get("payloads", [])
    text_parts = [str(item.get("text", "")).strip() for item in payloads if str(item.get("text", "")).strip()]
    if text_parts:
        return "\n\n".join(text_parts).strip()
    if timed_out:
        raise RuntimeError(f"nids-triage exceeded {TRIAGE_PROCESS_TIMEOUT_SEC}s before yielding text payload")
    raise RuntimeError("nids-triage returned no text payload")


def _terminate_process_tree(proc: subprocess.Popen[str]) -> None:
    if proc.poll() is not None:
        return
    try:
        if os.name == "nt":
            subprocess.run(
                ["taskkill", "/PID", str(proc.pid), "/T", "/F"],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                check=False,
                creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
            )
        else:
            proc.kill()
    except OSError:
        proc.kill()


def build_local_triage_payload(alerts: list[dict[str, Any]]) -> dict[str, str]:
    selected = alerts[:MAX_TRIAGE_ALERTS]
    if not selected:
        return {
            "alert_summary": "No alerts available for triage.",
            "severity_assessment": "No alert severity available.",
            "likely_cause": "No alert evidence was present in the run folder.",
            "recommended_action": "Verify the run output and rerun detection if triage is required.",
        }

    top = selected[0]
    summary_bits = [
        f"{row.get('severity', 'unknown')} {row.get('rule_name', 'unknown')}"
        f" from {row.get('src_ip', 'unknown')} to {row.get('dst_ip', 'unknown')}:{row.get('dst_port', 'unknown')}"
        for row in selected
    ]
    highest_severity = str(top.get("severity", "unknown")).lower()
    likely_cause = str(top.get("rule_name") or top.get("summary") or "Suspicious network activity")
    return {
        "alert_summary": "; ".join(summary_bits),
        "severity_assessment": f"Top severity is {highest_severity} based on the highest-ranked 3 alerts.",
        "likely_cause": likely_cause,
        "recommended_action": "Review the listed source and destination activity, validate legitimacy, and isolate affected systems if unauthorized behavior is confirmed.",
    }


def generate_outputs(run_dir: Path, out_dir: Path) -> list[Path]:
    digest = render_digest(run_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    selected_alerts = dedupe_and_prioritize_alerts(read_jsonl(run_dir / "alerts.jsonl"))

    prompt = (
        "Local NIDS triage only.\n"
        "Use only this local evidence.\n"
        "Focus only on the top 3 ranked alerts shown below.\n"
        "Return exactly one JSON object with these string fields:\n"
        '- "alert_summary": concise summary of the alert pattern and affected endpoints\n'
        '- "severity_assessment": concise severity assessment with confidence or caveat\n'
        '- "likely_cause": most likely cause based on the available evidence\n'
        '- "recommended_action": immediate recommended analyst action\n'
        "Do not include markdown. Do not include any keys beyond those four.\n\n"
        f"{digest}"
    )

    session_id = f"local-triage-{sanitize_name_part(run_dir.name)}-{uuid.uuid4().hex}"
    try:
        text = invoke_nids_triage(prompt=prompt, session_id=session_id)
        payload = normalize_triage_payload(text)
    except Exception:
        payload = build_local_triage_payload(selected_alerts)
    out_path = out_dir / f"triage_{sanitize_name_part(run_dir.name)}.json"
    out_path.write_text(json.dumps(payload, indent=2, ensure_ascii=True) + "\n", encoding="utf-8")
    return [out_path]


def main() -> int:
    args = parse_args()
    run_dir = Path(args.run_path).resolve()
    if not run_dir.exists() or not run_dir.is_dir():
        raise SystemExit(f"Run path does not exist or is not a directory: {run_dir}")

    out_dir = Path(args.out_dir).resolve() if args.out_dir else run_dir / "triage"
    created = generate_outputs(run_dir=run_dir, out_dir=out_dir)
    for path in created:
        print(path)
    return 0


if __name__ == "__main__":
    sys.exit(main())
