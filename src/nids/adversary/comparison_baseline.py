from __future__ import annotations

import json
import shutil
import time
from argparse import Namespace
from pathlib import Path
from typing import Any

import yaml

from ..config import _deep_merge, _read_yaml, build_runtime_config
from ..pipeline.runtime import run_local_pipeline


def _write_yaml(path: Path, payload: dict[str, Any]) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(yaml.safe_dump(payload, sort_keys=False), encoding="utf-8")
    return path


def _write_text(path: Path, content: str) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")
    return path


def _write_json(path: Path, payload: dict[str, Any]) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, ensure_ascii=True), encoding="utf-8")
    return path


def _reset_mode_run_dir(path: Path, *, root: Path) -> Path:
    resolved_root = root.resolve()
    resolved_path = path.resolve()
    try:
        resolved_path.relative_to(resolved_root)
    except ValueError as exc:
        raise ValueError(f"Refusing to reset comparison output outside {resolved_root}: {resolved_path}") from exc

    if resolved_path.exists():
        shutil.rmtree(resolved_path)
    resolved_path.mkdir(parents=True, exist_ok=True)
    return resolved_path


def _read_json(path: Path) -> dict[str, Any]:
    if not path.exists():
        return {}
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return {}
    return payload if isinstance(payload, dict) else {}


def _load_alerts(path: Path) -> list[dict[str, Any]]:
    if not path.exists():
        return []
    alerts: list[dict[str, Any]] = []
    for line in path.read_text(encoding="utf-8").splitlines():
        token = line.strip()
        if not token:
            continue
        try:
            payload = json.loads(token)
        except Exception:
            continue
        if isinstance(payload, dict):
            alerts.append(payload)
    return alerts


def _engine_distribution(alerts: list[dict[str, Any]]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for alert in alerts:
        engine = str(alert.get("engine") or "").strip().lower()
        if not engine:
            continue
        counts[engine] = counts.get(engine, 0) + 1
    return counts


def _base_runtime_yaml(config_path: Path) -> dict[str, Any]:
    payload = _read_yaml(config_path)
    return payload if isinstance(payload, dict) else {}


def _mode_specs(base_dir: Path) -> dict[str, dict[str, Any]]:
    disabled_model_path = str((base_dir / "missing-model.pkl").resolve())
    return {
        "signature_only": {
            "config_overrides": {
                "detection": {
                    "dos_packets_per_sec_threshold": 10**9,
                    "scan_ports_threshold": 10**9,
                    "http_login_threshold": 10**9,
                    "ssh_bruteforce_threshold": 10**9,
                    "rdp_bruteforce_threshold": 10**9,
                    "dns_unique_threshold": 10**9,
                    "zscore_enabled": False,
                },
                "ml": {
                    "model_path": disabled_model_path,
                    "unsupervised": False,
                },
                "fusion": {
                    "enabled": False,
                },
            },
            "use_empty_rules": False,
            "notes": "Signature rules remain active while anomaly, ML, and fusion paths are disabled or suppressed by configuration.",
        },
        "anomaly_only": {
            "config_overrides": {
                "ml": {
                    "model_path": disabled_model_path,
                    "unsupervised": False,
                },
                "fusion": {
                    "enabled": False,
                },
            },
            "use_empty_rules": True,
            "notes": "Signature matching is removed through an empty ruleset, while anomaly thresholds stay active and fusion is disabled.",
        },
        "ml_only": {
            "config_overrides": {
                "detection": {
                    "dos_packets_per_sec_threshold": 10**9,
                    "scan_ports_threshold": 10**9,
                    "http_login_threshold": 10**9,
                    "ssh_bruteforce_threshold": 10**9,
                    "rdp_bruteforce_threshold": 10**9,
                    "dns_unique_threshold": 10**9,
                    "zscore_enabled": False,
                },
                "ml": {
                    "unsupervised": True,
                },
                "fusion": {
                    "enabled": False,
                },
            },
            "use_empty_rules": True,
            "notes": "Signature rules are removed and anomaly thresholds are pushed beyond the replay range so ML paths operate alone; fusion stays disabled.",
        },
        "hybrid_tuned": {
            "config_overrides": {},
            "use_empty_rules": False,
            "notes": "The tuned offline replay profile is executed without detector suppression.",
        },
    }


def _build_runtime_namespace(
    *,
    pcap_path: Path,
    config_path: Path,
    rules_path: Path,
    output_dir: Path,
    model_path: Path | None,
) -> Namespace:
    return Namespace(
        config=str(config_path),
        enable_suricata=False,
        enable_zeek=False,
        interface=None,
        labels=None,
        maintenance_enabled=False,
        maintenance_include_artifacts=False,
        maintenance_interval_hours=None,
        maintenance_retention_days=None,
        maintenance_vacuum=False,
        metrics_interval=None,
        model=str(model_path) if model_path is not None else None,
        notify_backoff_sec=None,
        notify_dead_letter=None,
        notify_dead_letter_backup_count=None,
        notify_dead_letter_max_bytes=None,
        notify_max_backoff_sec=None,
        notify_max_retries=None,
        notify_min_interval_sec=None,
        notify_min_severity=None,
        notify_timeout_sec=None,
        notify_webhook=None,
        output_dir=str(output_dir),
        pcap_dir=str(pcap_path),
        replay_delay_ms=0,
        rules=str(rules_path),
        sensor_id="nids-comparison",
        suricata_log=None,
        unsupervised=False,
        unsupervised_threshold=None,
        zeek_log=None,
    )


def run_comparison_baseline(
    *,
    pcap_path: str | Path,
    base_config_path: str | Path,
    base_rules_path: str | Path,
    ground_truth_path: str | Path | None,
    output_root: str | Path,
    model_path: str | Path | None = None,
) -> dict[str, Any]:
    replay_path = Path(pcap_path).resolve()
    config_path = Path(base_config_path).resolve()
    rules_path = Path(base_rules_path).resolve()
    ground_truth = Path(ground_truth_path).resolve() if ground_truth_path is not None else None
    out_root = Path(output_root).resolve()
    out_root.mkdir(parents=True, exist_ok=True)
    base_yaml = _base_runtime_yaml(config_path)

    empty_rules_path = _write_text(out_root / "empty_rules.yml", "[]\n")
    specs = _mode_specs(out_root)
    modes: list[dict[str, Any]] = []

    for mode_name, spec in specs.items():
        mode_dir = out_root / mode_name
        mode_dir.mkdir(parents=True, exist_ok=True)
        merged_cfg = _deep_merge(base_yaml, dict(spec.get("config_overrides") or {}))
        runtime_config_path = _write_yaml(mode_dir / "runtime_config.yml", merged_cfg)
        runtime_rules_path = empty_rules_path if bool(spec.get("use_empty_rules")) else rules_path
        selected_model_path = Path(model_path).resolve() if model_path is not None and mode_name in {"ml_only", "hybrid_tuned"} else None
        run_dir = _reset_mode_run_dir(mode_dir / "run", root=out_root)
        args = _build_runtime_namespace(
            pcap_path=replay_path,
            config_path=runtime_config_path,
            rules_path=runtime_rules_path,
            output_dir=run_dir,
            model_path=selected_model_path,
        )
        cfg = build_runtime_config(args)
        started = time.perf_counter()
        result = run_local_pipeline(
            cfg=cfg,
            labels_path=None,
            sensor_id="nids-comparison",
            report_out=cfg.output_dir / "comparison_report.md",
            visual_out=cfg.output_dir / "comparison_graphs",
            ground_truth_path=ground_truth,
        )
        duration_sec = round(time.perf_counter() - started, 3)
        alerts = _load_alerts(result.alerts_jsonl_path)
        metrics = _read_json(result.output_dir / "metrics.json")
        totals = dict(metrics.get("totals") or {})
        metric_values = dict(metrics.get("metrics") or {})
        modes.append(
            {
                "mode": mode_name,
                "notes": str(spec.get("notes") or ""),
                "output_dir": str(result.output_dir),
                "runtime_sec": duration_sec,
                "flows": int(result.flow_count),
                "alerts": int(result.alert_count),
                "flows_per_sec": round(float(result.flow_count) / max(duration_sec, 0.001), 3),
                "engine_distribution": _engine_distribution(alerts),
                "tp": int(totals.get("tp", 0)),
                "fp": int(totals.get("fp", 0)),
                "fn": int(totals.get("fn", 0)),
                "precision": round(float(metric_values.get("precision", 0.0)), 4),
                "recall": round(float(metric_values.get("recall", 0.0)), 4),
                "f1": round(float(metric_values.get("f1", 0.0)), 4),
            }
        )

    payload = {
        "pcap_path": str(replay_path),
        "ground_truth_path": str(ground_truth) if ground_truth is not None else "",
        "assumptions": [
            "all four modes run against the same replay input and the same ground-truth file when provided",
            "signature-only uses the normal ruleset while anomaly, ML, and fusion are disabled or suppressed by config",
            "anomaly-only and ML-only use an empty ruleset so signature matching does not contribute",
            "ML-only suppresses anomaly thresholds and disables fusion so ML outputs are isolated for review",
            "these are replay-review comparisons, not event-aligned scientific benchmarks",
        ],
        "modes": modes,
    }
    return payload


def comparison_baseline_markdown(payload: dict[str, Any]) -> str:
    lines = [
        "# Comparative Baseline Study",
        "",
        f"- Replay input: `{payload.get('pcap_path', '')}`",
        f"- Ground truth: `{payload.get('ground_truth_path', '') or 'not provided'}`",
        "",
        "## Comparison Table",
        "",
        "| Mode | Flows | Alerts | TP | FP | FN | Precision | Recall | F1 | Runtime (s) | Flow/s |",
        "|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|",
    ]
    for row in list(payload.get("modes") or []):
        lines.append(
            f"| `{row.get('mode', '')}` | {int(row.get('flows', 0))} | {int(row.get('alerts', 0))} | "
            f"{int(row.get('tp', 0))} | {int(row.get('fp', 0))} | {int(row.get('fn', 0))} | "
            f"{float(row.get('precision', 0.0)):.4f} | {float(row.get('recall', 0.0)):.4f} | "
            f"{float(row.get('f1', 0.0)):.4f} | {float(row.get('runtime_sec', 0.0)):.3f} | {float(row.get('flows_per_sec', 0.0)):.3f} |"
        )
    lines.extend(["", "## Tradeoff Notes", ""])
    for row in list(payload.get("modes") or []):
        lines.append(f"- `{row.get('mode', '')}`: {row.get('notes', '')}")
    lines.extend(["", "## Matching Assumptions", ""])
    for item in list(payload.get("assumptions") or []):
        lines.append(f"- {item}")
    lines.append("")
    return "\n".join(lines)


def write_comparison_baseline(
    *,
    payload: dict[str, Any],
    out_json: str | Path,
    out_md: str | Path,
) -> tuple[Path, Path]:
    json_path = _write_json(Path(out_json), payload)
    md_path = _write_text(Path(out_md), comparison_baseline_markdown(payload))
    return json_path, md_path
