from __future__ import annotations

import json
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def _normalize_token(value: Any) -> str:
    token = re.sub(r"[^a-z0-9]+", " ", str(value or "").strip().lower())
    return " ".join(token.split())


def _safe_int(value: Any, default: int = 0) -> int:
    try:
        return int(value)
    except Exception:
        return int(default)


def _safe_ratio(numerator: int, denominator: int) -> float:
    if int(denominator) <= 0:
        return 0.0
    return float(numerator) / float(denominator)


def load_ground_truth(path: str | Path) -> dict[str, Any]:
    gt_path = Path(path)
    payload = json.loads(gt_path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise ValueError("ground truth JSON must be an object")
    items = payload.get("expected_detections")
    if not isinstance(items, list):
        raise ValueError("ground truth JSON must include expected_detections as a list")
    normalized_items: list[dict[str, Any]] = []
    for item in items:
        if not isinstance(item, dict):
            raise ValueError("each expected detection must be an object")
        label = str(item.get("label") or "").strip()
        if not label:
            raise ValueError("each expected detection requires a non-empty label")
        count = max(0, _safe_int(item.get("count"), 1))
        match_any = item.get("match_any")
        patterns = [label]
        if isinstance(match_any, list):
            cleaned = [str(entry).strip() for entry in match_any if str(entry).strip()]
            if cleaned:
                patterns = cleaned
        normalized_items.append(
            {
                "label": label,
                "count": count,
                "match_any": patterns,
            }
        )
    return {
        "schema_version": int(payload.get("schema_version", 1) or 1),
        "expected_detections": normalized_items,
    }


def load_observed_alerts(path: str | Path) -> list[dict[str, Any]]:
    alerts_path = Path(path)
    if not alerts_path.exists():
        return []
    payloads: list[dict[str, Any]] = []
    for raw_line in alerts_path.read_text(encoding="utf-8").splitlines():
        token = raw_line.strip()
        if not token:
            continue
        item = json.loads(token)
        if isinstance(item, dict):
            payloads.append(item)
    return payloads


def compute_replay_metrics(
    expected_detections: list[dict[str, Any]],
    observed_alerts: list[dict[str, Any]],
) -> dict[str, Any]:
    observed_texts = [
        _normalize_token(
            " ".join(
                [
                    str(alert.get("rule_name") or ""),
                    str(alert.get("summary") or ""),
                    str(alert.get("engine") or ""),
                ]
            )
        )
        for alert in observed_alerts
    ]
    unmatched_indexes = set(range(len(observed_texts)))
    per_label: list[dict[str, Any]] = []
    total_expected = 0
    tp = 0

    for item in expected_detections:
        label = str(item["label"])
        expected_count = max(0, _safe_int(item.get("count"), 1))
        total_expected += expected_count
        patterns = [_normalize_token(entry) for entry in list(item.get("match_any") or [label]) if _normalize_token(entry)]
        candidate_indexes = [
            idx
            for idx, observed_text in enumerate(observed_texts)
            if idx in unmatched_indexes and any(pattern in observed_text for pattern in patterns)
        ]
        matched_indexes = candidate_indexes[:expected_count]
        for idx in matched_indexes:
            unmatched_indexes.discard(idx)
        matched_count = len(matched_indexes)
        tp += matched_count
        per_label.append(
            {
                "label": label,
                "expected_count": expected_count,
                "matched_count": matched_count,
                "candidate_matches": len(candidate_indexes),
                "match_any": list(item.get("match_any") or [label]),
            }
        )

    fp = len(observed_alerts) - tp
    fn = total_expected - tp
    precision = _safe_ratio(tp, tp + fp)
    recall = _safe_ratio(tp, tp + fn)
    f1 = _safe_ratio(2 * tp, (2 * tp) + fp + fn)

    return {
        "generated_at": _utc_now_iso(),
        "matching_method": "category_or_label_substring_first_match",
        "assumptions": [
            "matching is case-insensitive and based on substring checks against rule_name, summary, and engine",
            "each observed alert can satisfy at most one expected detection entry in file order",
            "unmatched observed alerts are counted as false positives",
            "unmatched expected detections are counted as false negatives",
        ],
        "totals": {
            "expected": total_expected,
            "observed": len(observed_alerts),
            "tp": tp,
            "fp": fp,
            "fn": fn,
        },
        "metrics": {
            "precision": round(precision, 4),
            "recall": round(recall, 4),
            "f1": round(f1, 4),
        },
        "per_label": per_label,
    }


def write_replay_metrics(
    *,
    ground_truth_path: str | Path,
    alerts_jsonl_path: str | Path,
    out_json: str | Path,
    out_md: str | Path,
) -> tuple[Path, Path]:
    ground_truth = load_ground_truth(ground_truth_path)
    observed_alerts = load_observed_alerts(alerts_jsonl_path)
    metrics = compute_replay_metrics(
        expected_detections=list(ground_truth["expected_detections"]),
        observed_alerts=observed_alerts,
    )
    metrics["ground_truth_path"] = str(Path(ground_truth_path).resolve())
    metrics["alerts_jsonl_path"] = str(Path(alerts_jsonl_path).resolve())

    json_path = Path(out_json)
    md_path = Path(out_md)
    json_path.parent.mkdir(parents=True, exist_ok=True)
    md_path.parent.mkdir(parents=True, exist_ok=True)
    json_path.write_text(json.dumps(metrics, indent=2, ensure_ascii=True), encoding="utf-8")

    lines = [
        "# Replay Evaluation Metrics",
        "",
        f"Generated: {metrics['generated_at']}",
        f"Ground truth: `{metrics['ground_truth_path']}`",
        f"Observed alerts: `{metrics['alerts_jsonl_path']}`",
        "",
        "## Totals",
        "",
        f"- Expected detections: {metrics['totals']['expected']}",
        f"- Observed alerts: {metrics['totals']['observed']}",
        f"- TP: {metrics['totals']['tp']}",
        f"- FP: {metrics['totals']['fp']}",
        f"- FN: {metrics['totals']['fn']}",
        "",
        "## Metrics",
        "",
        f"- Precision: {metrics['metrics']['precision']:.4f}",
        f"- Recall: {metrics['metrics']['recall']:.4f}",
        f"- F1-score: {metrics['metrics']['f1']:.4f}",
        "",
        "## Matching Assumptions",
        "",
    ]
    for assumption in metrics["assumptions"]:
        lines.append(f"- {assumption}")
    lines.extend(["", "## Per Label", ""])
    if metrics["per_label"]:
        for row in metrics["per_label"]:
            lines.append(
                f"- {row['label']}: expected={row['expected_count']} matched={row['matched_count']} "
                f"candidate_matches={row['candidate_matches']}"
            )
    else:
        lines.append("- none")
    lines.append("")
    md_path.write_text("\n".join(lines), encoding="utf-8")
    return json_path, md_path
