from __future__ import annotations

import json
import re
from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from ..pipeline.runtime import _count_rows
from ..privacy import PrivacyConfig, apply_privacy_to_alert, privacy_config_from_env


VALIDATED_BASELINE = {
    "flows": 509,
    "alerts": 10,
    "alert_ratio": 0.0196,
    "ml_unsupervised_confirmation_hits": 2,
    "fusion_min_agreement_count": 3,
}


@dataclass(frozen=True)
class RunInspectionService:
    repo_root: Path
    privacy: PrivacyConfig | None = None

    @property
    def output_root(self) -> Path:
        return (self.repo_root / "output").resolve()

    @property
    def privacy_config(self) -> PrivacyConfig:
        return self.privacy or privacy_config_from_env()

    def list_runs(self, *, limit: int = 20) -> list[dict[str, Any]]:
        root = self.output_root
        if not root.exists():
            return []
        entries: list[dict[str, Any]] = []
        for child in root.iterdir():
            if not child.is_dir():
                continue
            if not (child / "alerts.jsonl").exists() and not (child / "nids.db").exists():
                continue
            summary = self.read_summary(child.name)
            metrics = self.read_metrics(child.name)
            stat = child.stat()
            entries.append(
                {
                    "run_name": child.name,
                    "output_dir": str(child),
                    "status": summary["status"],
                    "flows": summary["flows"],
                    "alerts": summary["alerts"],
                    "modified_at": int(stat.st_mtime),
                    "engine_distribution": metrics["engine_distribution"],
                    "severity_distribution": metrics["severity_distribution"],
                }
            )
        entries.sort(key=lambda item: (-int(item["modified_at"]), str(item["run_name"])))
        return entries[: max(1, min(int(limit), 100))]

    def read_summary(self, run_name: str) -> dict[str, Any]:
        run_dir = self.resolve_run_dir(run_name)
        db_path = (run_dir / "nids.db").resolve()
        report_path = (run_dir / "summary.md").resolve()
        visuals_path = (run_dir / "graphs" / "index.html").resolve()
        counts = {"flows": 0, "alerts": 0, "metrics": 0}
        if db_path.exists():
            counts = _count_rows(db_path)
        elif (run_dir / "alerts.jsonl").exists():
            counts["alerts"] = self._count_jsonl(run_dir / "alerts.jsonl")
        status = "ready" if db_path.exists() and report_path.exists() else "partial"
        return {
            "run_name": run_name,
            "output_dir": str(run_dir),
            "flows": int(counts.get("flows", 0)),
            "alerts": int(counts.get("alerts", 0)),
            "report_path": str(report_path) if report_path.exists() else None,
            "visuals_path": str(visuals_path) if visuals_path.exists() else None,
            "status": status,
        }

    def read_alerts(self, run_name: str, *, limit: int = 10) -> dict[str, Any]:
        run_dir = self.resolve_run_dir(run_name)
        alerts_path = (run_dir / "alerts.jsonl").resolve()
        if not alerts_path.exists():
            raise FileNotFoundError(f"alerts.jsonl not found for run: {run_name}")
        bounded_limit = max(1, min(100, int(limit)))
        records: list[dict[str, Any]] = []
        with alerts_path.open("r", encoding="utf-8") as handle:
            for idx, line in enumerate(handle):
                if idx >= bounded_limit:
                    break
                token = line.strip()
                if not token:
                    continue
                payload = json.loads(token)
                records.append(self._trim_alert(payload))
        return {
            "run_name": run_name,
            "output_dir": str(run_dir),
            "limit": bounded_limit,
            "count": len(records),
            "alerts": records,
        }

    def read_metrics(self, run_name: str) -> dict[str, Any]:
        summary = self.read_summary(run_name)
        run_dir = Path(summary["output_dir"])
        alerts_path = (run_dir / "alerts.jsonl").resolve()
        severity_distribution: Counter[str] = Counter()
        engine_distribution: Counter[str] = Counter()
        sampled_alerts: list[dict[str, Any]] = []
        if alerts_path.exists():
            with alerts_path.open("r", encoding="utf-8") as handle:
                for line in handle:
                    token = line.strip()
                    if not token:
                        continue
                    payload = json.loads(token)
                    severity_distribution[str(payload.get("severity") or "unknown")] += 1
                    engine_distribution[str(payload.get("engine") or "unknown")] += 1
                    if len(sampled_alerts) < 25:
                        sampled_alerts.append(self._trim_alert(payload))
        flows = int(summary["flows"])
        alerts = int(summary["alerts"])
        current_ratio = round((alerts / flows), 4) if flows > 0 else 0.0
        baseline_comparison = {
            "validated_baseline": dict(VALIDATED_BASELINE),
            "current": {"flows": flows, "alerts": alerts, "alert_ratio": current_ratio},
            "delta": {
                "flows": flows - int(VALIDATED_BASELINE["flows"]),
                "alerts": alerts - int(VALIDATED_BASELINE["alerts"]),
                "alert_ratio": round(current_ratio - float(VALIDATED_BASELINE["alert_ratio"]), 4),
            },
            "matches_validated_result": flows == VALIDATED_BASELINE["flows"] and alerts == VALIDATED_BASELINE["alerts"],
        }
        return {
            **summary,
            "engine_distribution": dict(sorted(engine_distribution.items(), key=lambda item: (-item[1], item[0]))),
            "severity_distribution": dict(sorted(severity_distribution.items(), key=lambda item: (-item[1], item[0]))),
            "baseline_comparison": baseline_comparison,
            "sampled_alerts": sampled_alerts,
        }

    def resolve_run_dir(self, run_name: str) -> Path:
        token = str(run_name).strip()
        if not re.fullmatch(r"[A-Za-z0-9._-]+", token):
            raise ValueError("run_name contains invalid characters.")
        run_dir = (self.output_root / token).resolve()
        try:
            run_dir.relative_to(self.output_root)
        except ValueError as exc:
            raise ValueError("run_name must resolve under the repo output directory.") from exc
        if not run_dir.exists() or not run_dir.is_dir():
            raise FileNotFoundError(f"Run output directory not found: {token}")
        return run_dir

    def _count_jsonl(self, path: Path) -> int:
        count = 0
        with path.open("r", encoding="utf-8") as handle:
            for line in handle:
                if line.strip():
                    count += 1
        return count

    def _trim_alert(self, payload: dict[str, Any]) -> dict[str, Any]:
        alert = {
            "timestamp": payload.get("timestamp"),
            "severity": payload.get("severity"),
            "engine": payload.get("engine"),
            "rule_name": payload.get("rule_name"),
            "summary": payload.get("summary"),
            "src_ip": payload.get("src_ip"),
            "dst_ip": payload.get("dst_ip"),
            "proto": payload.get("proto"),
            "fusion_score": payload.get("fusion_score"),
            "fusion_label": payload.get("fusion_label"),
            "evidence_reference": self._extract_evidence_reference(payload),
        }
        return apply_privacy_to_alert(alert, self.privacy_config)

    def _extract_evidence_reference(self, payload: dict[str, Any]) -> str | None:
        direct = payload.get("evidence_reference") or payload.get("evidence_path")
        if isinstance(direct, str) and direct.strip():
            return Path(direct).name
        extra = payload.get("extra")
        if isinstance(extra, dict):
            candidate = extra.get("baseline_snapshot_path") or extra.get("report_path")
            if isinstance(candidate, str) and candidate.strip():
                return Path(candidate).name
        return None
