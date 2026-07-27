from __future__ import annotations

import json
import re
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from ..privacy import PrivacyConfig, apply_privacy_to_alert, apply_privacy_to_summary_text, privacy_config_from_env, write_encrypted_json
from .run_inspection_service import RunInspectionService


def _utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


@dataclass(frozen=True)
class ExportService:
    repo_root: Path
    run_service: RunInspectionService
    privacy: PrivacyConfig | None = None

    @property
    def exports_root(self) -> Path:
        return (self.repo_root / "artifacts" / "portfolio_bundles").resolve()

    @property
    def privacy_config(self) -> PrivacyConfig:
        return self.privacy or privacy_config_from_env()

    def export_portfolio_bundle(self, *, run_name: str, bundle_name: str | None = None) -> dict[str, Any]:
        summary = self.run_service.read_summary(run_name)
        metrics = self.run_service.read_metrics(run_name)
        alerts_payload = self.run_service.read_alerts(run_name, limit=10)

        safe_bundle = self._sanitize_bundle_name(bundle_name or run_name)
        output_dir = (self.exports_root / safe_bundle).resolve()
        output_dir.mkdir(parents=True, exist_ok=True)

        summary_payload = {
            "generated_at": _utc_now(),
            "run_name": summary["run_name"],
            "flows": summary["flows"],
            "alerts": summary["alerts"],
            "status": summary["status"],
            "report_available": bool(summary["report_path"]),
            "visuals_available": bool(summary["visuals_path"]),
            "validated_baseline": metrics["baseline_comparison"]["validated_baseline"],
            "baseline_comparison": metrics["baseline_comparison"],
        }
        metrics_payload = {
            "generated_at": _utc_now(),
            "run_name": run_name,
            "engine_distribution": metrics["engine_distribution"],
            "severity_distribution": metrics["severity_distribution"],
            "baseline_comparison": metrics["baseline_comparison"],
        }
        alerts_sample_payload = {
            "generated_at": _utc_now(),
            "run_name": run_name,
            "count": alerts_payload["count"],
            "alerts": [apply_privacy_to_alert(alert, self.privacy_config) for alert in alerts_payload["alerts"]],
            "privacy_metadata": {"privacy_mode": self.privacy_config.mode},
        }
        architecture_payload = {
            "generated_at": _utc_now(),
            "control_layer": "FastAPI wrapper around validated local replay outputs",
            "detection_engine": "Signature + Anomaly + ML + Fusion",
            "baseline_controls": metrics["baseline_comparison"]["validated_baseline"],
            "security_boundaries": [
                "repo-local artifact access only",
                "no live capture through the control layer",
                "no arbitrary command execution",
                "Ollama optional and explanation-only",
            ],
        }

        (output_dir / "nids-summary.json").write_text(json.dumps(summary_payload, indent=2), encoding="utf-8")
        (output_dir / "nids-metrics.json").write_text(json.dumps(metrics_payload, indent=2), encoding="utf-8")
        alerts_sample_path = output_dir / "nids-alerts-sample.json"
        alerts_sample_path.write_text(json.dumps(alerts_sample_payload, indent=2), encoding="utf-8")
        (output_dir / "architecture-metadata.json").write_text(
            json.dumps(architecture_payload, indent=2), encoding="utf-8"
        )
        case_study_path = output_dir / "nids-case-study-summary.md"
        case_study_path.write_text(
            apply_privacy_to_summary_text(
                self._render_case_study(summary_payload, metrics_payload, alerts_sample_payload),
                self.privacy_config,
            ),
            encoding="utf-8",
        )
        write_encrypted_json(alerts_sample_path, alerts_sample_payload, self.privacy_config)

        return {
            "status": "ok",
            "run_name": run_name,
            "bundle_name": safe_bundle,
            "output_dir": str(output_dir),
            "files": [
                "nids-summary.json",
                "nids-metrics.json",
                "nids-alerts-sample.json",
                "nids-case-study-summary.md",
                "architecture-metadata.json",
            ],
        }

    def _sanitize_bundle_name(self, value: str) -> str:
        token = re.sub(r"[^A-Za-z0-9._-]+", "-", str(value).strip()).strip(".-")
        return token or "portfolio-bundle"

    def _render_case_study(
        self,
        summary_payload: dict[str, Any],
        metrics_payload: dict[str, Any],
        alerts_sample_payload: dict[str, Any],
    ) -> str:
        lines = [
            "# Universal NIDS Case Study Summary",
            "",
            f"Generated: {summary_payload['generated_at']}",
            "",
            "## Run Snapshot",
            "",
            f"- Run name: `{summary_payload['run_name']}`",
            f"- Flows: `{summary_payload['flows']}`",
            f"- Alerts: `{summary_payload['alerts']}`",
            f"- Status: `{summary_payload['status']}`",
            "",
            "## Detection Baseline",
            "",
            f"- Validated flows: `{summary_payload['validated_baseline']['flows']}`",
            f"- Validated alerts: `{summary_payload['validated_baseline']['alerts']}`",
            f"- Alert ratio: `{summary_payload['validated_baseline']['alert_ratio']}`",
            f"- ML confirmation hits: `{summary_payload['validated_baseline']['ml_unsupervised_confirmation_hits']}`",
            f"- Fusion agreement count: `{summary_payload['validated_baseline']['fusion_min_agreement_count']}`",
            "",
            "## Engine Distribution",
            "",
        ]
        for engine, count in metrics_payload["engine_distribution"].items():
            lines.append(f"- {engine}: {count}")
        lines.extend(["", "## Severity Distribution", ""])
        for severity, count in metrics_payload["severity_distribution"].items():
            lines.append(f"- {severity}: {count}")
        lines.extend(["", "## Sample Alerts", ""])
        for alert in alerts_sample_payload["alerts"][:5]:
            lines.append(
                f"- [{alert.get('timestamp')}] [{alert.get('severity')}] [{alert.get('engine')}] "
                f"{alert.get('rule_name')}: {alert.get('summary')}"
            )
        lines.extend(
            [
                "",
                "## Public Safety Notes",
                "",
                "- This bundle omits localhost URLs, raw PCAPs, and personal filesystem paths.",
                "- Alerts are trimmed to presentation-safe records with optional evidence filenames only.",
                "- The control layer explains stored results without altering detection logic or thresholds.",
                "",
            ]
        )
        return "\n".join(lines)
