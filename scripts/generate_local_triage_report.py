from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from scripts.generate_local_triage import sanitize_name_part


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Generate a human-readable local NIDS triage report from triage JSON."
    )
    parser.add_argument(
        "triage_json",
        help="Path to a standardized triage JSON file.",
    )
    return parser.parse_args()


def load_triage(path: Path) -> dict[str, str]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    return {
        "alert_summary": str(payload.get("alert_summary") or "").strip(),
        "severity_assessment": str(payload.get("severity_assessment") or "").strip(),
        "likely_cause": str(payload.get("likely_cause") or "").strip(),
        "recommended_action": str(payload.get("recommended_action") or "").strip(),
    }


def render_report(payload: dict[str, str], run_name: str) -> str:
    return "\n".join(
        [
            f"# Local NIDS Triage Report: {run_name}",
            "",
            "## Alert Summary",
            payload["alert_summary"],
            "",
            "## Severity",
            payload["severity_assessment"],
            "",
            "## Cause",
            payload["likely_cause"],
            "",
            "## Recommended Action",
            payload["recommended_action"],
            "",
        ]
    )


def generate_report(triage_json_path: Path) -> Path:
    triage_json_path = triage_json_path.resolve()
    payload = load_triage(triage_json_path)
    run_name = sanitize_name_part(triage_json_path.parent.name)
    report_path = triage_json_path.parent / f"triage_{run_name}_report.md"
    report_path.write_text(render_report(payload, run_name), encoding="utf-8")
    return report_path


def main() -> int:
    args = parse_args()
    triage_json_path = Path(args.triage_json).resolve()
    if not triage_json_path.exists() or not triage_json_path.is_file():
        raise SystemExit(f"Triage JSON does not exist or is not a file: {triage_json_path}")

    report_path = generate_report(triage_json_path)
    print(report_path)
    return 0


if __name__ == "__main__":
    sys.exit(main())
