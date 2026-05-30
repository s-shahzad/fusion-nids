from __future__ import annotations

import argparse
import sys
from pathlib import Path

from scripts import generate_local_triage
from scripts import generate_local_triage_report


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Run repeatable local NIDS triage for an existing output folder."
    )
    parser.add_argument(
        "run_path",
        help="Path to an existing NIDS run/output directory.",
    )
    return parser.parse_args()


def main() -> int:
    try:
        args = parse_args()
        run_dir = Path(args.run_path).resolve()
        if not run_dir.exists() or not run_dir.is_dir():
            raise SystemExit(f"Run path does not exist or is not a directory: {run_dir}")

        created = generate_local_triage.generate_outputs(run_dir=run_dir, out_dir=run_dir)
        triage_path = created[0]
        report_path = generate_local_triage_report.generate_report(triage_path)
        print(f"Triage generated: {triage_path}")
        print(f"Report generated: {report_path}")
        print(f"Delivery complete: {run_dir}")
        return 0
    except SystemExit:
        raise
    except Exception as exc:
        print(f"Triage failed: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
