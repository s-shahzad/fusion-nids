from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from src.NIDS.cloud import (  # noqa: E402
    build_cloud_storage_layout,
    cleanup_staged_replay,
    ensure_cloud_storage_layout,
    stage_validation_bundle,
)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Prepare a single-node cloud validation layout for Universal NIDS. "
            "This helper only stages lab-generated replay bundles, emits run plans, "
            "and performs bounded cleanup of temporary replay staging."
        )
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    layout_cmd = subparsers.add_parser("layout", help="Create or print the cloud storage layout.")
    layout_cmd.add_argument("--root", required=True, help="Cloud data root directory.")
    layout_cmd.add_argument("--create", action="store_true", help="Create the directories on disk.")
    layout_cmd.add_argument("--json", action="store_true", help="Print JSON instead of line-oriented output.")

    stage_cmd = subparsers.add_parser("stage-bundle", help="Stage one lab-generated bundle for cloud replay.")
    stage_cmd.add_argument("--root", required=True, help="Cloud data root directory.")
    stage_cmd.add_argument("--bundle-dir", required=True, help="Source adversary-lab bundle directory.")
    stage_cmd.add_argument("--config", default="config/nids_cloud_single_node.yml", help="Runtime config path to reference in the plan.")
    stage_cmd.add_argument("--rules", default="rules/rules.yml", help="Rules file path to reference in the plan.")
    stage_cmd.add_argument("--sensor-id", default="cloud-validation", help="Sensor identifier prefix for the plan.")
    stage_cmd.add_argument("--run-stamp", help="Optional deterministic run stamp.")

    cleanup_cmd = subparsers.add_parser("cleanup-temp", help="Remove old replay staging artifacts.")
    cleanup_cmd.add_argument("--root", required=True, help="Cloud data root directory.")
    cleanup_cmd.add_argument("--older-than-hours", type=int, default=24, help="Only consider items older than this many hours.")
    cleanup_cmd.add_argument("--apply", action="store_true", help="Actually remove candidates. Default is dry-run.")
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    layout = build_cloud_storage_layout(args.root)

    if args.command == "layout":
        if args.create:
            ensure_cloud_storage_layout(layout)
        payload = layout.as_dict()
        if args.json:
            print(json.dumps(payload, indent=2, ensure_ascii=True))
        else:
            for key, value in payload.items():
                print(f"{key}={value}")
        return 0

    ensure_cloud_storage_layout(layout)

    if args.command == "stage-bundle":
        plan = stage_validation_bundle(
            bundle_dir=args.bundle_dir,
            layout=layout,
            config_path=str(args.config),
            rules_path=str(args.rules),
            sensor_id=str(args.sensor_id),
            run_stamp=args.run_stamp,
        )
        print(json.dumps(plan, indent=2, ensure_ascii=True))
        return 0

    if args.command == "cleanup-temp":
        summary = cleanup_staged_replay(
            layout=layout,
            older_than_hours=int(args.older_than_hours),
            apply=bool(args.apply),
        )
        print(json.dumps(summary, indent=2, ensure_ascii=True))
        return 0

    parser.print_help()
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
