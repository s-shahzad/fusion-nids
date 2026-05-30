from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from src.NIDS.adversary_lab import (  # noqa: E402
    explicit_lab_cidrs_profile,
    generate_bundle,
    list_scenarios,
    localhost_only_profile,
    offline_replay_profile,
)

DEFAULT_OUTPUT_ROOT = REPO_ROOT / "NIDS_TestLab" / "results" / "adversary_lab"


def _build_policy(args: argparse.Namespace):
    if args.profile == "localhost-only":
        return localhost_only_profile()
    if args.profile == "explicit-lab-cidrs":
        return explicit_lab_cidrs_profile(*(args.lab_cidr or []))
    return offline_replay_profile(allowed_cidrs=tuple(args.lab_cidr or []))


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Generate safe, lab-generated adversary-emulation bundles for isolated Universal NIDS validation. "
            "This tool only writes offline replay artifacts and labeled adapter logs."
        )
    )
    parser.add_argument("--scenario", action="append", default=[], help="Scenario key to generate. Repeat for multiple scenarios.")
    parser.add_argument("--out-root", default=str(DEFAULT_OUTPUT_ROOT), help="Output root directory for generated bundles.")
    parser.add_argument(
        "--profile",
        choices=["offline-replay", "localhost-only", "explicit-lab-cidrs"],
        default="offline-replay",
        help="Safety profile controlling the permitted target boundary.",
    )
    parser.add_argument("--lab-cidr", action="append", default=[], help="Explicit isolated lab CIDR allowed by the safety policy.")
    parser.add_argument("--run-stamp", help="Optional fixed run stamp for deterministic bundle naming.")
    parser.add_argument("--list", action="store_true", help="List supported scenario keys and exit.")
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.list:
        for scenario_name in list_scenarios():
            print(scenario_name)
        return 0

    scenario_names = args.scenario or list_scenarios()
    policy = _build_policy(args)
    print("warning: lab-generated adversary emulation only; do not use outside isolated validation environments.")
    for scenario_name in scenario_names:
        manifest = generate_bundle(
            scenario_name=scenario_name,
            output_root=args.out_root,
            policy=policy,
            run_stamp=args.run_stamp,
        )
        print(f"scenario={scenario_name} bundle={manifest['bundle_dir']}")
        print(json.dumps({"pcap": manifest["pcap_path"], "labels": manifest["labels_path"]}, ensure_ascii=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
