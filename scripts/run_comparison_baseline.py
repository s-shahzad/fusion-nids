from __future__ import annotations

import argparse
import sys
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from src.NIDS.adversary import run_comparison_baseline, write_comparison_baseline


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Run deterministic offline comparative baseline study.")
    parser.add_argument("--pcap", required=True, help="Replay PCAP path.")
    parser.add_argument("--config", default=str(REPO_ROOT / "NIDS_TestLab" / "config" / "offline_replay_profile.yml"))
    parser.add_argument("--rules", default=str(REPO_ROOT / "rules" / "rules.yml"))
    parser.add_argument("--model", default=str(REPO_ROOT / "models" / "model.pkl"))
    parser.add_argument("--ground-truth", help="Optional replay-review ground truth JSON path.")
    parser.add_argument(
        "--output-root",
        default=str(REPO_ROOT / "output" / "comparison_baseline"),
        help="Directory used for per-mode run outputs.",
    )
    parser.add_argument(
        "--out-json",
        default=str(REPO_ROOT / "docs" / "generated" / "comparison_baseline.json"),
        help="Output JSON summary path.",
    )
    parser.add_argument(
        "--out-md",
        default=str(REPO_ROOT / "docs" / "generated" / "comparison_baseline.md"),
        help="Output markdown summary path.",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    payload = run_comparison_baseline(
        pcap_path=args.pcap,
        base_config_path=args.config,
        base_rules_path=args.rules,
        ground_truth_path=args.ground_truth,
        output_root=args.output_root,
        model_path=args.model,
    )
    json_path, md_path = write_comparison_baseline(payload=payload, out_json=args.out_json, out_md=args.out_md)
    print(f"comparison_baseline_json={json_path}")
    print(f"comparison_baseline_md={md_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
