from __future__ import annotations

import argparse
from pathlib import Path

from run_lab_scenario import REPORTS_ROOT, RESULTS_ROOT, _write_json, _write_text, build_execution_index, execution_index_markdown


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Summarize manifest-backed NIDS_TestLab runs.")
    parser.add_argument("--results-root", default=str(RESULTS_ROOT), help="Root directory containing result manifests.")
    parser.add_argument("--out-json", default=str(REPORTS_ROOT / "lab_execution_index.json"), help="Output JSON path.")
    parser.add_argument("--out-md", default=str(REPORTS_ROOT / "lab_execution_index.md"), help="Output markdown path.")
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    results_root = Path(args.results_root).resolve()
    out_json = Path(args.out_json).resolve()
    out_md = Path(args.out_md).resolve()

    index = build_execution_index(results_root)
    _write_json(out_json, index)
    _write_text(out_md, execution_index_markdown(index))

    print(f"lab_execution_index_json={out_json}")
    print(f"lab_execution_index_md={out_md}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
