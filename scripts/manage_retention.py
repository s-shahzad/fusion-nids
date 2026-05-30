from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from src.NIDS.config import _read_yaml
from src.NIDS.storage_policy import ensure_storage_layout, execute_retention_plan, plan_retention, retention_policy_from_mapping, write_storage_profile


def main() -> int:
    parser = argparse.ArgumentParser(description="Manage runtime retention for Universal NIDS bundles.")
    parser.add_argument("--config", default=str(REPO_ROOT / "config" / "nids.yml"))
    parser.add_argument("--apply", action="store_true", help="Apply archive/compress actions. Default is dry-run.")
    parser.add_argument(
        "--reviewed-apply",
        action="store_true",
        help="Explicitly confirm reviewed apply mode for non-destructive archive/compress actions.",
    )
    parser.add_argument("--profile-only", action="store_true", help="Only generate storage profile artifacts.")
    args = parser.parse_args()

    config = _read_yaml(Path(args.config))
    policy = retention_policy_from_mapping(dict(config.get("storage") or {}))
    ensure_storage_layout(REPO_ROOT)

    docs_generated = REPO_ROOT / "docs" / "generated"
    storage_md = docs_generated / "storage_profile.md"
    storage_json = docs_generated / "storage_profile.json"
    write_storage_profile(REPO_ROOT, policy, storage_md, storage_json)

    if args.profile_only:
        print(json.dumps({"status": "ok", "profile_md": str(storage_md), "profile_json": str(storage_json)}, indent=2))
        return 0

    plan = plan_retention(REPO_ROOT, policy)
    recommendation_path = docs_generated / "retention_recommendation.md"
    recommendation_lines = [
        "# Retention Recommendation",
        "",
        f"- compress candidates: `{len(plan.get('compress_actions', []))}`",
        f"- archive candidates: `{len(plan.get('archive_actions', []))}`",
        f"- reviewed apply required: `{bool(args.reviewed_apply)}`",
        "",
        "## Notes",
        "",
        "- Dry-run is the default behavior.",
        "- Archive actions copy bundles into `runtime_data/archive/`.",
        "- Compression actions create `.gz` sidecars for JSON/JSONL/Markdown-like artifacts.",
        "- No destructive deletion is performed by this helper.",
    ]
    recommendation_path.write_text("\n".join(recommendation_lines) + "\n", encoding="utf-8")

    apply_changes = bool(args.apply or args.reviewed_apply)
    result = execute_retention_plan(plan, apply_changes=apply_changes)
    print(
        json.dumps(
            {
                "status": "ok",
                "applied": apply_changes,
                "profile_md": str(storage_md),
                "profile_json": str(storage_json),
                "retention_recommendation_md": str(recommendation_path),
                "plan_summary": {
                    "compress_actions": len(plan.get("compress_actions", [])),
                    "archive_actions": len(plan.get("archive_actions", [])),
                },
                "execution": result,
            },
            indent=2,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
