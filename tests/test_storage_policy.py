from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path

from src.NIDS.storage_policy import RetentionPolicy, execute_retention_plan, plan_retention


def _touch_bundle(path: Path, *, days_old: int) -> None:
    path.mkdir(parents=True, exist_ok=True)
    (path / "alerts.jsonl").write_text("{}\n", encoding="utf-8")
    stamp = (datetime.now(timezone.utc) - timedelta(days=days_old)).timestamp()
    for child in (path, path / "alerts.jsonl"):
        child.touch()
        Path(child).stat()
        import os

        os.utime(child, (stamp, stamp))


def test_retention_dry_run_is_non_destructive(tmp_path: Path) -> None:
    _touch_bundle(tmp_path / "output" / "old-run", days_old=40)
    policy = RetentionPolicy(compress_after_days=7, archive_after_days=30, max_active_runs=5)
    plan = plan_retention(tmp_path, policy)
    result = execute_retention_plan(plan, apply_changes=False)
    assert result["applied"] is False
    assert (tmp_path / "output" / "old-run").exists()


def test_named_baseline_is_preserved(tmp_path: Path) -> None:
    _touch_bundle(tmp_path / "output" / "validated-baseline-run", days_old=90)
    policy = RetentionPolicy(
        compress_after_days=7,
        archive_after_days=30,
        max_active_runs=1,
        preserve_named_baselines=("validated-baseline",),
    )
    plan = plan_retention(tmp_path, policy)
    assert plan["archive_actions"] == []


def test_compress_and_archive_candidates_are_selected(tmp_path: Path) -> None:
    _touch_bundle(tmp_path / "output" / "old-run", days_old=45)
    _touch_bundle(tmp_path / "output" / "stale-run", days_old=10)
    policy = RetentionPolicy(compress_after_days=7, archive_after_days=30, max_active_runs=10)
    plan = plan_retention(tmp_path, policy)
    archive_names = {Path(item["bundle_path"]).name for item in plan["archive_actions"]}
    compress_names = {Path(item["bundle_path"]).name for item in plan["compress_actions"]}
    assert "old-run" in archive_names
    assert "stale-run" in compress_names
