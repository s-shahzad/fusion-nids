from __future__ import annotations

import os
import time
from pathlib import Path

from src.NIDS.adversary_lab import generate_bundle, offline_replay_profile
from src.NIDS.cloud import build_cloud_storage_layout, cleanup_staged_replay, ensure_cloud_storage_layout, stage_validation_bundle


def test_cloud_storage_layout_creates_expected_directories(tmp_path: Path) -> None:
    layout = build_cloud_storage_layout(tmp_path / "cloud_data")
    ensure_cloud_storage_layout(layout)

    assert layout.runtime_output_dir.exists()
    assert layout.runtime_logs_dir.exists()
    assert layout.runtime_reports_dir.exists()
    assert layout.lab_generated_bundles_dir.exists()
    assert layout.replay_staging_dir.exists()
    assert layout.archived_outputs_dir.exists()


def test_cloud_stage_validation_bundle_writes_plan_and_stage_copy(tmp_path: Path) -> None:
    bundle_manifest = generate_bundle(
        scenario_name="port_scan_pattern",
        output_root=tmp_path / "bundles",
        policy=offline_replay_profile(),
        run_stamp="pytest",
    )
    layout = ensure_cloud_storage_layout(build_cloud_storage_layout(tmp_path / "cloud_data"))

    plan = stage_validation_bundle(
        bundle_dir=bundle_manifest["bundle_dir"],
        layout=layout,
        run_stamp="fixed",
    )

    assert Path(plan["canonical_bundle_dir"]).exists()
    assert Path(plan["staged_bundle_dir"]).exists()
    assert Path(plan["plan_path"]).exists()
    assert "docker compose -f docker-compose.cloud-single-node.yml run --rm" in plan["commands"]["docker_compose_runtime"]
    assert "/data/runtime/output/" in plan["commands"]["docker_compose_runtime"]


def test_cloud_cleanup_staged_replay_removes_old_items_only_when_applied(tmp_path: Path) -> None:
    layout = ensure_cloud_storage_layout(build_cloud_storage_layout(tmp_path / "cloud_data"))
    stale_dir = layout.replay_staging_dir / "old-stage"
    stale_dir.mkdir(parents=True)
    labels_path = stale_dir / "labels.csv"
    labels_path.write_text("label\nlab_generated\n", encoding="utf-8")
    old_epoch = time.time() - 7200
    os.utime(labels_path, (old_epoch, old_epoch))
    os.utime(stale_dir, (old_epoch, old_epoch))

    summary_dry = cleanup_staged_replay(layout=layout, older_than_hours=1, apply=False)
    assert stale_dir.exists()
    assert summary_dry["candidates"]
    assert summary_dry["removed"] == []

    summary_apply = cleanup_staged_replay(layout=layout, older_than_hours=1, apply=True)
    assert summary_apply["removed"] == [str(stale_dir)]
    assert not stale_dir.exists()
