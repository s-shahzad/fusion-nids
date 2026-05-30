from __future__ import annotations

from pathlib import Path

import yaml


REPO_ROOT = Path(__file__).resolve().parents[1]


def test_dockerfile_copies_runtime_container_scripts() -> None:
    dockerfile = (REPO_ROOT / "Dockerfile").read_text(encoding="utf-8")
    assert "COPY scripts/run_runtime_container.sh /app/scripts/run_runtime_container.sh" in dockerfile
    assert "COPY scripts/run_dashboard_container.sh /app/scripts/run_dashboard_container.sh" in dockerfile
    assert "chmod +x /app/scripts/run_runtime_container.sh /app/scripts/run_dashboard_container.sh" in dockerfile


def test_cloud_compose_profile_keeps_dashboard_loopback_only() -> None:
    compose = yaml.safe_load((REPO_ROOT / "docker-compose.cloud-single-node.yml").read_text(encoding="utf-8"))
    runtime = compose["services"]["nids-runtime"]
    dashboard = compose["services"]["nids-dashboard"]

    assert runtime["environment"]["NIDS_CONFIG_PATH"] == "${NIDS_CONFIG_PATH:-config/nids_cloud_single_node.yml}"
    assert dashboard["ports"] == ["127.0.0.1:${DASHBOARD_PORT:-8000}:8000"]
    assert dashboard["profiles"] == ["dashboard"]


def test_dockerignore_excludes_cloud_data_and_archive_boundary() -> None:
    dockerignore = (REPO_ROOT / ".dockerignore").read_text(encoding="utf-8")
    assert "_archive/" in dockerignore
    assert "cloud_data/" in dockerignore
    assert "NIDS_TestLab/results/" in dockerignore
