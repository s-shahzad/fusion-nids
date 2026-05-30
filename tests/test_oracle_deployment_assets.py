from __future__ import annotations

from pathlib import Path

from src.NIDS.cloud import build_cloud_storage_layout


REPO_ROOT = Path(__file__).resolve().parents[1]
ORACLE_DOCS = [
    "docs/oracle_vm_cleanup_runbook.md",
    "docs/oracle_vm_deployment_steps.md",
    "docs/oracle_vm_first_boot.md",
    "docs/oracle_vm_nids_runbook.md",
]
ORACLE_CONFIG_FILES = [
    "deployment/oracle_vm.env.example",
]
ORACLE_SCRIPTS = [
    "scripts/oracle_common.sh",
    "scripts/oracle_prepare_bundle.sh",
    "scripts/oracle_copy_bundle.sh",
    "scripts/oracle_remote_bootstrap.sh",
    "scripts/oracle_remote_run.sh",
    "scripts/oracle_remote_status.sh",
    "scripts/oracle_remote_collect.sh",
    "scripts/oracle_remote_cleanup.sh",
    "scripts/oracle_common.ps1",
    "scripts/oracle_prepare_bundle.ps1",
    "scripts/oracle_copy_bundle.ps1",
    "scripts/oracle_remote_bootstrap.ps1",
    "scripts/oracle_remote_run.ps1",
    "scripts/oracle_remote_status.ps1",
    "scripts/oracle_remote_collect.ps1",
    "scripts/oracle_remote_cleanup.ps1",
]


def _norm(path: Path | str) -> str:
    return str(path).replace("\\", "/")


def test_oracle_remote_layout_matches_phase14b_boundary() -> None:
    layout = build_cloud_storage_layout("/opt/universal-nids/cloud_data")

    assert _norm(layout.runtime_output_dir).endswith("/opt/universal-nids/cloud_data/runtime/output")
    assert _norm(layout.runtime_logs_dir).endswith("/opt/universal-nids/cloud_data/runtime/logs")
    assert _norm(layout.runtime_reports_dir).endswith("/opt/universal-nids/cloud_data/runtime/reports")
    assert _norm(layout.runtime_artifacts_incoming_dir).endswith("/opt/universal-nids/cloud_data/runtime/artifacts/incoming")
    assert _norm(layout.runtime_artifacts_processed_dir).endswith("/opt/universal-nids/cloud_data/runtime/artifacts/processed")
    assert _norm(layout.runtime_artifacts_quarantine_dir).endswith("/opt/universal-nids/cloud_data/runtime/artifacts/quarantine")
    assert _norm(layout.lab_generated_bundles_dir).endswith("/opt/universal-nids/cloud_data/lab_generated/bundles")
    assert _norm(layout.lab_generated_archive_dir).endswith("/opt/universal-nids/cloud_data/lab_generated/archive")
    assert _norm(layout.replay_staging_dir).endswith("/opt/universal-nids/cloud_data/replay/staging")
    assert _norm(layout.archived_outputs_dir).endswith("/opt/universal-nids/cloud_data/archive/output_bundles")
    assert _norm(layout.manifests_dir).endswith("/opt/universal-nids/cloud_data/manifests")


def test_oracle_docs_and_scripts_exist() -> None:
    for relative_path in ORACLE_DOCS + ORACLE_CONFIG_FILES + ORACLE_SCRIPTS:
        assert (REPO_ROOT / relative_path).exists(), relative_path


def test_oracle_common_script_enforces_key_auth_and_bounded_defaults() -> None:
    bash_content = (REPO_ROOT / "scripts" / "oracle_common.sh").read_text(encoding="utf-8")
    ps_content = (REPO_ROOT / "scripts" / "oracle_common.ps1").read_text(encoding="utf-8")

    assert 'ORACLE_DEFAULT_REMOTE_PROJECT_DIR="/opt/universal-nids"' in bash_content
    assert 'ORACLE_DEFAULT_REMOTE_UPLOAD_DIR="/tmp/universal-nids-upload"' in bash_content
    assert "oracle_default_project_env_file" in bash_content
    assert "oracle_load_project_env" in bash_content
    assert "IdentitiesOnly=yes" in bash_content
    assert "StrictHostKeyChecking=accept-new" in bash_content
    assert "StrictHostKeyChecking=no" not in bash_content

    assert '$script:OracleDefaultRemoteProjectDir = "/opt/universal-nids"' in ps_content
    assert '$script:OracleDefaultRemoteUploadDir = "/tmp/universal-nids-upload"' in ps_content
    assert "Get-OracleDefaultEnvFile" in ps_content
    assert "Import-OracleProjectEnv" in ps_content
    assert "IdentitiesOnly=yes" in ps_content
    assert "StrictHostKeyChecking=accept-new" in ps_content
    assert "StrictHostKeyChecking=no" not in ps_content


def test_oracle_run_script_supports_bounded_replay_and_live_modes() -> None:
    bash_content = (REPO_ROOT / "scripts" / "oracle_remote_run.sh").read_text(encoding="utf-8")
    ps_content = (REPO_ROOT / "scripts" / "oracle_remote_run.ps1").read_text(encoding="utf-8")

    assert "--env-file <path>" in bash_content
    assert "--sync-method <rsync|bundle|git|none>" in bash_content
    assert "--run-mode <replay|live>" in bash_content
    assert "python3 scripts/cloud_validation_workflow.py stage-bundle" in bash_content
    assert 'upsert_env "NIDS_CLOUD_RUNTIME_OUTPUT_DIR"' in bash_content
    assert 'nids-runtime 2>&1 | tee "$combined_log_path"' in bash_content
    assert "--enable-dashboard" in bash_content

    assert "[-EnvFile <path>]" in ps_content
    assert 'ValidateSet("rsync", "bundle", "git", "none")' in ps_content
    assert 'ValidateSet("replay", "live")' in ps_content
    assert "cloud_validation_workflow.py stage-bundle" in ps_content
    assert '"NIDS_CLOUD_RUNTIME_OUTPUT_DIR"' in ps_content
    assert 'nids-runtime 2>&1 | tee "$combined_log_path"' in ps_content
    assert "-EnableDashboard" in ps_content


def test_oracle_collect_and_cleanup_stay_within_project_boundary() -> None:
    collect = (REPO_ROOT / "scripts" / "oracle_remote_collect.sh").read_text(encoding="utf-8")
    collect_ps = (REPO_ROOT / "scripts" / "oracle_remote_collect.ps1").read_text(encoding="utf-8")
    cleanup = (REPO_ROOT / "scripts" / "oracle_remote_cleanup.sh").read_text(encoding="utf-8")
    cleanup_ps = (REPO_ROOT / "scripts" / "oracle_remote_cleanup.ps1").read_text(encoding="utf-8")
    gitignore = (REPO_ROOT / ".gitignore").read_text(encoding="utf-8")
    env_example = (REPO_ROOT / "deployment" / "oracle_vm.env.example").read_text(encoding="utf-8")

    assert "--env-file <path>" in collect
    assert "cloud_data/runtime/logs/" in collect
    assert "cloud_data/runtime/reports/" in collect
    assert "cloud_data/manifests/" in collect
    assert "archives/oracle_vm_collections" in collect

    assert "[-EnvFile <path>]" in collect_ps
    assert 'RemoteCloudDataDir)/runtime/logs' in collect_ps
    assert 'RemoteCloudDataDir)/runtime/reports' in collect_ps
    assert 'RemoteCloudDataDir)/manifests' in collect_ps
    assert "oracle_vm_collections" in collect_ps

    assert "--env-file <path>" in cleanup
    assert "scripts/cloud_validation_workflow.py cleanup-temp" in cleanup
    assert "runtime/artifacts/incoming" in cleanup
    assert "tmp/oracle-uploaded-bundles" in cleanup
    assert "cloud_data/archive/output_bundles" not in cleanup

    assert "[-EnvFile <path>]" in cleanup_ps
    assert "cloud_validation_workflow.py cleanup-temp" in cleanup_ps
    assert "runtime/artifacts/incoming" in cleanup_ps
    assert "tmp/oracle-uploaded-bundles" in cleanup_ps
    assert "cloud_data/archive/output_bundles" not in cleanup_ps

    assert "ORACLE_VM_HOST=" in env_example
    assert "ORACLE_VM_SSH_KEY_PATH=" in env_example
    assert "cloud_data/" in gitignore
    assert "release/deployment-bundles/" in gitignore
    assert "archives/oracle_vm_collections/" in gitignore
    assert "deployment/oracle_vm.env" in gitignore
