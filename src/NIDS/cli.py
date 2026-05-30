from __future__ import annotations

import argparse
from pathlib import Path

from .artifacts.intake import run_artifact_scan, run_artifact_watch
from .artifacts.report import generate_artifact_report
from .config import build_runtime_config
from .ml.evaluate import evaluate_model
from .ml.train import train_from_db
from .pipeline.runtime import run_local_pipeline
from .reporting import generate_incident_report, generate_sla_weekly_summary, generate_threshold_tuning_report
from .runtime import run_runtime
from .thesis import generate_thesis_documents
from .storage import SQLiteStore
from .visuals.dashboard import run_dashboard
from .visuals.export import run_visual_export


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="nids",
        description="Universal NIDS command line interface.",
    )
    subparsers = parser.add_subparsers(dest="command")

    run_cmd = subparsers.add_parser(
        "run",
        help="Run unified NIDS pipeline (live, offline, and adapter ingest concurrently).",
    )
    run_cmd.add_argument("--interface", help="Network interface for live capture (example: eth0, wlan0).")
    run_cmd.add_argument("--pcap-dir", help="Directory or file path for offline pcap ingestion.")
    run_cmd.add_argument("--labels", help="Optional labels CSV for offline pcap flow labeling.")
    run_cmd.add_argument("--rules", default="rules/rules.yml", help="Path to signature rule YAML.")
    run_cmd.add_argument("--output-dir", default="output", help="Output directory for DB and JSONL files.")
    run_cmd.add_argument("--config", default="config/nids.yml", help="Runtime config YAML path.")
    run_cmd.add_argument("--sensor-id", default="sensor-local", help="Sensor identifier for multi-sensor records.")
    run_cmd.add_argument("--replay-delay-ms", type=int, help="Offline replay delay in milliseconds.")
    run_cmd.add_argument("--metrics-interval", type=int, help="Runtime metrics print interval seconds.")
    run_cmd.add_argument("--maintenance-enabled", action="store_true", help="Enable scheduled retention maintenance while runtime is active.")
    run_cmd.add_argument("--maintenance-retention-days", type=int, help="Retention window (days) for scheduled maintenance.")
    run_cmd.add_argument("--maintenance-interval-hours", type=float, help="How often to run scheduled maintenance.")
    run_cmd.add_argument("--maintenance-include-artifacts", action="store_true", help="Include artifacts table during scheduled maintenance.")
    run_cmd.add_argument("--maintenance-vacuum", action="store_true", help="Run VACUUM after scheduled maintenance cleanup.")
    run_cmd.add_argument("--model", help="Path to supervised ensemble model for runtime ML inference.")
    run_cmd.add_argument("--unsupervised", action="store_true", help="Enable hybrid unsupervised anomaly scoring.")
    run_cmd.add_argument("--unsupervised-threshold", type=float, help="Combined unsupervised alert threshold (0-1).")
    run_cmd.add_argument("--enable-suricata", action="store_true", help="Enable Suricata eve.json adapter ingest.")
    run_cmd.add_argument("--enable-zeek", action="store_true", help="Enable Zeek JSON adapter ingest.")
    run_cmd.add_argument("--suricata-log", help="Path to Suricata eve.json log.")
    run_cmd.add_argument("--zeek-log", help="Path to Zeek JSON conn log.")
    run_cmd.add_argument("--notify-webhook", help="Optional Slack webhook URL for high alert notifications.")
    run_cmd.add_argument("--notify-min-severity", default="high", help="Minimum severity to notify (low/medium/high/critical).")
    run_cmd.add_argument("--notify-timeout-sec", type=float, help="Webhook request timeout in seconds.")
    run_cmd.add_argument("--notify-max-retries", type=int, help="Webhook retry count on failure.")
    run_cmd.add_argument("--notify-backoff-sec", type=float, help="Initial backoff seconds between retries.")
    run_cmd.add_argument("--notify-max-backoff-sec", type=float, help="Maximum retry backoff seconds.")
    run_cmd.add_argument("--notify-min-interval-sec", type=float, help="Minimum interval seconds between webhook sends.")
    run_cmd.add_argument("--notify-dead-letter", help="Path to JSONL dead-letter log for failed notifications.")
    run_cmd.add_argument("--notify-dead-letter-max-bytes", type=int, help="Rotate dead-letter file when size exceeds this many bytes.")
    run_cmd.add_argument("--notify-dead-letter-backup-count", type=int, help="Number of rotated dead-letter backups to keep.")

    run_local_cmd = subparsers.add_parser(
        "run-local",
        help="Run replay-only local pipeline end-to-end and generate report + visualization outputs.",
    )
    run_local_cmd.add_argument("--pcap-dir", required=True, help="Directory or file path for offline pcap ingestion.")
    run_local_cmd.add_argument("--labels", help="Optional labels CSV for offline pcap flow labeling.")
    run_local_cmd.add_argument("--rules", default="rules/rules.yml", help="Path to signature rule YAML.")
    run_local_cmd.add_argument("--output-dir", default="output", help="Output directory for DB, JSONL, report, and graph files.")
    run_local_cmd.add_argument("--config", default="config/nids.yml", help="Runtime config YAML path.")
    run_local_cmd.add_argument("--sensor-id", default="sensor-local", help="Sensor identifier for replay records.")
    run_local_cmd.add_argument("--replay-delay-ms", type=int, help="Offline replay delay in milliseconds.")
    run_local_cmd.add_argument("--metrics-interval", type=int, help="Runtime metrics print interval seconds.")
    run_local_cmd.add_argument("--model", help="Path to supervised ensemble model for runtime ML inference.")
    run_local_cmd.add_argument("--unsupervised", action="store_true", help="Enable hybrid unsupervised anomaly scoring.")
    run_local_cmd.add_argument("--unsupervised-threshold", type=float, help="Combined unsupervised alert threshold (0-1).")
    run_local_cmd.add_argument("--report-out", help="Optional markdown incident report output path.")
    run_local_cmd.add_argument("--visual-out", help="Optional output directory for generated charts and index page.")

    visualize = subparsers.add_parser(
        "visualize",
        help="Generate offline analytics charts (HTML + PNG + index page).",
    )
    visualize.add_argument("--from-db", required=True, help="Path to SQLite database.")
    visualize.add_argument("--out", required=True, help="Output directory for chart artifacts.")

    dashboard = subparsers.add_parser(
        "dashboard",
        help="Run lightweight live analytics dashboard server.",
    )
    dashboard.add_argument("--from-db", required=True, help="Path to SQLite database used by dashboard.")
    dashboard.add_argument("--host", default="127.0.0.1", help="Dashboard host bind.")
    dashboard.add_argument("--port", type=int, default=8000, help="Dashboard port.")
    dashboard.add_argument("--token", help="Optional API token for dashboard and analytics endpoints.")
    dashboard.add_argument("--action-token", help="Optional token required for dashboard write actions (ack/suppress).")
    dashboard.add_argument("--notify-webhook", help="Optional Slack webhook URL for incident update notifications.")
    dashboard.add_argument("--notify-timeout-sec", type=float, help="Webhook request timeout in seconds.")
    dashboard.add_argument("--notify-max-retries", type=int, help="Webhook retry count on failure.")
    dashboard.add_argument("--notify-backoff-sec", type=float, help="Initial backoff seconds between retries.")
    dashboard.add_argument("--notify-max-backoff-sec", type=float, help="Maximum retry backoff seconds.")
    dashboard.add_argument("--notify-min-interval-sec", type=float, help="Minimum interval seconds between webhook sends.")
    dashboard.add_argument("--notify-dead-letter", help="Path to JSONL dead-letter log for failed notifications.")
    dashboard.add_argument("--notify-dead-letter-max-bytes", type=int, help="Rotate dead-letter file when size exceeds this many bytes.")
    dashboard.add_argument("--notify-dead-letter-backup-count", type=int, help="Number of rotated dead-letter backups to keep.")

    report = subparsers.add_parser(
        "report",
        help="Generate incident timeline report from alerts database.",
    )
    report.add_argument("--from-db", default="output/nids.db", help="Path to SQLite database.")
    report.add_argument("--out", default="reports/summary.md", help="Output markdown report path.")

    sla_report = subparsers.add_parser(
        "sla-report",
        help="Generate weekly SLA KPI summary (JSON + Markdown).",
    )
    sla_report.add_argument("--from-db", default="output/nids.db", help="Path to SQLite database.")
    sla_report.add_argument("--out-json", default="reports/weekly_sla_summary.json", help="Output JSON summary path.")
    sla_report.add_argument("--out-md", default="reports/weekly_sla_summary.md", help="Output markdown summary path.")
    sla_report.add_argument("--lookback-days", type=int, default=7, help="Lookback window in days.")

    threshold_report = subparsers.add_parser(
        "threshold-report",
        help="Generate threshold-tuning guidance from runtime flow scores.",
    )
    threshold_report.add_argument("--from-db", default="output/nids.db", help="Path to SQLite database.")
    threshold_report.add_argument("--out-json", default="reports/threshold_tuning.json", help="Output JSON report path.")
    threshold_report.add_argument("--out-md", default="reports/threshold_tuning.md", help="Output markdown report path.")
    threshold_report.add_argument("--lookback-days", type=int, default=7, help="Lookback window in days.")

    maintenance = subparsers.add_parser(
        "maintenance",
        help="Run SQLite retention + optimization maintenance tasks.",
    )
    maintenance.add_argument("--from-db", default="output/nids.db", help="Path to SQLite database.")
    maintenance.add_argument("--retention-days", type=int, default=30, help="Delete rows older than this many days.")
    maintenance.add_argument("--include-artifacts", action="store_true", help="Include artifacts table in retention cleanup.")
    maintenance.add_argument("--vacuum", action="store_true", help="Run VACUUM after cleanup.")

    train = subparsers.add_parser(
        "train",
        help="Train supervised ensemble model from labeled flow data in SQLite.",
    )
    train.add_argument("--from-db", default="output/nids.db", help="Input SQLite database path.")
    train.add_argument("--out", default="models/model.pkl", help="Output model path.")
    train.add_argument("--metrics-json", default="reports/ml_metrics.json", help="Output metrics JSON path.")
    train.add_argument("--metrics-md", default="reports/ml_metrics.md", help="Output metrics markdown path.")

    evaluate = subparsers.add_parser(
        "evaluate",
        help="Evaluate trained supervised ensemble model on labeled flows in SQLite.",
    )
    evaluate.add_argument("--from-db", default="output/nids.db", help="Input SQLite database path.")
    evaluate.add_argument("--model", default="models/model.pkl", help="Model path.")
    evaluate.add_argument("--out", default="reports/ml_evaluation.json", help="Output evaluation JSON path.")

    artifact_scan = subparsers.add_parser(
        "artifact-scan",
        help="Run one-shot static analysis for files in artifact intake path.",
    )
    artifact_scan.add_argument("--path", default="artifacts/incoming", help="Incoming file or folder path.")
    artifact_scan.add_argument("--recursive", action="store_true", help="Scan directories recursively.")
    artifact_scan.add_argument("--db", default="output/nids.db", help="SQLite path for artifact records.")
    artifact_scan.add_argument("--jsonl", default="output/artifacts.jsonl", help="JSONL output file path.")

    artifact_watch = subparsers.add_parser(
        "artifact-watch",
        help="Continuously watch and process files from artifact intake path.",
    )
    artifact_watch.add_argument("--path", default="artifacts/incoming", help="Incoming folder path.")
    artifact_watch.add_argument("--recursive", action="store_true", help="Recursive scanning each cycle.")
    artifact_watch.add_argument("--interval", type=int, default=5, help="Polling interval seconds.")
    artifact_watch.add_argument("--db", default="output/nids.db", help="SQLite path for artifact records.")
    artifact_watch.add_argument("--jsonl", default="output/artifacts.jsonl", help="JSONL output file path.")

    artifact_report = subparsers.add_parser(
        "artifact-report",
        help="Generate markdown summary report for analyzed artifacts.",
    )
    artifact_report.add_argument("--from-db", default="output/nids.db", help="Path to SQLite database.")
    artifact_report.add_argument("--out", default="reports/artifacts/summary.md", help="Output markdown path.")

    thesis_docs = subparsers.add_parser(
        "thesis-docs",
        help="Generate thesis-style documentation from the current repository state.",
    )
    thesis_docs.add_argument("--repo-root", default=".", help="Repository root path.")
    thesis_docs.add_argument("--out-md", help="Optional override for the consolidated markdown output path.")
    thesis_docs.add_argument("--out-docx", help="Optional override for the consolidated DOCX output path.")

    return parser


def cmd_run(args: argparse.Namespace) -> int:
    cfg = build_runtime_config(args)
    labels_path = Path(args.labels).resolve() if args.labels else None
    run_runtime(cfg=cfg, labels_path=labels_path, sensor_id=str(args.sensor_id))
    return 0


def cmd_run_local(args: argparse.Namespace) -> int:
    cfg = build_runtime_config(args)
    labels_path = Path(args.labels).resolve() if args.labels else None
    report_out = Path(args.report_out).resolve() if args.report_out else None
    visual_out = Path(args.visual_out).resolve() if args.visual_out else None

    try:
        result = run_local_pipeline(
            cfg=cfg,
            labels_path=labels_path,
            sensor_id=str(args.sensor_id),
            report_out=report_out,
            visual_out=visual_out,
        )
    except Exception as exc:
        print(f"run-local: error: {exc}")
        return 2

    print(f"run-local: db={result.db_path}")
    print(
        "run-local: "
        f"flows={result.flow_count} alerts={result.alert_count} metrics={result.metric_count}"
    )
    print(f"run-local: report={result.report_path}")
    print(f"run-local: visuals={result.visual_index_path} charts={result.chart_count}")
    return 0


def cmd_visualize(args: argparse.Namespace) -> int:
    index_path, charts = run_visual_export(db_path=Path(args.from_db), output_dir=Path(args.out))
    print(f"Generated {len(charts)} charts")
    print(f"Index: {index_path}")
    return 0


def cmd_dashboard(args: argparse.Namespace) -> int:
    run_dashboard(
        db_path=args.from_db,
        host=args.host,
        port=args.port,
        api_token=args.token,
        action_token=args.action_token,
        notify_webhook=args.notify_webhook,
        notify_timeout_sec=args.notify_timeout_sec,
        notify_max_retries=args.notify_max_retries,
        notify_backoff_sec=args.notify_backoff_sec,
        notify_max_backoff_sec=args.notify_max_backoff_sec,
        notify_min_interval_sec=args.notify_min_interval_sec,
        notify_dead_letter=args.notify_dead_letter,
        notify_dead_letter_max_bytes=args.notify_dead_letter_max_bytes,
        notify_dead_letter_backup_count=args.notify_dead_letter_backup_count,
    )
    return 0


def cmd_report(args: argparse.Namespace) -> int:
    output = generate_incident_report(from_db=args.from_db, out=args.out)
    print(f"report: generated {output}")
    return 0


def cmd_sla_report(args: argparse.Namespace) -> int:
    json_path, md_path = generate_sla_weekly_summary(
        from_db=args.from_db,
        out_json=args.out_json,
        out_md=args.out_md,
        lookback_days=int(args.lookback_days),
    )
    print(f"sla-report: generated {json_path}")
    print(f"sla-report: generated {md_path}")
    return 0


def cmd_maintenance(args: argparse.Namespace) -> int:
    store = SQLiteStore(args.from_db)
    try:
        before = store.health_snapshot()
        result = store.prune_old_rows(
            retention_days=int(args.retention_days),
            include_artifacts=bool(args.include_artifacts),
        )
        if bool(args.vacuum):
            store.vacuum()
        after = store.health_snapshot()
    finally:
        store.close()

    print(
        "maintenance: "
        f"retention_days={result['retention_days']} "
        f"deleted_total={result['deleted_total']} "
        f"vacuum={bool(args.vacuum)}"
    )
    print(f"maintenance: deleted={result['deleted']}")
    print(f"maintenance: rows_before={before.get('row_counts', {})}")
    print(f"maintenance: rows_after={after.get('row_counts', {})}")
    return 0


def cmd_threshold_report(args: argparse.Namespace) -> int:
    json_path, md_path = generate_threshold_tuning_report(
        from_db=args.from_db,
        out_json=args.out_json,
        out_md=args.out_md,
        lookback_days=int(args.lookback_days),
    )
    print(f"threshold-report: generated {json_path}")
    print(f"threshold-report: generated {md_path}")
    return 0


def cmd_train(args: argparse.Namespace) -> int:
    metrics = train_from_db(
        db_path=args.from_db,
        out_model=args.out,
        metrics_json=args.metrics_json,
        metrics_md=args.metrics_md,
    )
    print(
        "train: "
        f"samples={metrics.get('samples_total')} "
        f"accuracy={metrics.get('accuracy', 0):.4f} "
        f"f1={metrics.get('f1_weighted', 0):.4f}"
    )
    return 0


def cmd_evaluate(args: argparse.Namespace) -> int:
    metrics = evaluate_model(db_path=args.from_db, model_path=args.model, output_json=args.out)
    print(
        "evaluate: "
        f"samples={metrics.get('samples')} "
        f"accuracy={metrics.get('accuracy', 0):.4f} "
        f"f1={metrics.get('f1_weighted', 0):.4f}"
    )
    return 0


def cmd_artifact_scan(args: argparse.Namespace) -> int:
    summary = run_artifact_scan(
        path=args.path,
        recursive=bool(args.recursive),
        db_path=args.db,
        jsonl_path=args.jsonl,
    )
    print(
        "artifact-scan: "
        f"scanned={summary.scanned} inserted={summary.inserted} "
        f"duplicates={summary.duplicates} quarantined={summary.quarantined} "
        f"processed={summary.processed} errors={summary.errors}"
    )
    return 0


def cmd_artifact_watch(args: argparse.Namespace) -> int:
    run_artifact_watch(
        path=args.path,
        recursive=bool(args.recursive),
        interval_sec=int(args.interval),
        db_path=args.db,
        jsonl_path=args.jsonl,
    )
    return 0


def cmd_artifact_report(args: argparse.Namespace) -> int:
    output_path = generate_artifact_report(db_path=args.from_db, out_path=args.out)
    print(f"artifact-report: generated {output_path}")
    return 0


def cmd_thesis_docs(args: argparse.Namespace) -> int:
    outputs = generate_thesis_documents(
        repo_root=Path(args.repo_root),
        out_md=args.out_md,
        out_docx=args.out_docx,
    )
    for key, value in outputs.items():
        print(f"thesis-docs: {key}={value}")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.command == "run":
        return cmd_run(args)
    if args.command == "run-local":
        return cmd_run_local(args)
    if args.command == "visualize":
        return cmd_visualize(args)
    if args.command == "dashboard":
        return cmd_dashboard(args)
    if args.command == "report":
        return cmd_report(args)
    if args.command == "sla-report":
        return cmd_sla_report(args)
    if args.command == "maintenance":
        return cmd_maintenance(args)
    if args.command == "threshold-report":
        return cmd_threshold_report(args)
    if args.command == "train":
        return cmd_train(args)
    if args.command == "evaluate":
        return cmd_evaluate(args)
    if args.command == "artifact-scan":
        return cmd_artifact_scan(args)
    if args.command == "artifact-watch":
        return cmd_artifact_watch(args)
    if args.command == "artifact-report":
        return cmd_artifact_report(args)
    if args.command == "thesis-docs":
        return cmd_thesis_docs(args)

    parser.print_help()
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
