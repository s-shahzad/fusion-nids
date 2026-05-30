from __future__ import annotations

import asyncio
from collections import deque
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .config import RuntimeConfig
from .detect import AlertSuppressor, AnomalyEngine, FusionEngine, MLEngineRouter, SignatureEngine
from .ingest import run_live_capture, run_offline_pcaps, run_suricata_eve, run_zeek_json
from .pipeline.features import FeatureExtractor
from .storage import JSONLStore, SQLiteStore
from .utils import SlackWebhookNotifier


@dataclass
class RuntimeStats:
    events_seen: int = 0
    alerts_emitted: int = 0
    suppressed_alerts: int = 0
    policy_suppressed_alerts: int = 0
    high_alerts: int = 0
    medium_alerts: int = 0
    low_alerts: int = 0
    last_ingest_lag_sec: float = 0.0
    recent_alerts: deque[dict[str, Any]] = field(default_factory=lambda: deque(maxlen=10))


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _to_epoch(value: str) -> float | None:
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00")).timestamp()
    except Exception:
        return None


def _severity_bucket(severity: str) -> str:
    token = severity.lower()
    if token in {"critical", "high", "alert"}:
        return "high"
    if token in {"medium", "warning", "monitor"}:
        return "medium"
    return "low"


class NIDSRuntime:
    """Concurrent runtime for live/offline/adapters using one detection pipeline."""

    def __init__(
        self,
        cfg: RuntimeConfig,
        labels_path: Path | None = None,
        sensor_id: str = "sensor-local",
    ) -> None:
        self.cfg = cfg
        self.labels_path = labels_path
        self.sensor_id = sensor_id

        self.queue: asyncio.Queue[dict[str, Any] | None] = asyncio.Queue(
            maxsize=int(self.cfg.pipeline.get("queue_max_size", 20000))
        )
        self.stop_event = asyncio.Event()

        self.stats = RuntimeStats()

        self.features = FeatureExtractor(scan_window_sec=int(self.cfg.detection.get("scan_window_sec", 12)))
        self.signature = SignatureEngine(self.cfg.rules_path)
        self.anomaly = AnomalyEngine(self.cfg.detection)
        self.fusion = FusionEngine(self.cfg.fusion)

        ml_cfg = dict(self.cfg.ml)
        ml_cfg.setdefault("unsupervised", False)
        ml_cfg.setdefault("unsupervised_persist_baseline", True)
        if bool(ml_cfg.get("unsupervised_persist_baseline", True)) and not str(
            ml_cfg.get("unsupervised_baseline_path") or ""
        ).strip():
            ml_cfg["unsupervised_baseline_path"] = str((self.cfg.output_dir / "unsupervised_baseline.pkl").resolve())
        self.ml = MLEngineRouter(ml_cfg)

        self.suppressor = AlertSuppressor(window_sec=int(self.cfg.detection.get("suppress_window_sec", 15)))

        self.cfg.output_dir.mkdir(parents=True, exist_ok=True)
        self.sqlite = SQLiteStore(self.cfg.output_dir / "nids.db")
        self.jsonl = JSONLStore(self.cfg.output_dir)

        maintenance_cfg = dict(self.cfg.maintenance or {})
        self._maintenance_enabled = bool(maintenance_cfg.get("enabled", False))
        self._maintenance_retention_days = max(1, int(maintenance_cfg.get("retention_days", 30)))
        self._maintenance_include_artifacts = bool(maintenance_cfg.get("include_artifacts", False))
        self._maintenance_vacuum = bool(maintenance_cfg.get("vacuum", False))

        if maintenance_cfg.get("interval_sec") is not None:
            self._maintenance_interval_sec = max(300, int(maintenance_cfg.get("interval_sec") or 86400))
        else:
            interval_hours = float(maintenance_cfg.get("interval_hours", 24))
            self._maintenance_interval_sec = max(300, int(interval_hours * 3600))

        self._last_maintenance_epoch = 0.0

        notify_cfg = dict(self.cfg.notifications or {})
        notify_enabled = bool(notify_cfg.get("enabled", False))
        notify_webhook = str(notify_cfg.get("slack_webhook") or "").strip() if notify_enabled else ""
        notify_timeout = float(notify_cfg.get("timeout_sec", 3))
        notify_min_severity = str(notify_cfg.get("min_severity", "high"))
        notify_max_retries = int(notify_cfg.get("max_retries", 2))
        notify_backoff_sec = float(notify_cfg.get("backoff_sec", 0.5))
        notify_max_backoff_sec = float(notify_cfg.get("max_backoff_sec", 4.0))
        notify_min_interval_sec = float(notify_cfg.get("min_interval_sec", 0.1))
        notify_dead_letter = str(notify_cfg.get("dead_letter_path") or "").strip()
        notify_dead_letter_max_bytes = int(notify_cfg.get("dead_letter_max_bytes", 10485760))
        notify_dead_letter_backup_count = int(notify_cfg.get("dead_letter_backup_count", 5))
        self.notifier = SlackWebhookNotifier(
            webhook_url=notify_webhook or None,
            timeout_sec=notify_timeout,
            min_severity=notify_min_severity,
            max_retries=notify_max_retries,
            backoff_sec=notify_backoff_sec,
            max_backoff_sec=notify_max_backoff_sec,
            min_interval_sec=notify_min_interval_sec,
            dead_letter_path=notify_dead_letter or None,
            dead_letter_max_bytes=notify_dead_letter_max_bytes,
            dead_letter_backup_count=notify_dead_letter_backup_count,
        )

    async def _producer_wrapper(self, name: str, producer: asyncio.Future[Any] | asyncio.Task[Any] | Any) -> None:
        try:
            await producer
        except asyncio.CancelledError:
            pass
        except Exception as exc:
            print(f"producer[{name}] error: {exc}")
        finally:
            await self.queue.put(None)

    async def _run_consumer(self, producers: int) -> None:
        sentinels = 0
        while sentinels < producers:
            item = await self.queue.get()
            try:
                if item is None:
                    sentinels += 1
                    continue
                self._process_event(item)
            finally:
                self.queue.task_done()

    def _process_event(self, event: dict[str, Any]) -> None:
        self.stats.events_seen += 1
        features = self.features.extract(event)

        anomaly_alerts, anomaly_score = self.anomaly.detect(event, features)
        signature_alerts = self.signature.detect(event, features)
        ml_alerts, ml_prediction = self.ml.detect(
            event,
            features,
            force=bool(signature_alerts or anomaly_alerts),
        )
        fusion_alerts, fusion_prediction = self.fusion.fuse(
            signature_alerts=signature_alerts,
            anomaly_alerts=anomaly_alerts,
            ml_alerts=ml_alerts,
            ml_prediction=ml_prediction,
            anomaly_score=anomaly_score,
        )

        event_timestamp = str(event.get("timestamp") or _now_iso())
        event_epoch = _to_epoch(event_timestamp)
        if event_epoch is not None:
            now_epoch = datetime.now(timezone.utc).timestamp()
            self.stats.last_ingest_lag_sec = max(0.0, now_epoch - event_epoch)

        flow_record = {
            "timestamp": event_timestamp,
            "sensor_id": event.get("sensor_id") or self.sensor_id,
            "dataset_source": event.get("dataset_source") or "unknown",
            "src_ip": event.get("src_ip"),
            "dst_ip": event.get("dst_ip"),
            "src_port": event.get("src_port"),
            "dst_port": event.get("dst_port"),
            "proto": event.get("proto"),
            "packet_len": event.get("packet_len"),
            "tcp_flags": event.get("tcp_flags"),
            "packet_count": 1,
            "packet_rate_dst": features.get("packet_rate_dst"),
            "unique_dst_ports_src_window": features.get("unique_dst_ports_src_window"),
            "unique_dst_hosts_src_window": features.get("unique_dst_hosts_src_window"),
            "label": event.get("label"),
            "attack_type": event.get("attack_type"),
            "is_labeled": int(event.get("is_labeled") or (1 if event.get("label") else 0)),
            "anomaly_score": anomaly_score,
            "predicted_label": ml_prediction.get("predicted_label"),
            "predicted_attack_type": ml_prediction.get("predicted_attack_type"),
            "prediction_score": ml_prediction.get("prediction_score"),
            "supervised_label": ml_prediction.get("supervised_label"),
            "supervised_score": ml_prediction.get("supervised_score"),
            "unsupervised_label": ml_prediction.get("unsupervised_label"),
            "unsupervised_score": ml_prediction.get("unsupervised_score"),
            "unsupervised_isolation_score": ml_prediction.get("unsupervised_isolation_score"),
            "unsupervised_autoencoder_score": ml_prediction.get("unsupervised_autoencoder_score"),
            "fusion_label": fusion_prediction.get("fusion_label"),
            "fusion_score": fusion_prediction.get("fusion_score"),
            "fusion_agreement_count": fusion_prediction.get("fusion_agreement_count"),
            "payload_preview": bytes(event.get("payload", b""))[:180].decode("utf-8", errors="ignore"),
        }
        self.sqlite.insert_flow(flow_record)
        self.jsonl.append_flow(flow_record)

        all_alerts = signature_alerts + anomaly_alerts + ml_alerts + fusion_alerts
        for alert in all_alerts:
            record = {
                "timestamp": flow_record["timestamp"],
                "sensor_id": flow_record["sensor_id"],
                "dataset_source": flow_record["dataset_source"],
                "src_ip": flow_record["src_ip"],
                "dst_ip": flow_record["dst_ip"],
                "src_port": flow_record["src_port"],
                "dst_port": flow_record["dst_port"],
                "proto": flow_record["proto"],
                "severity": alert.get("severity", "medium"),
                "engine": alert.get("engine", "unknown"),
                "rule_name": alert.get("rule_name", "unknown_rule"),
                "summary": alert.get("summary", "alert"),
                "anomaly_score": flow_record.get("anomaly_score"),
                "predicted_label": flow_record.get("predicted_label"),
                "predicted_attack_type": flow_record.get("predicted_attack_type"),
                "prediction_score": flow_record.get("prediction_score"),
                "supervised_score": flow_record.get("supervised_score"),
                "unsupervised_score": flow_record.get("unsupervised_score"),
                "unsupervised_isolation_score": flow_record.get("unsupervised_isolation_score"),
                "unsupervised_autoencoder_score": flow_record.get("unsupervised_autoencoder_score"),
                "fusion_score": flow_record.get("fusion_score"),
                "fusion_label": flow_record.get("fusion_label"),
                "fusion_agreement_count": flow_record.get("fusion_agreement_count"),
                "label": flow_record.get("label"),
                "attack_type": flow_record.get("attack_type"),
                "is_labeled": flow_record.get("is_labeled"),
                "extra": {
                    **(alert.get("extra", {}) or {}),
                    "supervised_label": flow_record.get("supervised_label"),
                    "unsupervised_label": flow_record.get("unsupervised_label"),
                    "unsupervised_components": ml_prediction.get("unsupervised_components", {}),
                    "unsupervised_active_components": ml_prediction.get("unsupervised_active_components", []),
                    "fusion_components": fusion_prediction.get("fusion_components", {}),
                    "fusion_active_components": fusion_prediction.get("fusion_active_components", []),
                },
            }

            suppression_rule = self.sqlite.match_active_suppression(record)
            if suppression_rule is not None:
                self.stats.suppressed_alerts += 1
                self.stats.policy_suppressed_alerts += 1
                continue

            if not self.suppressor.should_emit(record, str(record["timestamp"])):
                self.stats.suppressed_alerts += 1
                continue

            alert_id = self.sqlite.insert_alert(record)
            record["id"] = alert_id
            self.jsonl.append_alert(record)

            if self.notifier.enabled:
                self.notifier.notify_high_alert(record)

            severity_bucket = _severity_bucket(str(record["severity"]))
            if severity_bucket == "high":
                self.stats.high_alerts += 1
            elif severity_bucket == "medium":
                self.stats.medium_alerts += 1
            else:
                self.stats.low_alerts += 1

            self.stats.alerts_emitted += 1
            self.stats.recent_alerts.append(record)

    def _run_maintenance_if_due(self, now_epoch: float) -> None:
        if not self._maintenance_enabled:
            return

        if self._last_maintenance_epoch > 0:
            elapsed = now_epoch - self._last_maintenance_epoch
            if elapsed < self._maintenance_interval_sec:
                return

        self._last_maintenance_epoch = now_epoch

        try:
            result = self.sqlite.prune_old_rows(
                retention_days=self._maintenance_retention_days,
                include_artifacts=self._maintenance_include_artifacts,
            )
            if self._maintenance_vacuum:
                self.sqlite.vacuum()

            deleted_total = float(result.get("deleted_total", 0))
            stamp = _now_iso()
            self.sqlite.insert_metric(stamp, self.sensor_id, "maintenance_deleted_total", deleted_total)
            self.jsonl.append_metric(
                {
                    "timestamp": stamp,
                    "sensor_id": self.sensor_id,
                    "metric_name": "maintenance_deleted_total",
                    "metric_value": deleted_total,
                }
            )
            print(
                "maintenance: "
                f"deleted_total={int(deleted_total)} "
                f"retention_days={self._maintenance_retention_days} "
                f"vacuum={self._maintenance_vacuum}"
            )
        except Exception as exc:
            print(f"maintenance error: {exc}")

    async def _metrics_loop(self) -> None:
        interval = max(1, int(self.cfg.pipeline.get("metrics_interval_sec", 5)))
        prev_events = 0
        prev_alerts = 0

        while not self.stop_event.is_set():
            await asyncio.sleep(interval)

            events_delta = self.stats.events_seen - prev_events
            alerts_delta = self.stats.alerts_emitted - prev_alerts
            prev_events = self.stats.events_seen
            prev_alerts = self.stats.alerts_emitted

            eps = events_delta / interval
            apm = alerts_delta * (60.0 / interval)

            stamp = _now_iso()
            queue_size = self.queue.qsize()

            metric_payloads = [
                ("runtime_heartbeat", 1.0),
                ("events_per_sec", eps),
                ("alerts_per_min", apm),
                ("queue_size", float(queue_size)),
                ("ingest_lag_sec", float(self.stats.last_ingest_lag_sec)),
                ("total_alerts", float(self.stats.alerts_emitted)),
                ("suppressed_alerts", float(self.stats.suppressed_alerts)),
                ("policy_suppressed_alerts", float(self.stats.policy_suppressed_alerts)),
            ]
            for name, value in metric_payloads:
                self.sqlite.insert_metric(stamp, self.sensor_id, name, float(value))
                self.jsonl.append_metric(
                    {
                        "timestamp": stamp,
                        "sensor_id": self.sensor_id,
                        "metric_name": name,
                        "metric_value": value,
                    }
                )

            self._run_maintenance_if_due(datetime.now(timezone.utc).timestamp())
            self.ml.persist_state()

            recent = list(self.stats.recent_alerts)[-3:]
            tail = " | ".join(f"{item['engine']}:{item['rule_name']}" for item in recent) if recent else "none"
            print(
                f"runtime: eps={eps:.1f} apm={apm:.1f} alerts={self.stats.alerts_emitted} "
                f"suppressed={self.stats.suppressed_alerts} queue={queue_size} "
                f"lag={self.stats.last_ingest_lag_sec:.2f}s recent={tail}"
            )

    async def run(self) -> None:
        producer_tasks: list[asyncio.Task[Any]] = []

        if self.cfg.interface:
            producer_tasks.append(
                asyncio.create_task(
                    self._producer_wrapper(
                        "live",
                        run_live_capture(
                            interface=self.cfg.interface,
                            queue=self.queue,
                            stop_event=self.stop_event,
                            sensor_id=self.sensor_id,
                            backend=str(self.cfg.pipeline.get("live_capture_backend", "auto")),
                            tcpdump_bin=str(self.cfg.pipeline.get("live_capture_tcpdump_bin", "tcpdump")),
                            tcpdump_snaplen=int(self.cfg.pipeline.get("live_capture_tcpdump_snaplen", 0)),
                            bpf_filter=str(self.cfg.pipeline.get("live_capture_bpf_filter", "")),
                        ),
                    )
                )
            )

        if self.cfg.pcap_dir:
            producer_tasks.append(
                asyncio.create_task(
                    self._producer_wrapper(
                        "offline",
                        run_offline_pcaps(
                            pcap_dir=self.cfg.pcap_dir,
                            queue=self.queue,
                            stop_event=self.stop_event,
                            replay_delay_ms=int(self.cfg.pipeline.get("replay_delay_ms", 0)),
                            labels_path=self.labels_path,
                            sensor_id=self.sensor_id,
                        ),
                    )
                )
            )

        suricata_cfg = self.cfg.adapters.get("suricata", {}) if isinstance(self.cfg.adapters, dict) else {}
        if bool(suricata_cfg.get("enabled")):
            producer_tasks.append(
                asyncio.create_task(
                    self._producer_wrapper(
                        "suricata",
                        run_suricata_eve(
                            eve_path=str(suricata_cfg.get("path", "")),
                            queue=self.queue,
                            stop_event=self.stop_event,
                            sensor_id=f"{self.sensor_id}-suricata",
                        ),
                    )
                )
            )

        zeek_cfg = self.cfg.adapters.get("zeek", {}) if isinstance(self.cfg.adapters, dict) else {}
        if bool(zeek_cfg.get("enabled")):
            producer_tasks.append(
                asyncio.create_task(
                    self._producer_wrapper(
                        "zeek",
                        run_zeek_json(
                            zeek_path=str(zeek_cfg.get("path", "")),
                            queue=self.queue,
                            stop_event=self.stop_event,
                            sensor_id=f"{self.sensor_id}-zeek",
                        ),
                    )
                )
            )

        if not producer_tasks:
            raise ValueError("No ingest source configured. Provide --interface and/or --pcap-dir or adapters.")

        consumer_task = asyncio.create_task(self._run_consumer(producers=len(producer_tasks)))
        metrics_task = asyncio.create_task(self._metrics_loop())

        try:
            await asyncio.gather(*producer_tasks)
            await consumer_task
        finally:
            self.stop_event.set()
            for task in producer_tasks:
                if not task.done():
                    task.cancel()
            await asyncio.gather(*producer_tasks, return_exceptions=True)

            if not consumer_task.done():
                consumer_task.cancel()
                await asyncio.gather(consumer_task, return_exceptions=True)

            metrics_task.cancel()
            await asyncio.gather(metrics_task, return_exceptions=True)
            baseline_path = self.ml.close()
            if baseline_path:
                print(f"runtime: saved unsupervised baseline {baseline_path}")
            self.sqlite.close()


def run_runtime(cfg: RuntimeConfig, labels_path: Path | None = None, sensor_id: str = "sensor-local") -> None:
    runtime = NIDSRuntime(cfg=cfg, labels_path=labels_path, sensor_id=sensor_id)

    try:
        asyncio.run(runtime.run())
    except KeyboardInterrupt:
        print("runtime: stopped by user")
