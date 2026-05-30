from __future__ import annotations

import copy
from datetime import datetime
from pathlib import Path
import time
from typing import Any

from .ml_supervised import SupervisedMLEngine
from .ml_unsupervised import UnsupervisedMLEngine


def _to_epoch(value: Any) -> float | None:
    token = str(value or "").strip()
    if not token:
        return None
    try:
        return datetime.fromisoformat(token.replace("Z", "+00:00")).timestamp()
    except Exception:
        return None


class MLEngineRouter:
    """Route runtime ML detection between supervised and unsupervised engines."""

    def __init__(self, config: dict[str, Any]) -> None:
        model_path = Path(str(config.get("model_path") or "models/model.pkl"))
        score_threshold = float(config.get("score_threshold", 0.6))
        self.live_throttle_enabled = bool(config.get("live_throttle_enabled", True))
        self.live_min_inference_interval_sec = max(0.0, float(config.get("live_min_inference_interval_sec", 1.0)))
        self._live_last_inference_ts: dict[tuple[str, str, str, str, str], float] = {}
        self._live_prediction_cache: dict[tuple[str, str, str, str, str], dict[str, Any]] = {}
        self._live_cleanup_counter = 0

        self.supervised: SupervisedMLEngine | None = None
        if model_path.exists():
            engine = SupervisedMLEngine(model_path=model_path, score_threshold=score_threshold)
            if engine.available:
                self.supervised = engine

        self.unsupervised_enabled = bool(config.get("unsupervised", False))
        self.unsupervised: UnsupervisedMLEngine | None = None
        if self.unsupervised_enabled:
            snapshot_path = config.get("unsupervised_baseline_path") if bool(
                config.get("unsupervised_persist_baseline", True)
            ) else None
            self.unsupervised = UnsupervisedMLEngine(
                warmup_samples=int(config.get("unsupervised_warmup_samples", 200)),
                contamination=float(config.get("unsupervised_contamination", 0.03)),
                alert_threshold=float(config.get("unsupervised_alert_threshold", 0.65)),
                component_threshold=config.get("unsupervised_component_threshold"),
                autoencoder_enabled=bool(config.get("unsupervised_autoencoder", True)),
                autoencoder_hidden_size=int(config.get("unsupervised_autoencoder_hidden_size", 8)),
                autoencoder_max_iter=int(config.get("unsupervised_autoencoder_max_iter", 400)),
                snapshot_path=snapshot_path,
            )

    @staticmethod
    def _empty_prediction() -> dict[str, Any]:
        return {
            "predicted_label": None,
            "predicted_attack_type": None,
            "prediction_score": None,
            "supervised_label": None,
            "supervised_attack_type": None,
            "supervised_score": None,
            "supervised_algorithms": [],
            "supervised_model_count": 0,
            "unsupervised_label": None,
            "unsupervised_attack_type": None,
            "unsupervised_score": None,
            "unsupervised_isolation_score": None,
            "unsupervised_autoencoder_score": None,
            "unsupervised_components": {},
            "unsupervised_active_components": [],
            "unsupervised_algorithms": [],
            "unsupervised_model_count": 0,
            "unsupervised_baseline_path": None,
        }

    @staticmethod
    def _is_live_event(event: dict[str, Any]) -> bool:
        return str(event.get("dataset_source") or "").lower() == "live"

    @staticmethod
    def _port_token(value: Any) -> str:
        try:
            return str(int(value))
        except Exception:
            return str(value or "0")

    @classmethod
    def _live_key(cls, event: dict[str, Any]) -> tuple[str, str, str, str, str]:
        return (
            str(event.get("src_ip") or "unknown"),
            str(event.get("dst_ip") or "unknown"),
            cls._port_token(event.get("src_port")),
            cls._port_token(event.get("dst_port")),
            str(event.get("proto") or "UNKNOWN").upper(),
        )

    def _maybe_prune_live_cache(self, now_epoch: float) -> None:
        self._live_cleanup_counter += 1
        if self._live_cleanup_counter % 256 != 0:
            return
        if len(self._live_last_inference_ts) < 4096:
            return

        cutoff = now_epoch - max(60.0, self.live_min_inference_interval_sec * 10.0)
        expired = [key for key, stamp in self._live_last_inference_ts.items() if stamp < cutoff]
        for key in expired:
            self._live_last_inference_ts.pop(key, None)
            self._live_prediction_cache.pop(key, None)

    def _cached_live_prediction(self, event: dict[str, Any], force: bool) -> dict[str, Any] | None:
        if force or not self.live_throttle_enabled or self.live_min_inference_interval_sec <= 0:
            return None
        if not self._is_live_event(event):
            return None

        key = self._live_key(event)
        now_epoch = _to_epoch(event.get("timestamp")) or time.monotonic()
        last_epoch = self._live_last_inference_ts.get(key)
        if last_epoch is None:
            return None
        if now_epoch - last_epoch >= self.live_min_inference_interval_sec:
            return None

        cached = self._live_prediction_cache.get(key)
        return copy.deepcopy(cached) if cached is not None else self._empty_prediction()

    def _store_live_prediction(self, event: dict[str, Any], prediction: dict[str, Any]) -> None:
        if not self.live_throttle_enabled or self.live_min_inference_interval_sec <= 0:
            return
        if not self._is_live_event(event):
            return

        key = self._live_key(event)
        now_epoch = _to_epoch(event.get("timestamp")) or time.monotonic()
        self._live_last_inference_ts[key] = now_epoch
        self._live_prediction_cache[key] = copy.deepcopy(prediction)
        self._maybe_prune_live_cache(now_epoch)

    def detect(
        self,
        event: dict[str, Any],
        features: dict[str, Any],
        *,
        force: bool = False,
    ) -> tuple[list[dict[str, Any]], dict[str, Any]]:
        alerts: list[dict[str, Any]] = []
        merged_prediction = self._empty_prediction()

        cached = self._cached_live_prediction(event, force=force)
        if cached is not None:
            return [], cached

        if self.supervised is not None:
            model_alerts, model_prediction = self.supervised.detect(event, features)
            alerts.extend(model_alerts)
            merged_prediction.update(model_prediction)

        if self.unsupervised is not None:
            unsup_alerts, unsup_prediction = self.unsupervised.detect(event, features)
            alerts.extend(unsup_alerts)
            merged_prediction.update(unsup_prediction)

            if merged_prediction.get("predicted_label") in {None, ""}:
                unsup_label = merged_prediction.get("unsupervised_label")
                if unsup_label not in {None, "", "benign"}:
                    merged_prediction["predicted_label"] = unsup_label
                    merged_prediction["predicted_attack_type"] = merged_prediction.get("unsupervised_attack_type")
                    merged_prediction["prediction_score"] = merged_prediction.get("unsupervised_score")

        self._store_live_prediction(event, merged_prediction)
        return alerts, merged_prediction

    def persist_state(self) -> str | None:
        if self.unsupervised is None:
            return None
        saved_path = self.unsupervised.save_snapshot()
        return str(saved_path) if saved_path is not None else None

    def close(self) -> str | None:
        return self.persist_state()
