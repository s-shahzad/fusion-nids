from __future__ import annotations

from src.NIDS.replay_metrics import compute_replay_metrics


def _alert(rule_name: str, *, summary: str = "", engine: str = "signature") -> dict[str, str]:
    return {"rule_name": rule_name, "summary": summary, "engine": engine}


def test_compute_replay_metrics_mixed_case() -> None:
    payload = compute_replay_metrics(
        expected_detections=[
            {"label": "port_scan", "count": 1, "match_any": ["port scan"]},
            {"label": "dos", "count": 1, "match_any": ["dos"]},
        ],
        observed_alerts=[
            _alert("Port Scan Threshold"),
            _alert("Unexpected Noise"),
        ],
    )

    assert payload["totals"] == {"expected": 2, "observed": 2, "tp": 1, "fp": 1, "fn": 1}
    assert payload["metrics"]["precision"] == 0.5
    assert payload["metrics"]["recall"] == 0.5
    assert payload["metrics"]["f1"] == 0.5


def test_compute_replay_metrics_perfect_case() -> None:
    payload = compute_replay_metrics(
        expected_detections=[
            {"label": "port_scan", "count": 1, "match_any": ["port scan"]},
            {"label": "dos", "count": 1, "match_any": ["dos"]},
        ],
        observed_alerts=[
            _alert("Port Scan Threshold"),
            _alert("DoS Rate Threshold"),
        ],
    )

    assert payload["totals"] == {"expected": 2, "observed": 2, "tp": 2, "fp": 0, "fn": 0}
    assert payload["metrics"]["precision"] == 1.0
    assert payload["metrics"]["recall"] == 1.0
    assert payload["metrics"]["f1"] == 1.0


def test_compute_replay_metrics_zero_alerts() -> None:
    payload = compute_replay_metrics(
        expected_detections=[{"label": "port_scan", "count": 1, "match_any": ["port scan"]}],
        observed_alerts=[],
    )

    assert payload["totals"] == {"expected": 1, "observed": 0, "tp": 0, "fp": 0, "fn": 1}
    assert payload["metrics"]["precision"] == 0.0
    assert payload["metrics"]["recall"] == 0.0
    assert payload["metrics"]["f1"] == 0.0


def test_compute_replay_metrics_zero_expected_events() -> None:
    payload = compute_replay_metrics(
        expected_detections=[],
        observed_alerts=[_alert("Port Scan Threshold")],
    )

    assert payload["totals"] == {"expected": 0, "observed": 1, "tp": 0, "fp": 1, "fn": 0}
    assert payload["metrics"]["precision"] == 0.0
    assert payload["metrics"]["recall"] == 0.0
    assert payload["metrics"]["f1"] == 0.0


def test_compute_replay_metrics_partial_match_with_counts() -> None:
    payload = compute_replay_metrics(
        expected_detections=[{"label": "fusion", "count": 2, "match_any": ["fusion"]}],
        observed_alerts=[
            _alert("Hybrid Fusion Decision", engine="fusion"),
        ],
    )

    assert payload["totals"] == {"expected": 2, "observed": 1, "tp": 1, "fp": 0, "fn": 1}
    assert payload["metrics"]["precision"] == 1.0
    assert payload["metrics"]["recall"] == 0.5
    assert round(payload["metrics"]["f1"], 4) == 0.6667
