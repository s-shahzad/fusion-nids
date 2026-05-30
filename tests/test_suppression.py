from src.NIDS.detect.suppression import AlertSuppressor


def test_alert_suppression_window() -> None:
    suppressor = AlertSuppressor(window_sec=10)
    alert = {
        "engine": "anomaly",
        "rule_name": "DoS Rate Threshold",
        "src_ip": "1.1.1.1",
        "dst_ip": "2.2.2.2",
        "dst_port": 80,
        "severity": "high",
    }

    ts0 = "2026-03-06T00:00:00+00:00"
    ts1 = "2026-03-06T00:00:05+00:00"
    ts2 = "2026-03-06T00:00:11+00:00"

    assert suppressor.should_emit(alert, ts0)
    assert not suppressor.should_emit(alert, ts1)
    assert suppressor.should_emit(alert, ts2)
