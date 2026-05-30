from datetime import datetime, timedelta, timezone

from src.NIDS.detect.anomaly import AnomalyEngine


def _ts(offset_sec: int) -> str:
    base = datetime(2026, 3, 6, tzinfo=timezone.utc)
    return (base + timedelta(seconds=offset_sec)).isoformat()


def test_anomaly_threshold_alerts() -> None:
    engine = AnomalyEngine(
        {
            "dos_packets_per_sec_threshold": 5,
            "scan_ports_threshold": 3,
            "zscore_enabled": False,
            "anomaly_cooldown_sec": 0,
            "dns_unique_threshold": 10,
        }
    )

    event = {"timestamp": _ts(0), "src_ip": "10.0.0.1", "dst_ip": "10.0.0.2", "proto": "TCP"}
    features = {"packet_rate_dst": 12, "unique_dst_ports_src_window": 7}

    alerts, score = engine.detect(event, features)
    assert any(alert["rule_name"] == "DoS Rate Threshold" for alert in alerts)
    assert any(alert["rule_name"] == "Port Scan Threshold" for alert in alerts)
    assert score is None


def test_anomaly_dns_burst() -> None:
    engine = AnomalyEngine(
        {
            "dos_packets_per_sec_threshold": 999,
            "scan_ports_threshold": 999,
            "zscore_enabled": False,
            "scan_window_sec": 20,
            "anomaly_cooldown_sec": 0,
            "dns_unique_threshold": 10,
        }
    )

    seen_dns_alert = False
    for i in range(35):
        event = {
            "timestamp": _ts(i),
            "src_ip": "192.168.1.50",
            "dst_ip": "8.8.8.8",
            "proto": "UDP",
            "dns_qname": f"{i}.domain.test",
        }
        features = {"packet_rate_dst": 1, "unique_dst_ports_src_window": 1}
        alerts, _ = engine.detect(event, features)
        if any(alert["rule_name"] == "DNS Burst / DGA-like Activity" for alert in alerts):
            seen_dns_alert = True
            break

    assert seen_dns_alert


def test_anomaly_ssh_bruteforce_threshold() -> None:
    engine = AnomalyEngine(
        {
            "dos_packets_per_sec_threshold": 999,
            "scan_ports_threshold": 999,
            "scan_window_sec": 12,
            "ssh_bruteforce_threshold": 5,
            "ssh_bruteforce_window_sec": 10,
            "zscore_enabled": False,
            "anomaly_cooldown_sec": 0,
            "dns_unique_threshold": 999,
        }
    )

    seen_alert = False
    for i in range(6):
        event = {
            "timestamp": _ts(i),
            "src_ip": "10.77.0.20",
            "dst_ip": "10.77.0.30",
            "proto": "TCP",
            "dst_port": 22,
            "tcp_flags": "S",
        }
        alerts, _ = engine.detect(event, {"packet_rate_dst": 1, "unique_dst_ports_src_window": 1})
        if any(alert["rule_name"] == "SSH Brute Force Threshold" for alert in alerts):
            seen_alert = True
            break

    assert seen_alert


def test_anomaly_rdp_bruteforce_threshold() -> None:
    engine = AnomalyEngine(
        {
            "dos_packets_per_sec_threshold": 999,
            "scan_ports_threshold": 999,
            "scan_window_sec": 12,
            "rdp_bruteforce_threshold": 5,
            "rdp_bruteforce_window_sec": 10,
            "zscore_enabled": False,
            "anomaly_cooldown_sec": 0,
            "dns_unique_threshold": 999,
        }
    )

    seen_alert = False
    for i in range(6):
        event = {
            "timestamp": _ts(i),
            "src_ip": "10.77.0.20",
            "dst_ip": "10.77.0.30",
            "proto": "TCP",
            "dst_port": 3389,
            "tcp_flags": "S",
        }
        alerts, _ = engine.detect(event, {"packet_rate_dst": 1, "unique_dst_ports_src_window": 1})
        if any(alert["rule_name"] == "RDP Brute Force Threshold" for alert in alerts):
            seen_alert = True
            break

    assert seen_alert


def test_anomaly_http_login_bruteforce_threshold() -> None:
    engine = AnomalyEngine(
        {
            "dos_packets_per_sec_threshold": 999,
            "scan_ports_threshold": 999,
            "http_login_threshold": 3,
            "http_login_window_sec": 20,
            "zscore_enabled": False,
            "anomaly_cooldown_sec": 0,
            "dns_unique_threshold": 999,
        }
    )

    payload = b"POST /login HTTP/1.1\r\nHost: app.internal\r\n\r\nusername=alice&password=bad"
    seen_alert = False
    for i in range(4):
        event = {
            "timestamp": _ts(i),
            "src_ip": "10.77.0.20",
            "dst_ip": "10.77.0.30",
            "proto": "TCP",
            "dst_port": 8080,
            "http_method": "POST",
            "http_uri": "/login",
            "payload": payload,
        }
        alerts, _ = engine.detect(event, {"packet_rate_dst": 1, "unique_dst_ports_src_window": 1})
        if any(alert["rule_name"] == "HTTP Login Brute Force Threshold" for alert in alerts):
            seen_alert = True
            break

    assert seen_alert
