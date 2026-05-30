from __future__ import annotations

from pathlib import Path

from src.NIDS.detect.ml_unsupervised import UnsupervisedMLEngine


def _normal_event(index: int) -> tuple[dict[str, object], dict[str, object]]:
    event = {
        "packet_len": 96 + (index % 4),
        "payload_len": 48 + (index % 3),
        "src_port": 40000 + index,
        "dst_port": 443,
    }
    features = {
        "is_tcp": 1,
        "is_udp": 0,
        "is_icmp": 0,
        "tcp_syn": 0,
        "tcp_ack": 1,
        "packet_rate_dst": 2.0,
        "unique_dst_ports_src_window": 1.0,
        "unique_dst_hosts_src_window": 1.0,
        "has_dns_qname": 0,
        "has_http_host": 1,
        "has_tls_sni": 1,
    }
    return event, features


def test_unsupervised_engine_uses_isolation_forest_and_autoencoder() -> None:
    engine = UnsupervisedMLEngine(
        warmup_samples=20,
        contamination=0.05,
        alert_threshold=0.6,
        component_threshold=0.5,
        autoencoder_enabled=True,
        autoencoder_hidden_size=6,
        autoencoder_max_iter=300,
        random_state=42,
    )

    for index in range(20):
        event, features = _normal_event(index)
        alerts, prediction = engine.detect(event, features)
        assert alerts == []
        assert prediction["unsupervised_label"] is None

    alerts, prediction = engine.detect(
        {
            "packet_len": 1800,
            "payload_len": 1600,
            "src_port": 65000,
            "dst_port": 1,
        },
        {
            "is_tcp": 0,
            "is_udp": 1,
            "is_icmp": 0,
            "tcp_syn": 0,
            "tcp_ack": 0,
            "packet_rate_dst": 950.0,
            "unique_dst_ports_src_window": 80.0,
            "unique_dst_hosts_src_window": 42.0,
            "has_dns_qname": 1,
            "has_http_host": 0,
            "has_tls_sni": 0,
        },
    )

    assert prediction["unsupervised_label"] == "attack"
    assert prediction["unsupervised_attack_type"] == "anomaly"
    assert prediction["unsupervised_isolation_score"] is not None
    assert prediction["unsupervised_autoencoder_score"] is not None
    assert prediction["unsupervised_score"] is not None
    assert set(prediction["unsupervised_components"]).issuperset({"isolation_forest", "autoencoder"})
    assert len(prediction["unsupervised_active_components"]) >= 1
    assert prediction["unsupervised_model_count"] == 2

    assert len(alerts) == 1
    assert alerts[0]["rule_name"] == "Hybrid Unsupervised Anomaly Score"
    assert set(alerts[0]["extra"]["unsupervised_components"]).issuperset({"isolation_forest", "autoencoder"})


def test_unsupervised_engine_persists_and_reloads_baseline(tmp_path: Path) -> None:
    snapshot_path = tmp_path / "unsupervised_baseline.pkl"

    engine = UnsupervisedMLEngine(
        warmup_samples=20,
        contamination=0.05,
        alert_threshold=0.6,
        component_threshold=0.5,
        autoencoder_enabled=True,
        autoencoder_hidden_size=6,
        autoencoder_max_iter=300,
        snapshot_path=snapshot_path,
        random_state=42,
    )

    for index in range(20):
        event, features = _normal_event(index)
        engine.detect(event, features)

    saved_path = engine.save_snapshot()
    assert saved_path == snapshot_path.resolve()
    assert snapshot_path.exists()

    reloaded = UnsupervisedMLEngine(
        warmup_samples=20,
        contamination=0.05,
        alert_threshold=0.6,
        component_threshold=0.5,
        autoencoder_enabled=True,
        autoencoder_hidden_size=6,
        autoencoder_max_iter=300,
        snapshot_path=snapshot_path,
        random_state=42,
    )

    alerts, prediction = reloaded.detect(
        {
            "packet_len": 1700,
            "payload_len": 1500,
            "src_port": 65001,
            "dst_port": 2,
        },
        {
            "is_tcp": 0,
            "is_udp": 1,
            "is_icmp": 0,
            "tcp_syn": 0,
            "tcp_ack": 0,
            "packet_rate_dst": 900.0,
            "unique_dst_ports_src_window": 75.0,
            "unique_dst_hosts_src_window": 40.0,
            "has_dns_qname": 1,
            "has_http_host": 0,
            "has_tls_sni": 0,
        },
    )

    assert prediction["unsupervised_label"] == "attack"
    assert prediction["unsupervised_baseline_path"] == str(snapshot_path.resolve())
    assert prediction["unsupervised_isolation_score"] is not None
    assert len(alerts) == 1
