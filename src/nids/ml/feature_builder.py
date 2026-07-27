from __future__ import annotations

import pandas as pd

from .featureset import FEATURE_COLUMNS


def _num(frame: pd.DataFrame, name: str) -> pd.Series:
    """Numeric feature column, aligned to ``frame``; missing/malformed -> 0.0."""
    series = frame[name] if name in frame.columns else pd.Series(0.0, index=frame.index)
    return pd.to_numeric(series, errors="coerce").fillna(0.0)


def _text(frame: pd.DataFrame, name: str) -> pd.Series:
    """String feature column, aligned to ``frame``; missing -> empty string."""
    series = frame[name] if name in frame.columns else pd.Series("", index=frame.index)
    return series.astype(str)


def build_training_frame(df: pd.DataFrame) -> tuple[pd.DataFrame, pd.Series, list[str]]:
    """Transform flow rows into feature matrix + label vector."""
    if df.empty:
        return pd.DataFrame(), pd.Series(dtype=str), FEATURE_COLUMNS

    frame = df.copy()

    frame["packet_len"] = _num(frame, "packet_len")
    frame["payload_len"] = frame["packet_len"]
    frame["src_port"] = _num(frame, "src_port")
    frame["dst_port"] = _num(frame, "dst_port")

    proto = _text(frame, "proto").str.upper()
    frame["is_tcp"] = (proto == "TCP").astype(float)
    frame["is_udp"] = (proto == "UDP").astype(float)
    frame["is_icmp"] = (proto == "ICMP").astype(float)

    flags = _text(frame, "tcp_flags")
    frame["tcp_syn"] = flags.str.contains("S", regex=False).astype(float)
    frame["tcp_ack"] = flags.str.contains("A", regex=False).astype(float)

    frame["packet_rate_dst"] = _num(frame, "packet_rate_dst")
    frame["unique_dst_ports_src_window"] = _num(frame, "unique_dst_ports_src_window")
    frame["unique_dst_hosts_src_window"] = _num(frame, "unique_dst_hosts_src_window")

    frame["has_dns_qname"] = 0.0
    frame["has_http_host"] = 0.0
    frame["has_tls_sni"] = 0.0

    X = frame[FEATURE_COLUMNS].copy()
    y = _text(frame, "label")

    return X, y, FEATURE_COLUMNS
