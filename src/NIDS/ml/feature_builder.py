from __future__ import annotations

from typing import Any

import pandas as pd

from .featureset import FEATURE_COLUMNS


def _num(series: Any) -> pd.Series | float:
    if series is None:
        return 0.0
    if not isinstance(series, pd.Series):
        series = pd.Series(series)
    return pd.to_numeric(series, errors="coerce").fillna(0.0)


def build_training_frame(df: pd.DataFrame) -> tuple[pd.DataFrame, pd.Series, list[str]]:
    """Transform flow rows into feature matrix + label vector."""
    if df.empty:
        return pd.DataFrame(), pd.Series(dtype=str), FEATURE_COLUMNS

    frame = df.copy()

    frame["packet_len"] = _num(frame.get("packet_len"))
    frame["payload_len"] = frame["packet_len"]
    frame["src_port"] = _num(frame.get("src_port"))
    frame["dst_port"] = _num(frame.get("dst_port"))

    proto = frame.get("proto", pd.Series(dtype=str)).astype(str).str.upper()
    frame["is_tcp"] = (proto == "TCP").astype(float)
    frame["is_udp"] = (proto == "UDP").astype(float)
    frame["is_icmp"] = (proto == "ICMP").astype(float)

    flags = frame.get("tcp_flags", pd.Series(dtype=str)).astype(str)
    frame["tcp_syn"] = flags.str.contains("S", regex=False).astype(float)
    frame["tcp_ack"] = flags.str.contains("A", regex=False).astype(float)

    frame["packet_rate_dst"] = _num(frame.get("packet_rate_dst"))
    frame["unique_dst_ports_src_window"] = _num(frame.get("unique_dst_ports_src_window"))
    frame["unique_dst_hosts_src_window"] = _num(frame.get("unique_dst_hosts_src_window"))

    frame["has_dns_qname"] = 0.0
    frame["has_http_host"] = 0.0
    frame["has_tls_sni"] = 0.0

    X = frame[FEATURE_COLUMNS].copy()
    y = frame.get("label", pd.Series(dtype=str)).astype(str)

    return X, y, FEATURE_COLUMNS
