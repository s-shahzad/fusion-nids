from __future__ import annotations

import argparse
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

import numpy as np
import pandas as pd
from sklearn.datasets import fetch_kddcup99

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from src.NIDS.storage.sqlite_store import SQLiteStore


SERVICE_PORT_MAP = {
    "IRC": 194,
    "X11": 6000,
    "Z39_50": 210,
    "domain": 53,
    "domain_u": 53,
    "eco_i": 7,
    "ecr_i": 7,
    "finger": 79,
    "ftp": 21,
    "ftp_data": 20,
    "gopher": 70,
    "hostnames": 101,
    "http": 80,
    "http_2784": 2784,
    "imap4": 143,
    "iso_tsap": 102,
    "klogin": 543,
    "kshell": 544,
    "ldap": 389,
    "link": 245,
    "login": 513,
    "mtp": 57,
    "name": 42,
    "netbios_dgm": 138,
    "netbios_ns": 137,
    "netbios_ssn": 139,
    "nnsp": 433,
    "nntp": 119,
    "ntp_u": 123,
    "other": 0,
    "pm_dump": 7,
    "pop_2": 109,
    "pop_3": 110,
    "printer": 515,
    "private": 0,
    "red_i": 0,
    "remote_job": 512,
    "rje": 5,
    "shell": 514,
    "smtp": 25,
    "sql_net": 66,
    "ssh": 22,
    "sunrpc": 111,
    "supdup": 95,
    "systat": 11,
    "telnet": 23,
    "tim_i": 0,
    "time": 37,
    "urh_i": 0,
    "urp_i": 0,
    "uucp": 540,
    "uucp_path": 117,
    "vmnet": 175,
    "whois": 43,
}

FLAG_TO_TCP_FLAGS = {
    "OTH": "",
    "REJ": "A",
    "RSTO": "A",
    "RSTOS0": "A",
    "RSTR": "A",
    "S0": "S",
    "S1": "SA",
    "S2": "SA",
    "S3": "SA",
    "SF": "SA",
    "SH": "S",
}

ATTACK_GROUPS = {
    "normal": "normal",
    "back": "dos",
    "land": "dos",
    "neptune": "dos",
    "pod": "dos",
    "smurf": "dos",
    "teardrop": "dos",
    "mailbomb": "dos",
    "apache2": "dos",
    "processtable": "dos",
    "udpstorm": "dos",
    "ipsweep": "probe",
    "nmap": "probe",
    "portsweep": "probe",
    "satan": "probe",
    "mscan": "probe",
    "saint": "probe",
    "ftp_write": "r2l",
    "guess_passwd": "r2l",
    "imap": "r2l",
    "multihop": "r2l",
    "named": "r2l",
    "phf": "r2l",
    "sendmail": "r2l",
    "snmpgetattack": "r2l",
    "snmpguess": "r2l",
    "spy": "r2l",
    "warezclient": "r2l",
    "warezmaster": "r2l",
    "xlock": "r2l",
    "xsnoop": "r2l",
    "httptunnel": "r2l",
    "buffer_overflow": "u2r",
    "loadmodule": "u2r",
    "perl": "u2r",
    "ps": "u2r",
    "rootkit": "u2r",
    "sqlattack": "u2r",
    "xterm": "u2r",
}

FLOW_INSERT_SQL = """
    INSERT INTO flows(
        timestamp, sensor_id, dataset_source,
        src_ip, dst_ip, src_port, dst_port, proto,
        packet_len, tcp_flags, packet_count,
        packet_rate_dst, unique_dst_ports_src_window, unique_dst_hosts_src_window,
        label, attack_type, is_labeled,
        anomaly_score,
        predicted_label, predicted_attack_type, prediction_score,
        payload_preview
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
"""


def _decode(value: object) -> str:
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="ignore")
    return str(value)


def _load_kddcup99(sample_limit: int) -> tuple[pd.DataFrame, pd.Series]:
    dataset = fetch_kddcup99(percent10=True, shuffle=True, random_state=42, as_frame=True)

    if dataset.frame is not None:
        frame = dataset.frame.copy()
        if "target" in frame.columns:
            target = frame.pop("target")
        else:
            target = pd.Series(dataset.target, name="target")
    else:
        frame = pd.DataFrame(dataset.data, columns=list(dataset.feature_names))
        target = pd.Series(dataset.target, name="target")

    for column in ("protocol_type", "service", "flag"):
        frame[column] = frame[column].map(_decode)

    labels = target.map(_decode).str.rstrip(".")

    if sample_limit > 0:
        frame = frame.iloc[:sample_limit].reset_index(drop=True)
        labels = labels.iloc[:sample_limit].reset_index(drop=True)

    return frame, labels


def _build_bootstrap_flows(frame: pd.DataFrame, labels: pd.Series) -> pd.DataFrame:
    count = len(frame)
    base_time = datetime(2026, 1, 1, tzinfo=timezone.utc)
    offsets = [base_time + timedelta(seconds=index) for index in range(count)]
    packet_len = (
        pd.to_numeric(frame["src_bytes"], errors="coerce").fillna(0)
        + pd.to_numeric(frame["dst_bytes"], errors="coerce").fillna(0)
    ).clip(lower=0)

    bootstrap = pd.DataFrame(
        {
            "timestamp": [value.isoformat(timespec="seconds") for value in offsets],
            "sensor_id": "bootstrap-kddcup99",
            "dataset_source": "kddcup99-percent10",
            "src_ip": [f"10.0.{index // 250 % 250}.{index % 250}" for index in range(count)],
            "dst_ip": [f"172.16.{index // 400 % 250}.{index % 250}" for index in range(count)],
            "src_port": 40000 + (np.arange(count) % 1000),
            "dst_port": frame["service"].map(lambda value: SERVICE_PORT_MAP.get(str(value), 0)).astype(int),
            "proto": frame["protocol_type"].str.upper(),
            "packet_len": packet_len.astype(int),
            "tcp_flags": frame["flag"].map(lambda value: FLAG_TO_TCP_FLAGS.get(str(value), "")).astype(str),
            "packet_count": pd.to_numeric(frame["count"], errors="coerce").fillna(1).clip(lower=1).astype(int),
            "packet_rate_dst": pd.to_numeric(frame["srv_count"], errors="coerce").fillna(0.0),
            "unique_dst_ports_src_window": pd.to_numeric(frame["srv_count"], errors="coerce").fillna(0.0),
            "unique_dst_hosts_src_window": pd.to_numeric(frame["dst_host_count"], errors="coerce").fillna(0.0),
            "label": labels.map(lambda value: ATTACK_GROUPS.get(str(value), "attack")).astype(str),
            "attack_type": labels.astype(str),
            "is_labeled": 1,
            "anomaly_score": labels.ne("normal").astype(float),
            "predicted_label": None,
            "predicted_attack_type": None,
            "prediction_score": None,
            "payload_preview": "",
        }
    )

    label_counts = bootstrap["label"].value_counts()
    keep_labels = label_counts[label_counts >= 2].index
    return bootstrap[bootstrap["label"].isin(keep_labels)].reset_index(drop=True)


def _write_db(flows: pd.DataFrame, out_db: Path) -> None:
    out_db.parent.mkdir(parents=True, exist_ok=True)
    if out_db.exists():
        out_db.unlink()

    store = SQLiteStore(out_db)
    try:
        rows = [
            (
                row.timestamp,
                row.sensor_id,
                row.dataset_source,
                row.src_ip,
                row.dst_ip,
                int(row.src_port),
                int(row.dst_port),
                row.proto,
                int(row.packet_len),
                row.tcp_flags,
                int(row.packet_count),
                float(row.packet_rate_dst),
                float(row.unique_dst_ports_src_window),
                float(row.unique_dst_hosts_src_window),
                row.label,
                row.attack_type,
                int(row.is_labeled),
                float(row.anomaly_score),
                row.predicted_label,
                row.predicted_attack_type,
                row.prediction_score,
                row.payload_preview,
            )
            for row in flows.itertuples(index=False)
        ]
        store.conn.executemany(FLOW_INSERT_SQL, rows)
        store.conn.commit()
    finally:
        store.close()


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Bootstrap a labeled NIDS training database from KDDCup99.")
    parser.add_argument(
        "--out-db",
        default="output/nids_training.db",
        help="Path to output SQLite database containing labeled flows.",
    )
    parser.add_argument(
        "--sample-limit",
        type=int,
        default=25000,
        help="Maximum number of KDDCup99 rows to import (0 means all fetched rows).",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    out_db = Path(args.out_db).resolve()

    frame, labels = _load_kddcup99(sample_limit=max(0, int(args.sample_limit)))
    flows = _build_bootstrap_flows(frame, labels)
    if flows.empty:
        raise SystemExit("No labeled flows available after bootstrap filtering.")

    _write_db(flows, out_db)

    print(f"bootstrap-db: wrote {len(flows)} labeled flows to {out_db}")
    print("bootstrap-db: label distribution")
    for label, count in flows["label"].value_counts().items():
        print(f"  {label}: {int(count)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
