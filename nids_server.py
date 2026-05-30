from __future__ import annotations

import datetime as dt
import hashlib
import io
import ipaddress
import os
import re
import socket
import subprocess
import tarfile
import threading
import time
import zipfile
from collections import Counter, defaultdict, deque
from typing import Any

from flask import Flask, jsonify, request, send_from_directory

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
MAX_UPLOAD_BYTES = 700 * 1024 * 1024

DOMAIN_PROFILES: dict[str, dict[str, Any]] = {
    "universal": {
        "label": "Universal",
        "sensitive_ports": [21, 22, 23, 25, 53, 80, 110, 139, 143, 443, 445, 3389, 5432, 5900],
        "dos_syn_weight": 6.0,
        "dos_conn_weight": 2.0,
        "dos_timewait_weight": 0.22,
        "portscan_port_weight": 6.0,
        "portscan_host_weight": 0.9,
        "unauthorized_weight": 14.0,
    },
    "evcs": {
        "label": "EVCS",
        "sensitive_ports": [80, 443, 1883, 8883, 502, 8080, 8443],
        "dos_syn_weight": 6.5,
        "dos_conn_weight": 2.2,
        "dos_timewait_weight": 0.24,
        "portscan_port_weight": 6.2,
        "portscan_host_weight": 0.9,
        "unauthorized_weight": 14.0,
    },
    "iot": {
        "label": "IoT",
        "sensitive_ports": [22, 23, 80, 443, 1883, 8883, 5683, 1900],
        "dos_syn_weight": 6.8,
        "dos_conn_weight": 2.3,
        "dos_timewait_weight": 0.25,
        "portscan_port_weight": 6.8,
        "portscan_host_weight": 1.0,
        "unauthorized_weight": 15.0,
    },
    "healthcare": {
        "label": "Healthcare",
        "sensitive_ports": [104, 11112, 2575, 443, 445, 3389, 5432],
        "dos_syn_weight": 6.1,
        "dos_conn_weight": 2.1,
        "dos_timewait_weight": 0.23,
        "portscan_port_weight": 6.3,
        "portscan_host_weight": 0.95,
        "unauthorized_weight": 16.0,
    },
    "enterprise": {
        "label": "Enterprise",
        "sensitive_ports": [22, 80, 135, 139, 389, 443, 445, 3389, 5985, 5986],
        "dos_syn_weight": 6.0,
        "dos_conn_weight": 2.0,
        "dos_timewait_weight": 0.22,
        "portscan_port_weight": 6.0,
        "portscan_host_weight": 0.9,
        "unauthorized_weight": 14.5,
    },
    "industrial": {
        "label": "Industrial",
        "sensitive_ports": [502, 102, 20000, 44818, 1911, 9600, 80, 443],
        "dos_syn_weight": 6.7,
        "dos_conn_weight": 2.4,
        "dos_timewait_weight": 0.25,
        "portscan_port_weight": 7.0,
        "portscan_host_weight": 1.05,
        "unauthorized_weight": 16.0,
    },
}

SUSPICIOUS_EXTENSIONS = {
    ".exe",
    ".dll",
    ".msi",
    ".scr",
    ".bat",
    ".cmd",
    ".ps1",
    ".vbs",
    ".js",
    ".jar",
    ".apk",
    ".iso",
}

SCRIPT_EXTENSIONS = {".py", ".ps1", ".vbs", ".js", ".bat", ".cmd", ".sh"}
MACRO_EXTENSIONS = {".docm", ".xlsm", ".pptm"}
NESTED_ARCHIVE_EXTENSIONS = {".zip", ".rar", ".7z", ".tar", ".gz", ".tgz", ".bz2"}
TEXT_EXTENSIONS = {
    ".txt",
    ".log",
    ".csv",
    ".json",
    ".xml",
    ".yaml",
    ".yml",
    ".md",
    ".ini",
    ".conf",
    ".py",
    ".js",
    ".ps1",
    ".sql",
}

FILENAME_INDICATORS = [
    "payload",
    "backdoor",
    "keylog",
    "mimikatz",
    "meterpreter",
    "ransom",
    "shell",
    "credential",
    "stealer",
    "inject",
]

CONTENT_PATTERNS = {
    "command_injection": re.compile(r"(?:cmd\.exe|powershell\s+-|/bin/sh|wget\s+http|curl\s+http)", re.I),
    "sql_injection": re.compile(r"(?:union\s+select|or\s+1=1|drop\s+table|information_schema)", re.I),
    "credential_theft": re.compile(r"(?:password\s*=|token\s*=|api[_-]?key|private\s+key)", re.I),
    "remote_control": re.compile(r"(?:reverse\s+shell|nc\s+-e|socket\.|subprocess\.Popen)", re.I),
}

TCP_RE = re.compile(r"^\s*TCP\s+(\S+)\s+(\S+)\s+(\S+)\s+(\d+)\s*$", re.I)
ARP_RE = re.compile(r"^\s*(\d+\.\d+\.\d+\.\d+)\s+([0-9a-fA-F-]{17})\s+(\w+)\s*$")

app = Flask(__name__, static_folder=BASE_DIR, static_url_path="")

state_lock = threading.Lock()
scan_state: dict[str, Any] = {
    "running": False,
    "started_at": None,
    "last_snapshot": None,
    "last_file_scan": None,
    "profile": "universal",
}
event_log: deque[dict[str, Any]] = deque(maxlen=120)
recent_event_signatures: dict[str, float] = {}
snapshot_history: deque[dict[str, Any]] = deque(maxlen=120)


def utc_now() -> str:
    return dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")


def run_cmd(command: list[str], timeout: int = 8) -> str:
    try:
        completed = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
            encoding="utf-8",
            errors="ignore",
        )
        return completed.stdout or ""
    except Exception:
        return ""


def clip_text(value: str, limit: int = 180) -> str:
    text = value.strip().replace("\n", " ")
    if len(text) <= limit:
        return text
    return text[: limit - 3] + "..."


def score_status(score: int) -> str:
    if score >= 70:
        return "alert"
    if score >= 35:
        return "monitor"
    return "normal"


def finding_severity(value: int, low: int, medium: int) -> str:
    if value >= medium:
        return "high"
    if value >= low:
        return "medium"
    return "low"


def profile_options() -> list[dict[str, str]]:
    return [{"key": key, "label": value["label"]} for key, value in DOMAIN_PROFILES.items()]


def get_profile(profile_key: str | None) -> tuple[str, dict[str, Any]]:
    key = (profile_key or "universal").lower()
    if key not in DOMAIN_PROFILES:
        key = "universal"
    return key, DOMAIN_PROFILES[key]


def record_event(event_type: str, severity: str, summary: str) -> None:
    now = time.time()
    signature = f"{event_type}|{summary}"

    with state_lock:
        previous = recent_event_signatures.get(signature)
        if previous is not None and (now - previous) < 8:
            return

        recent_event_signatures[signature] = now
        event_log.appendleft(
            {
                "time": utc_now(),
                "type": event_type,
                "severity": severity,
                "summary": clip_text(summary),
            }
        )


def append_snapshot_history(snapshot: dict[str, Any]) -> None:
    counters = snapshot.get("counters", {})
    history_item = {
        "timestamp": snapshot.get("timestamp"),
        "profile_key": snapshot.get("profile_key"),
        "dos_score": int(counters.get("dos_score", 0)),
        "mitm_score": int(counters.get("mitm_score", 0)),
        "port_scan_score": int(counters.get("port_scan_score", 0)),
        "unauthorized_score": int(counters.get("unauthorized_score", 0)),
        "suspicious_events": int(counters.get("suspicious_events", 0)),
    }

    with state_lock:
        snapshot_history.append(history_item)


def split_endpoint(endpoint: str) -> tuple[str, int | None]:
    token = endpoint.strip()
    if token in {"*:*", "*", "0.0.0.0:0"}:
        return "*", None

    if token.startswith("[") and "]:" in token:
        host, _, port_token = token[1:].partition("]:")
        return host, int(port_token) if port_token.isdigit() else None

    if ":" in token:
        host, port_token = token.rsplit(":", 1)
        return host.strip("[]"), int(port_token) if port_token.isdigit() else None

    return token.strip("[]"), None


def is_internal_host(host: str) -> bool:
    token = host.strip().lower()
    if token in {"*", "0.0.0.0", "::", "127.0.0.1", "::1", "localhost"}:
        return True

    try:
        ip_obj = ipaddress.ip_address(token)
    except ValueError:
        return False

    return (
        ip_obj.is_private
        or ip_obj.is_loopback
        or ip_obj.is_link_local
        or ip_obj.is_multicast
        or ip_obj.is_reserved
    )


def scan_text_signatures(raw_bytes: bytes) -> Counter:
    text = raw_bytes.decode("utf-8", errors="ignore")
    hits: Counter = Counter()
    for name, pattern in CONTENT_PATTERNS.items():
        if pattern.search(text):
            hits[name] += 1
    return hits


def extension_of(path_name: str) -> str:
    return os.path.splitext(path_name.lower())[1]


def scan_zip(name: str, data: bytes) -> dict[str, Any]:
    metrics: dict[str, Any] = {
        "archive_name": name,
        "archive_type": "zip",
        "total_files": 0,
        "corrupted_files": 0,
        "suspicious_files": 0,
        "password_protected": 0,
        "nested_archives": 0,
        "executable_files": 0,
        "script_files": 0,
        "macro_files": 0,
        "filename_indicator_hits": 0,
        "content_indicator_hits": 0,
    }

    suspicious_names: set[str] = set()
    suspicious_paths: set[str] = set()
    signature_hits: Counter = Counter()
    corrupted_members: list[str] = []

    with zipfile.ZipFile(io.BytesIO(data)) as archive:
        members = [entry for entry in archive.infolist() if not entry.is_dir()]
        metrics["total_files"] = len(members)

        for member in members:
            entry_name = member.filename
            lower_name = entry_name.lower()
            ext = extension_of(lower_name)

            if member.flag_bits & 0x1:
                metrics["password_protected"] += 1
                suspicious_paths.add(entry_name)

            if ext in NESTED_ARCHIVE_EXTENSIONS:
                metrics["nested_archives"] += 1

            if ext in SUSPICIOUS_EXTENSIONS:
                metrics["executable_files"] += 1
                suspicious_paths.add(entry_name)

            if ext in SCRIPT_EXTENSIONS:
                metrics["script_files"] += 1

            if ext in MACRO_EXTENSIONS:
                metrics["macro_files"] += 1
                suspicious_paths.add(entry_name)

            if any(keyword in lower_name for keyword in FILENAME_INDICATORS):
                metrics["filename_indicator_hits"] += 1
                suspicious_names.add(entry_name)
                suspicious_paths.add(entry_name)

            if ext in TEXT_EXTENSIONS and member.file_size <= 500_000 and not (member.flag_bits & 0x1):
                try:
                    with archive.open(member, "r") as handle:
                        sample = handle.read(250_000)
                        signature_hits.update(scan_text_signatures(sample))
                        while handle.read(262_144):
                            pass
                except Exception:
                    corrupted_members.append(entry_name)
            else:
                if not (member.flag_bits & 0x1):
                    try:
                        with archive.open(member, "r") as handle:
                            while handle.read(262_144):
                                pass
                    except Exception:
                        corrupted_members.append(entry_name)

    metrics["content_indicator_hits"] = int(sum(signature_hits.values()))
    metrics["corrupted_files"] = len(set(corrupted_members))
    metrics["suspicious_files"] = len(suspicious_paths | suspicious_names)
    metrics["signature_breakdown"] = dict(signature_hits)
    return metrics


def scan_tar(name: str, data: bytes) -> dict[str, Any]:
    metrics: dict[str, Any] = {
        "archive_name": name,
        "archive_type": "tar",
        "total_files": 0,
        "corrupted_files": 0,
        "suspicious_files": 0,
        "password_protected": 0,
        "nested_archives": 0,
        "executable_files": 0,
        "script_files": 0,
        "macro_files": 0,
        "filename_indicator_hits": 0,
        "content_indicator_hits": 0,
    }

    suspicious_paths: set[str] = set()
    signature_hits: Counter = Counter()
    corrupted_members: list[str] = []

    with tarfile.open(fileobj=io.BytesIO(data), mode="r:*") as archive:
        members = [member for member in archive.getmembers() if member.isfile()]
        metrics["total_files"] = len(members)

        for member in members:
            entry_name = member.name
            lower_name = entry_name.lower()
            ext = extension_of(lower_name)

            if ext in NESTED_ARCHIVE_EXTENSIONS:
                metrics["nested_archives"] += 1

            if ext in SUSPICIOUS_EXTENSIONS:
                metrics["executable_files"] += 1
                suspicious_paths.add(entry_name)

            if ext in SCRIPT_EXTENSIONS:
                metrics["script_files"] += 1

            if ext in MACRO_EXTENSIONS:
                metrics["macro_files"] += 1
                suspicious_paths.add(entry_name)

            if any(keyword in lower_name for keyword in FILENAME_INDICATORS):
                metrics["filename_indicator_hits"] += 1
                suspicious_paths.add(entry_name)

            try:
                extracted = archive.extractfile(member)
                if extracted is None:
                    continue

                if ext in TEXT_EXTENSIONS and member.size <= 500_000:
                    sample = extracted.read(250_000)
                    signature_hits.update(scan_text_signatures(sample))

                while extracted.read(262_144):
                    pass
            except Exception:
                corrupted_members.append(entry_name)

    metrics["content_indicator_hits"] = int(sum(signature_hits.values()))
    metrics["corrupted_files"] = len(set(corrupted_members))
    metrics["suspicious_files"] = len(suspicious_paths)
    metrics["signature_breakdown"] = dict(signature_hits)
    return metrics


def scan_generic_file(name: str, data: bytes) -> dict[str, Any]:
    ext = extension_of(name)
    file_type = ext.lstrip(".") if ext else "unknown"

    metrics: dict[str, Any] = {
        "archive_name": name,
        "archive_type": file_type,
        "total_files": 1,
        "corrupted_files": 0,
        "suspicious_files": 0,
        "password_protected": 0,
        "nested_archives": 0,
        "executable_files": 0,
        "script_files": 0,
        "macro_files": 0,
        "filename_indicator_hits": 0,
        "content_indicator_hits": 0,
    }

    lower_name = name.lower()
    suspicious_paths: set[str] = set()
    signature_hits: Counter = Counter()

    if ext in SUSPICIOUS_EXTENSIONS:
        metrics["executable_files"] += 1
        suspicious_paths.add(name)

    if ext in SCRIPT_EXTENSIONS:
        metrics["script_files"] += 1

    if ext in MACRO_EXTENSIONS:
        metrics["macro_files"] += 1
        suspicious_paths.add(name)

    if any(keyword in lower_name for keyword in FILENAME_INDICATORS):
        metrics["filename_indicator_hits"] += 1
        suspicious_paths.add(name)

    if ext in TEXT_EXTENSIONS and len(data) <= 2_000_000:
        signature_hits.update(scan_text_signatures(data[:500_000]))

    corrupted = False
    if ext == ".pdf" and not data.startswith(b"%PDF"):
        corrupted = True
    elif ext == ".png" and not data.startswith(b"\x89PNG\r\n\x1a\n"):
        corrupted = True
    elif ext in {".jpg", ".jpeg"} and not data.startswith(b"\xff\xd8"):
        corrupted = True
    elif ext == ".gif" and not (data.startswith(b"GIF87a") or data.startswith(b"GIF89a")):
        corrupted = True
    elif ext in {".docx", ".xlsx", ".pptx"}:
        try:
            with zipfile.ZipFile(io.BytesIO(data)) as office_zip:
                if office_zip.testzip() is not None:
                    corrupted = True
        except Exception:
            corrupted = True

    if corrupted:
        metrics["corrupted_files"] = 1
        suspicious_paths.add(name)

    metrics["content_indicator_hits"] = int(sum(signature_hits.values()))
    if metrics["content_indicator_hits"] > 0:
        suspicious_paths.add(name)

    metrics["suspicious_files"] = 1 if suspicious_paths else 0
    metrics["signature_breakdown"] = dict(signature_hits)
    return metrics


def build_file_response(name: str, data: bytes) -> dict[str, Any]:
    if name.lower().endswith(".zip"):
        metrics = scan_zip(name, data)
    elif name.lower().endswith((".tar", ".tar.gz", ".tgz", ".gz")):
        metrics = scan_tar(name, data)
    else:
        metrics = scan_generic_file(name, data)

    base_score = 0
    base_score += metrics["corrupted_files"] * 22
    base_score += metrics["password_protected"] * 14
    base_score += metrics["nested_archives"] * 4
    base_score += metrics["executable_files"] * 3
    base_score += metrics["macro_files"] * 8
    base_score += metrics["filename_indicator_hits"] * 7
    base_score += metrics["content_indicator_hits"] * 9

    risk_score = min(100, int(base_score))
    verdict = "clean"
    if risk_score >= 70:
        verdict = "high-risk"
    elif risk_score >= 35:
        verdict = "monitor"

    findings = [
        {"name": "Input Type", "value": metrics["archive_type"], "severity": "low"},
        {"name": "Files Scanned", "value": metrics["total_files"], "severity": "low"},
        {
            "name": "Corrupted Files",
            "value": metrics["corrupted_files"],
            "severity": finding_severity(metrics["corrupted_files"], 1, 3),
        },
        {
            "name": "Suspicious Files",
            "value": metrics["suspicious_files"],
            "severity": finding_severity(metrics["suspicious_files"], 1, 5),
        },
        {
            "name": "Password Protected",
            "value": metrics["password_protected"],
            "severity": finding_severity(metrics["password_protected"], 1, 2),
        },
        {
            "name": "Nested Archives",
            "value": metrics["nested_archives"],
            "severity": finding_severity(metrics["nested_archives"], 2, 5),
        },
        {
            "name": "Executable Payload Candidates",
            "value": metrics["executable_files"],
            "severity": finding_severity(metrics["executable_files"], 1, 4),
        },
        {
            "name": "Script Files",
            "value": metrics["script_files"],
            "severity": finding_severity(metrics["script_files"], 3, 8),
        },
        {
            "name": "Content Signature Hits",
            "value": metrics["content_indicator_hits"],
            "severity": finding_severity(metrics["content_indicator_hits"], 1, 3),
        },
        {
            "name": "SHA256",
            "value": hashlib.sha256(data).hexdigest()[:20] + "...",
            "severity": "low",
        },
    ]

    attack_matrix_fragment = {
        "malware_payload": {
            "score": min(100, metrics["executable_files"] * 10 + metrics["content_indicator_hits"] * 14),
            "status": score_status(min(100, metrics["executable_files"] * 10 + metrics["content_indicator_hits"] * 14)),
            "summary": "File payload and script indicators from dropped file.",
        },
        "data_tampering": {
            "score": min(100, metrics["corrupted_files"] * 35 + metrics["password_protected"] * 12),
            "status": score_status(min(100, metrics["corrupted_files"] * 35 + metrics["password_protected"] * 12)),
            "summary": "Corruption and tampering integrity indicators from dropped file.",
        },
    }

    return {
        "file_name": metrics["archive_name"],
        "file_type": metrics["archive_type"],
        "archive_name": metrics["archive_name"],
        "archive_type": metrics["archive_type"],
        "total_files": metrics["total_files"],
        "corrupted_files": metrics["corrupted_files"],
        "suspicious_files": metrics["suspicious_files"],
        "risk_score": risk_score,
        "verdict": verdict,
        "findings": findings,
        "signature_breakdown": metrics["signature_breakdown"],
        "attack_matrix_fragment": attack_matrix_fragment,
    }


def collect_arp_indicators() -> dict[str, Any]:
    output = run_cmd(["arp", "-a"], timeout=6)
    ip_to_mac: dict[str, set[str]] = defaultdict(set)
    mac_to_ip: dict[str, set[str]] = defaultdict(set)

    for line in output.splitlines():
        match = ARP_RE.match(line)
        if not match:
            continue
        ip_addr = match.group(1)
        mac_addr = match.group(2).lower()
        ip_to_mac[ip_addr].add(mac_addr)
        mac_to_ip[mac_addr].add(ip_addr)

    duplicate_ip_count = sum(1 for macs in ip_to_mac.values() if len(macs) > 1)
    broad_mac_reuse = sum(1 for ips in mac_to_ip.values() if len(ips) >= 8)

    score = min(100, duplicate_ip_count * 80 + max(0, broad_mac_reuse - 1) * 10)
    return {
        "score": int(score),
        "duplicate_ip_count": duplicate_ip_count,
        "broad_mac_reuse": broad_mac_reuse,
    }


def build_network_snapshot(running: bool, profile_key: str) -> dict[str, Any]:
    profile_key, profile_cfg = get_profile(profile_key)
    sensitive_ports = set(int(port) for port in profile_cfg.get("sensitive_ports", []))

    state_counts: Counter = Counter()
    remote_connection_counts: Counter = Counter()
    remote_port_sets: dict[str, set[int]] = defaultdict(set)

    active_connections = 0
    unauthorized_attempts = 0

    output = run_cmd(["netstat", "-ano", "-p", "tcp"], timeout=8)
    for line in output.splitlines():
        match = TCP_RE.match(line)
        if not match:
            continue

        local_raw, remote_raw, state, _pid = match.groups()
        state_upper = state.upper()
        state_counts[state_upper] += 1

        _local_host, local_port = split_endpoint(local_raw)
        remote_host, _remote_port = split_endpoint(remote_raw)

        if state_upper != "LISTENING":
            active_connections += 1

        if remote_host != "*" and not is_internal_host(remote_host):
            remote_connection_counts[remote_host] += 1
            if local_port is not None:
                remote_port_sets[remote_host].add(local_port)

            if local_port in sensitive_ports and state_upper in {"SYN_RECEIVED", "ESTABLISHED", "TIME_WAIT", "CLOSE_WAIT"}:
                unauthorized_attempts += 1

    unique_external_ips = len(remote_connection_counts)
    top_remote = "-"
    max_conn_per_ip = 0

    if remote_connection_counts:
        top_remote, max_conn_per_ip = remote_connection_counts.most_common(1)[0]

    max_ports_per_ip = 0
    if remote_port_sets:
        max_ports_per_ip = max(len(ports) for ports in remote_port_sets.values())

    syn_pressure = state_counts.get("SYN_SENT", 0) + state_counts.get("SYN_RECEIVED", 0)
    dos_score = min(
        100,
        int(
            syn_pressure * float(profile_cfg["dos_syn_weight"])
            + max_conn_per_ip * float(profile_cfg["dos_conn_weight"])
            + state_counts.get("TIME_WAIT", 0) * float(profile_cfg["dos_timewait_weight"])
        ),
    )
    port_scan_score = min(
        100,
        int(
            max_ports_per_ip * float(profile_cfg["portscan_port_weight"])
            + unique_external_ips * float(profile_cfg["portscan_host_weight"])
        ),
    )

    arp_data = collect_arp_indicators()
    mitm_score = int(arp_data["score"])

    unauthorized_score = min(100, int(unauthorized_attempts * float(profile_cfg["unauthorized_weight"])))

    with state_lock:
        last_file_scan = scan_state.get("last_file_scan")

    malware_score = 0
    tamper_score = 0
    malware_summary = "No file scan yet. Drop any file to evaluate payload risk."
    tamper_summary = "No file scan yet. Drop any file to evaluate corruption/tampering risk."

    if last_file_scan:
        malware_fragment = last_file_scan.get("attack_matrix_fragment", {}).get("malware_payload", {})
        tamper_fragment = last_file_scan.get("attack_matrix_fragment", {}).get("data_tampering", {})
        malware_score = int(malware_fragment.get("score", 0))
        tamper_score = int(tamper_fragment.get("score", 0))
        malware_summary = "Derived from last dropped file scan."
        tamper_summary = "Derived from last dropped file scan."

    attack_matrix = {
        "dos_ddos": {
            "score": dos_score,
            "status": score_status(dos_score),
            "summary": f"SYN pressure={syn_pressure}, top remote connections={max_conn_per_ip}",
        },
        "mitm_arp": {
            "score": mitm_score,
            "status": score_status(mitm_score),
            "summary": f"ARP duplicate IP mappings={arp_data['duplicate_ip_count']}",
        },
        "port_scan": {
            "score": port_scan_score,
            "status": score_status(port_scan_score),
            "summary": f"Max ports touched by one remote IP={max_ports_per_ip}",
        },
        "unauthorized_access": {
            "score": unauthorized_score,
            "status": score_status(unauthorized_score),
            "summary": f"Sensitive port access attempts={unauthorized_attempts}",
        },
        "malware_payload": {
            "score": malware_score,
            "status": score_status(malware_score),
            "summary": malware_summary,
        },
        "data_tampering": {
            "score": tamper_score,
            "status": score_status(tamper_score),
            "summary": tamper_summary,
        },
    }

    suspicious_events = sum(1 for value in attack_matrix.values() if value["status"] in {"monitor", "alert"})

    if running:
        if attack_matrix["dos_ddos"]["status"] in {"monitor", "alert"}:
            record_event("DoS/DDoS", "high" if attack_matrix["dos_ddos"]["status"] == "alert" else "medium", attack_matrix["dos_ddos"]["summary"])

        if attack_matrix["mitm_arp"]["status"] in {"monitor", "alert"}:
            record_event("MITM", "high" if attack_matrix["mitm_arp"]["status"] == "alert" else "medium", attack_matrix["mitm_arp"]["summary"])

        if attack_matrix["port_scan"]["status"] in {"monitor", "alert"}:
            record_event("Port Scan", "high" if attack_matrix["port_scan"]["status"] == "alert" else "medium", attack_matrix["port_scan"]["summary"])

        if attack_matrix["unauthorized_access"]["status"] in {"monitor", "alert"}:
            record_event(
                "Unauthorized Access",
                "high" if attack_matrix["unauthorized_access"]["status"] == "alert" else "medium",
                attack_matrix["unauthorized_access"]["summary"],
            )

    with state_lock:
        current_events = list(event_log)

    snapshot = {
        "timestamp": utc_now(),
        "running": running,
        "profile_key": profile_key,
        "profile_label": profile_cfg["label"],
        "top_remote": top_remote,
        "counters": {
            "active_connections": active_connections,
            "unique_external_ips": unique_external_ips,
            "unauthorized_attempts": unauthorized_attempts,
            "unauthorized_score": unauthorized_score,
            "suspicious_events": suspicious_events,
            "dos_score": dos_score,
            "mitm_score": mitm_score,
            "port_scan_score": port_scan_score,
        },
        "attack_matrix": attack_matrix,
        "events": current_events,
    }
    return snapshot


@app.route("/")
def index() -> Any:
    return send_from_directory(BASE_DIR, "nids_page.html")


@app.route("/api/health", methods=["GET"])
def health() -> Any:
    with state_lock:
        running = bool(scan_state["running"])
        profile_key = str(scan_state["profile"])
    _, profile_cfg = get_profile(profile_key)
    return jsonify(
        {
            "ok": True,
            "running": running,
            "time": utc_now(),
            "profile": profile_key,
            "profile_label": profile_cfg["label"],
            "history_points": len(snapshot_history),
        }
    )


@app.route("/api/config/profile", methods=["GET", "POST"])
def config_profile() -> Any:
    if request.method == "GET":
        with state_lock:
            active = str(scan_state["profile"])
        active, profile_cfg = get_profile(active)
        return jsonify(
            {
                "active_profile": active,
                "active_profile_label": profile_cfg["label"],
                "available_profiles": profile_options(),
            }
        )

    payload = request.get_json(silent=True) or {}
    profile_key = str(payload.get("profile", "")).lower()
    if profile_key not in DOMAIN_PROFILES:
        return jsonify(
            {
                "error": "Invalid profile.",
                "supported_profiles": [item["key"] for item in profile_options()],
            }
        ), 400

    with state_lock:
        scan_state["profile"] = profile_key

    record_event("System", "low", f"Detection profile changed to {DOMAIN_PROFILES[profile_key]['label']}")
    return jsonify(
        {
            "ok": True,
            "active_profile": profile_key,
            "active_profile_label": DOMAIN_PROFILES[profile_key]["label"],
            "available_profiles": profile_options(),
        }
    )


@app.route("/api/scan/file-drop", methods=["POST"])
def file_drop_scan() -> Any:
    uploaded = request.files.get("archive") or request.files.get("file")
    if uploaded is None:
        return jsonify({"error": "No file uploaded. Use field name 'archive' or 'file'."}), 400

    raw = uploaded.read()
    if not raw:
        return jsonify({"error": "Uploaded file is empty."}), 400

    if len(raw) > MAX_UPLOAD_BYTES:
        return jsonify({"error": "File too large. Keep file under 700 MB."}), 413

    try:
        result = build_file_response(uploaded.filename or "uploaded.zip", raw)
    except (zipfile.BadZipFile, tarfile.ReadError, ValueError) as exc:
        return jsonify({"error": str(exc)}), 400
    except Exception as exc:
        return jsonify({"error": f"Scan failed: {exc}"}), 500

    with state_lock:
        scan_state["last_file_scan"] = result
        active_profile = str(scan_state["profile"])

    profile_key, profile_cfg = get_profile(active_profile)
    result["profile_key"] = profile_key
    result["profile_label"] = profile_cfg["label"]

    if result["risk_score"] >= 70:
        record_event("File Scan", "high", f"High-risk file detected: {uploaded.filename}")
    elif result["risk_score"] >= 35:
        record_event("File Scan", "medium", f"File requires monitoring: {uploaded.filename}")
    else:
        record_event("File Scan", "low", f"File scan clean: {uploaded.filename}")

    return jsonify(result)


@app.route("/api/scan/network/start", methods=["POST"])
def start_network_scan() -> Any:
    with state_lock:
        scan_state["running"] = True
        scan_state["started_at"] = utc_now()
        active_profile = str(scan_state["profile"])

    _, profile_cfg = get_profile(active_profile)
    record_event("System", "low", f"Live network scan started ({profile_cfg['label']} profile)")
    return jsonify(
        {
            "ok": True,
            "running": True,
            "started_at": scan_state["started_at"],
            "profile": active_profile,
            "profile_label": profile_cfg["label"],
        }
    )


@app.route("/api/scan/network/stop", methods=["POST"])
def stop_network_scan() -> Any:
    with state_lock:
        scan_state["running"] = False

    record_event("System", "low", "Live network scan stopped")
    return jsonify({"ok": True, "running": False})


@app.route("/api/scan/network/snapshot", methods=["GET"])
def network_snapshot() -> Any:
    with state_lock:
        running = bool(scan_state["running"])
        active_profile = str(scan_state["profile"])
        last_snapshot = scan_state.get("last_snapshot")

    if running:
        snapshot = build_network_snapshot(True, active_profile)
        with state_lock:
            scan_state["last_snapshot"] = snapshot
        append_snapshot_history(snapshot)
    else:
        should_rebuild = not last_snapshot or last_snapshot.get("profile_key") != active_profile
        if should_rebuild:
            snapshot = build_network_snapshot(False, active_profile)
            with state_lock:
                scan_state["last_snapshot"] = snapshot
            if len(snapshot_history) == 0:
                append_snapshot_history(snapshot)
        else:
            snapshot = dict(last_snapshot)
            snapshot["running"] = False

    return jsonify(snapshot)


@app.route("/api/scan/network/history", methods=["GET"])
def network_history() -> Any:
    with state_lock:
        active_profile = str(scan_state["profile"])
        history = list(snapshot_history)
    _, profile_cfg = get_profile(active_profile)
    return jsonify(
        {
            "profile_key": active_profile,
            "profile_label": profile_cfg["label"],
            "history": history,
        }
    )


@app.route("/api/report/latest", methods=["GET"])
def latest_report() -> Any:
    with state_lock:
        report = {
            "generated_at": utc_now(),
            "agent": socket.gethostname(),
            "running": bool(scan_state["running"]),
            "started_at": scan_state["started_at"],
            "active_profile": scan_state["profile"],
            "active_profile_label": get_profile(str(scan_state["profile"]))[1]["label"],
            "latest_snapshot": scan_state["last_snapshot"],
            "last_file_scan": scan_state["last_file_scan"],
            "recent_events": list(event_log)[:60],
            "trend_history": list(snapshot_history),
        }
    return jsonify(report)


@app.route("/<path:asset_path>")
def static_assets(asset_path: str) -> Any:
    if asset_path.startswith("api/"):
        return jsonify({"error": "Not found"}), 404

    target = os.path.join(BASE_DIR, asset_path)
    if os.path.isfile(target):
        return send_from_directory(BASE_DIR, asset_path)

    return jsonify({"error": "Not found"}), 404


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=8788, debug=False)

