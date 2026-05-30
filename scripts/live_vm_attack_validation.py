from __future__ import annotations

import argparse
import json
import posixpath
import shlex
import sqlite3
import sys
import threading
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import paramiko


REPO_ROOT = Path(__file__).resolve().parents[1]
SRC_ROOT = REPO_ROOT / "src"
if str(SRC_ROOT) not in sys.path:
    sys.path.insert(0, str(SRC_ROOT))

from NIDS.utils.secrets import get_secret  # noqa: E402


LAB_VM_USER_ENV = "LAB_VM_USER"
LAB_VM_PASS_ENV = "LAB_VM_PASS"
LAB_VM_USER_ALIASES = ("NIDS_LAB_USERNAME",)
LAB_VM_PASS_ALIASES = ("NIDS_LAB_PASSWORD",)


def lab_vm_username_default() -> str | None:
    return get_secret(LAB_VM_USER_ENV, aliases=LAB_VM_USER_ALIASES)


def lab_vm_password_default() -> str | None:
    return get_secret(LAB_VM_PASS_ENV, aliases=LAB_VM_PASS_ALIASES)


def require_lab_vm_credentials(parser: argparse.ArgumentParser, args: argparse.Namespace) -> None:
    if not str(getattr(args, "username", "") or "").strip():
        parser.error(f"Missing lab VM username. Set {LAB_VM_USER_ENV} or pass --username.")
    if not str(getattr(args, "password", "") or "").strip():
        parser.error(f"Missing lab VM password. Set {LAB_VM_PASS_ENV} or pass --password.")


def _now_stamp() -> str:
    return datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")


def _run_command(
    ssh: paramiko.SSHClient,
    command: str,
    *,
    sudo_password: str | None = None,
    timeout: int = 120,
    check: bool = True,
) -> tuple[str, str, int]:
    stdin, stdout, stderr = ssh.exec_command(
        command,
        timeout=timeout,
        get_pty=bool(sudo_password),
    )
    if sudo_password:
        stdin.write(sudo_password + "\n")
        stdin.flush()

    exit_status = stdout.channel.recv_exit_status()
    out = stdout.read().decode("utf-8", errors="ignore")
    err = stderr.read().decode("utf-8", errors="ignore")
    if check and exit_status != 0:
        raise RuntimeError(
            f"Remote command failed ({exit_status}): {command}\nSTDOUT:\n{out}\nSTDERR:\n{err}"
        )
    return out, err, exit_status


def _quote_remote(path: str) -> str:
    return shlex.quote(path)


def _connect(host: str, port: int, username: str, password: str) -> paramiko.SSHClient:
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    client.connect(
        hostname=host,
        port=port,
        username=username,
        password=password,
        timeout=20,
        banner_timeout=20,
        auth_timeout=20,
    )
    return client


def _upload_file(
    ssh: paramiko.SSHClient,
    local_path: Path,
    remote_path: str,
    *,
    sudo_password: str | None = None,
) -> None:
    remote_parent = posixpath.dirname(remote_path)
    _run_command(ssh, f"mkdir -p {_quote_remote(remote_parent)}", check=True)
    sftp = ssh.open_sftp()
    try:
        sftp.put(str(local_path), remote_path)
        return
    except PermissionError:
        if not sudo_password:
            raise
        tmp_remote = f"/tmp/{local_path.name}"
        sftp.put(str(local_path), tmp_remote)
    finally:
        sftp.close()

    _run_command(
        ssh,
        f"sudo -S cp {_quote_remote(tmp_remote)} {_quote_remote(remote_path)} && "
        f"sudo -S chown nidslab:nidslab {_quote_remote(remote_path)}",
        sudo_password=sudo_password,
        check=True,
    )


def _download_file(ssh: paramiko.SSHClient, remote_path: str, local_path: Path) -> None:
    local_path.parent.mkdir(parents=True, exist_ok=True)
    sftp = ssh.open_sftp()
    try:
        sftp.get(remote_path, str(local_path))
    finally:
        sftp.close()


def _remote_python(script: str) -> str:
    return "python3 - <<'PY'\n" + script + "\nPY"


def _trigger_dns_burst(target_ssh: paramiko.SSHClient, sensor_ip: str, count: int) -> None:
    return _trigger_dns_burst_with_delay(target_ssh, sensor_ip, count=count, delay_sec=0.08)


def _trigger_dns_burst_with_delay(
    target_ssh: paramiko.SSHClient,
    sensor_ip: str,
    *,
    count: int,
    delay_sec: float,
) -> None:
    script = f"""
import socket
import struct
import time

def encode_name(name: str) -> bytes:
    return b"".join(bytes([len(part)]) + part.encode("ascii") for part in name.split(".")) + b"\\x00"

server = ({sensor_ip!r}, 53)
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
for index in range({count}):
    qname = f"{{index:03d}}.dga-test.example"
    txid = (4096 + index) & 0xFFFF
    header = struct.pack("!HHHHHH", txid, 0x0100, 1, 0, 0, 0)
    question = encode_name(qname) + struct.pack("!HH", 1, 1)
    sock.sendto(header + question, server)
    time.sleep(max(0.0, float({delay_sec})))
sock.close()
print("dns_queries_sent", {count})
"""
    _run_command(target_ssh, _remote_python(script), timeout=120)


def _trigger_dns_flood(
    target_ssh: paramiko.SSHClient,
    sensor_ip: str,
    *,
    rate_per_sec: float,
    duration_sec: float,
    qname: str,
) -> None:
    script = f"""
import socket
import struct
import time

def encode_name(name: str) -> bytes:
    return b"".join(bytes([len(part)]) + part.encode("ascii") for part in name.split(".")) + b"\\x00"

server = ({sensor_ip!r}, 53)
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
rate_per_sec = max(1.0, float({rate_per_sec}))
duration_limit = max(0.1, float({duration_sec}))
interval = 1.0 / rate_per_sec
end_time = time.perf_counter() + duration_limit
next_send = time.perf_counter()
sent = 0
qname = {qname!r}
while time.perf_counter() < end_time:
    txid = (4096 + sent) & 0xFFFF
    header = struct.pack("!HHHHHH", txid, 0x0100, 1, 0, 0, 0)
    question = encode_name(qname) + struct.pack("!HH", 1, 1)
    sock.sendto(header + question, server)
    sent += 1
    next_send += interval
    sleep_for = next_send - time.perf_counter()
    if sleep_for > 0:
        time.sleep(sleep_for)
sock.close()
print("dns_flood_packets_sent", sent)
print("dns_flood_duration_sec", duration_limit)
print("dns_flood_send_rate", round(sent / duration_limit, 2))
"""
    _run_command(target_ssh, _remote_python(script), timeout=120)


def _trigger_tcp_bruteforce(
    target_ssh: paramiko.SSHClient,
    sensor_ip: str,
    *,
    port: int,
    attempts: int,
    label: str,
    attempt_delay_sec: float = 0.2,
) -> None:
    script = f"""
import socket
import time

for _ in range({attempts}):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(0.6)
    try:
        sock.connect(({sensor_ip!r}, {port}))
    except Exception:
        pass
    finally:
        sock.close()
    time.sleep(max(0.0, float({attempt_delay_sec})))
print("{label}_attempts_sent", {attempts})
"""
    _run_command(target_ssh, _remote_python(script), timeout=120)


def _trigger_tcp_scan(
    target_ssh: paramiko.SSHClient,
    sensor_ip: str,
    *,
    start_port: int,
    count: int,
    delay_sec: float,
) -> None:
    script = f"""
import socket
import time

start_port = int({start_port})
count = int({count})
delay_sec = float({delay_sec})

for port in range(start_port, start_port + count):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(0.35)
    try:
        sock.connect(({sensor_ip!r}, port))
    except Exception:
        pass
    finally:
        sock.close()
    if delay_sec > 0:
        time.sleep(delay_sec)
print("tcp_scan_ports_sent", count)
print("tcp_scan_start_port", start_port)
"""
    _run_command(target_ssh, _remote_python(script), timeout=180)


def _trigger_udp_flood(
    target_ssh: paramiko.SSHClient,
    sensor_ip: str,
    *,
    port: int,
    packets: int,
    payload_bytes: int,
    rate_per_sec: float,
    duration_sec: float,
) -> None:
    script = f"""
import socket
import time

server = ({sensor_ip!r}, {port})
payload = b"U" * max(1, int({payload_bytes}))
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.settimeout(0.1)
start = time.perf_counter()
sent = 0
rate_per_sec = float({rate_per_sec})
duration_limit = float({duration_sec})
packet_limit = int({packets})

if rate_per_sec > 0 and duration_limit > 0:
    interval = 1.0 / rate_per_sec
    end_time = start + duration_limit
    next_send = start
    while time.perf_counter() < end_time:
        sock.sendto(payload, server)
        sent += 1
        next_send += interval
        sleep_for = next_send - time.perf_counter()
        if sleep_for > 0:
            time.sleep(sleep_for)
else:
    for _ in range(packet_limit):
        sock.sendto(payload, server)
        sent += 1

duration = max(time.perf_counter() - start, 1e-6)
sock.close()
print("udp_flood_packets_sent", sent)
print("udp_flood_duration_sec", round(duration, 6))
print("udp_flood_send_rate", round(sent / duration, 2))
"""
    _run_command(target_ssh, _remote_python(script), timeout=120)


def _start_http_login_server(
    sensor_ssh: paramiko.SSHClient,
    result_rel: str,
    *,
    port: int,
    sudo_password: str | None = None,
) -> int:
    _, _, existing_status = _run_command(
        sensor_ssh,
        f"ss -ltn | grep ':{port} '",
        timeout=30,
        check=False,
    )
    if existing_status == 0:
        return 0

    token = result_rel.replace("/", "_")
    server_log = posixpath.join("/tmp", f"{token}_http_login_server.log")
    pid_file = posixpath.join("/tmp", f"{token}_http_login_server.pid")
    marker = f"nids_http_helper_{port}"
    pkill_command = f"pkill -f {shlex.quote(marker)}"
    if port < 1024 and sudo_password:
        _run_command(sensor_ssh, f"sudo -S {pkill_command}", sudo_password=sudo_password, timeout=30, check=False)
    else:
        _run_command(sensor_ssh, pkill_command, timeout=30, check=False)
    script = (
        "import socket\n"
        f"MARKER = {marker!r}\n"
        "sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)\n"
        "sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)\n"
        f"sock.bind(('0.0.0.0', {port}))\n"
        "sock.listen(64)\n"
        "while True:\n"
        "    conn, _ = sock.accept()\n"
        "    try:\n"
        "        conn.settimeout(1.0)\n"
        "        data = b''\n"
        "        while b'\\r\\n\\r\\n' not in data and len(data) < 65535:\n"
        "            chunk = conn.recv(4096)\n"
        "            if not chunk:\n"
        "                break\n"
        "            data += chunk\n"
        "        header, _, body = data.partition(b'\\r\\n\\r\\n')\n"
        "        content_length = 0\n"
        "        for line in header.split(b'\\r\\n'):\n"
        "            if line.lower().startswith(b'content-length:'):\n"
        "                try:\n"
        "                    content_length = int(line.split(b':', 1)[1].strip() or b'0')\n"
        "                except Exception:\n"
        "                    content_length = 0\n"
        "                break\n"
        "        remaining = max(0, min(content_length - len(body), 65536))\n"
        "        while remaining > 0:\n"
        "            chunk = conn.recv(min(4096, remaining))\n"
        "            if not chunk:\n"
        "                break\n"
        "            remaining -= len(chunk)\n"
        "        conn.sendall(b'HTTP/1.1 200 OK\\r\\nContent-Length: 2\\r\\nConnection: close\\r\\n\\r\\nOK')\n"
        "    except Exception:\n"
        "        pass\n"
        "    finally:\n"
        "        conn.close()\n"
    )
    inner = (
        f"(nohup python3 -c {shlex.quote(script)} "
        f"> {_quote_remote(server_log)} 2>&1 < /dev/null & "
        f"echo $! > {_quote_remote(pid_file)})"
    )
    if port < 1024:
        if not sudo_password:
            raise RuntimeError(f"Binding HTTP helper on privileged port {port} requires sudo_password")
        _run_command(
            sensor_ssh,
            f"sudo -S bash -lc {shlex.quote(inner)}",
            sudo_password=sudo_password,
            timeout=120,
        )
    else:
        _run_command(sensor_ssh, f"bash -lc {shlex.quote(inner)}", timeout=120)
    pid_text, _, _ = _run_command(sensor_ssh, f"cat {_quote_remote(pid_file)}", timeout=30)
    pid = int(pid_text.strip())
    _, _, status = _run_command(
        sensor_ssh,
        f"sleep 1; ss -ltn | grep ':{port} '",
        timeout=30,
        check=False,
    )
    if status != 0:
        log_text, _, _ = _run_command(
            sensor_ssh,
            f"tail -n 20 {_quote_remote(server_log)}",
            timeout=30,
            check=False,
        )
        raise RuntimeError(f"HTTP helper server failed to bind on port {port}. Log:\n{log_text}")
    return pid


def _start_udp_sink(
    sensor_ssh: paramiko.SSHClient,
    result_rel: str,
    *,
    port: int,
    sudo_password: str | None = None,
) -> int:
    _, _, existing_status = _run_command(
        sensor_ssh,
        f"ss -lun | grep ':{port} '",
        timeout=30,
        check=False,
    )
    if existing_status == 0:
        return 0

    token = result_rel.replace("/", "_")
    server_log = posixpath.join("/tmp", f"{token}_udp_sink.log")
    pid_file = posixpath.join("/tmp", f"{token}_udp_sink.pid")
    script = (
        "import socket\n"
        "sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)\n"
        f"sock.bind(('0.0.0.0', {port}))\n"
        "while True:\n"
        "    sock.recvfrom(65535)\n"
    )
    inner = (
        f"(nohup python3 -c {shlex.quote(script)} "
        f"> {_quote_remote(server_log)} 2>&1 < /dev/null & "
        f"echo $! > {_quote_remote(pid_file)})"
    )
    if port < 1024:
        if not sudo_password:
            raise RuntimeError(f"Binding UDP sink on privileged port {port} requires sudo_password")
        _run_command(
            sensor_ssh,
            f"sudo -S bash -lc {shlex.quote(inner)}",
            sudo_password=sudo_password,
            timeout=120,
        )
    else:
        _run_command(sensor_ssh, f"bash -lc {shlex.quote(inner)}", timeout=120)
    pid_text, _, _ = _run_command(sensor_ssh, f"cat {_quote_remote(pid_file)}", timeout=30)
    pid = int(pid_text.strip())
    _, _, status = _run_command(
        sensor_ssh,
        f"sleep 1; ss -lun | grep ':{port} '",
        timeout=30,
        check=False,
    )
    if status != 0:
        log_text, _, _ = _run_command(
            sensor_ssh,
            f"tail -n 20 {_quote_remote(server_log)}",
            timeout=30,
            check=False,
        )
        raise RuntimeError(f"UDP sink failed to bind on port {port}. Log:\n{log_text}")
    return pid


def _start_tcp_sink(
    sensor_ssh: paramiko.SSHClient,
    result_rel: str,
    *,
    port: int,
    sudo_password: str | None = None,
) -> int:
    _, _, existing_status = _run_command(
        sensor_ssh,
        f"ss -ltn | grep ':{port} '",
        timeout=30,
        check=False,
    )
    if existing_status == 0:
        return 0

    token = result_rel.replace("/", "_")
    server_log = posixpath.join("/tmp", f"{token}_tcp_sink_{port}.log")
    pid_file = posixpath.join("/tmp", f"{token}_tcp_sink_{port}.pid")
    script = (
        "import socket\n"
        "sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)\n"
        "sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)\n"
        f"sock.bind(('0.0.0.0', {port}))\n"
        "sock.listen(64)\n"
        "while True:\n"
        "    conn, _ = sock.accept()\n"
        "    try:\n"
        "        conn.settimeout(0.2)\n"
        "        conn.recv(1024)\n"
        "    except Exception:\n"
        "        pass\n"
        "    finally:\n"
        "        conn.close()\n"
    )
    inner = (
        f"(nohup python3 -c {shlex.quote(script)} "
        f"> {_quote_remote(server_log)} 2>&1 < /dev/null & "
        f"echo $! > {_quote_remote(pid_file)})"
    )
    if port < 1024:
        if not sudo_password:
            raise RuntimeError(f"Binding TCP sink on privileged port {port} requires sudo_password")
        _run_command(
            sensor_ssh,
            f"sudo -S bash -lc {shlex.quote(inner)}",
            sudo_password=sudo_password,
            timeout=120,
        )
    else:
        _run_command(sensor_ssh, f"bash -lc {shlex.quote(inner)}", timeout=120)
    pid_text, _, _ = _run_command(sensor_ssh, f"cat {_quote_remote(pid_file)}", timeout=30)
    pid = int(pid_text.strip())
    _, _, status = _run_command(
        sensor_ssh,
        f"sleep 1; ss -ltn | grep ':{port} '",
        timeout=30,
        check=False,
    )
    if status != 0:
        log_text, _, _ = _run_command(
            sensor_ssh,
            f"tail -n 20 {_quote_remote(server_log)}",
            timeout=30,
            check=False,
        )
        raise RuntimeError(f"TCP sink failed to bind on port {port}. Log:\n{log_text}")
    return pid


def _trigger_http_login_bruteforce(
    target_ssh: paramiko.SSHClient,
    sensor_ip: str,
    *,
    port: int,
    attempts: int,
    uri: str,
    attempt_delay_sec: float = 0.65,
) -> None:
    script = f"""
import socket
import time

for index in range({attempts}):
    body = f"username=alice&password=bad{{index}}"
    request = (
        f"POST {uri} HTTP/1.1\\r\\n"
        f"Host: app.internal\\r\\n"
        f"Content-Type: application/x-www-form-urlencoded\\r\\n"
        f"Content-Length: {{len(body)}}\\r\\n\\r\\n"
        f"{{body}}"
    ).encode("utf-8")
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(1.5)
    try:
        sock.connect(({sensor_ip!r}, {port}))
        sock.sendall(request)
        try:
            sock.recv(512)
        except Exception:
            pass
    except Exception:
        pass
    finally:
        sock.close()
    time.sleep(max(0.0, float({attempt_delay_sec})))
print("http_login_attempts_sent", {attempts})
"""
    _run_command(target_ssh, _remote_python(script), timeout=180)


def _trigger_http_suspicious_keyword(
    target_ssh: paramiko.SSHClient,
    sensor_ip: str,
    *,
    port: int,
    requests: int,
    uri: str,
    request_delay_sec: float = 0.45,
) -> None:
    script = f"""
import socket
import time

for index in range({requests}):
    request = (
        f"GET {uri}?cmd.exe=whoami&tool=powershell&n={{index}} HTTP/1.1\\r\\n"
        f"Host: app.internal\\r\\n"
        f"User-Agent: nids-lab\\r\\n\\r\\n"
    ).encode("utf-8")
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(1.5)
    try:
        sock.connect(({sensor_ip!r}, {port}))
        sock.sendall(request)
        try:
            sock.recv(512)
        except Exception:
            pass
    except Exception:
        pass
    finally:
        sock.close()
    time.sleep(max(0.0, float({request_delay_sec})))
print("http_keyword_requests_sent", {requests})
"""
    _run_command(target_ssh, _remote_python(script), timeout=180)


def _build_attack_jobs(args: argparse.Namespace) -> list[dict[str, Any]]:
    jobs: list[dict[str, Any]] = []
    if args.dns_count > 0:
        jobs.append(
            {
                "name": "dns-burst",
                "label": "DNS Burst / DGA-like Activity",
                "kind": "dns_burst",
                "expected_rules": ["DNS Burst / DGA-like Activity"],
                "count": args.dns_count,
                "delay_sec": args.dns_delay_sec,
            }
        )
    if args.dns_flood_rate_per_sec > 0 and args.dns_flood_duration_sec > 0:
        jobs.append(
            {
                "name": "dns-flood",
                "label": "DoS / DNS Flood",
                "kind": "dns_flood",
                "expected_rules": ["DoS Rate Threshold"],
                "rate_per_sec": args.dns_flood_rate_per_sec,
                "duration_sec": args.dns_flood_duration_sec,
                "qname": args.dns_flood_qname,
            }
        )
    if args.scan_start_port > 0 and args.scan_port_count > 0:
        jobs.append(
            {
                "name": "tcp-scan",
                "label": "Port Scan",
                "kind": "tcp_scan",
                "expected_rules": ["Suspicious Port Scan", "Port Scan Threshold"],
                "start_port": args.scan_start_port,
                "count": args.scan_port_count,
                "delay_sec": args.scan_delay_sec,
            }
        )
    if args.udp_flood_packets > 0:
        jobs.append(
            {
                "name": "udp-flood",
                "label": "UDP Flood",
                "kind": "udp_flood",
                "expected_rules": ["DoS Rate Threshold"],
                "port": args.udp_flood_port,
                "packets": args.udp_flood_packets,
                "payload_bytes": args.udp_flood_payload_bytes,
                "rate_per_sec": args.udp_flood_rate_per_sec,
                "duration_sec": args.udp_flood_duration_sec,
            }
        )
    if args.ssh_attempts > 0:
        jobs.append(
            {
                "name": "ssh-bruteforce",
                "label": "SSH Brute Force",
                "kind": "tcp_bruteforce",
                "expected_rules": ["SSH Brute Force Threshold"],
                "port": 22,
                "attempts": args.ssh_attempts,
                "protocol_label": "ssh",
                "attempt_delay_sec": args.ssh_attempt_delay_sec,
            }
        )
    if args.rdp_attempts > 0:
        jobs.append(
            {
                "name": "rdp-bruteforce",
                "label": "RDP Brute Force",
                "kind": "tcp_bruteforce",
                "expected_rules": ["RDP Brute Force Threshold"],
                "port": 3389,
                "attempts": args.rdp_attempts,
                "protocol_label": "rdp",
                "attempt_delay_sec": args.rdp_attempt_delay_sec,
            }
        )
    if args.http_login_attempts > 0:
        jobs.append(
            {
                "name": "http-login-bruteforce",
                "label": "HTTP Login Brute Force",
                "kind": "http_login",
                "expected_rules": ["HTTP Login Brute Force Threshold"],
                "port": args.http_login_port,
                "attempts": args.http_login_attempts,
                "uri": args.http_login_uri,
                "attempt_delay_sec": args.http_login_attempt_delay_sec,
            }
        )
    if args.http_keyword_requests > 0:
        keyword_port = args.http_keyword_port if args.http_keyword_port > 0 else args.http_login_port
        jobs.append(
            {
                "name": "http-keyword",
                "label": "HTTP Suspicious Keyword",
                "kind": "http_keyword",
                "expected_rules": ["HTTP Suspicious Keyword"],
                "port": keyword_port,
                "requests": args.http_keyword_requests,
                "uri": args.http_keyword_uri,
                "request_delay_sec": args.http_keyword_request_delay_sec,
            }
        )
    return jobs


def _run_attack_job_on_client(
    target_ssh: paramiko.SSHClient,
    args: argparse.Namespace,
    job: dict[str, Any],
) -> None:
    kind = str(job["kind"])
    if kind == "dns_burst":
        _trigger_dns_burst_with_delay(
            target_ssh,
            args.sensor_ip,
            count=int(job["count"]),
            delay_sec=float(job["delay_sec"]),
        )
        return
    if kind == "dns_flood":
        _trigger_dns_flood(
            target_ssh,
            args.sensor_ip,
            rate_per_sec=float(job["rate_per_sec"]),
            duration_sec=float(job["duration_sec"]),
            qname=str(job["qname"]),
        )
        return
    if kind == "tcp_scan":
        _trigger_tcp_scan(
            target_ssh,
            args.sensor_ip,
            start_port=int(job["start_port"]),
            count=int(job["count"]),
            delay_sec=float(job["delay_sec"]),
        )
        return
    if kind == "udp_flood":
        _trigger_udp_flood(
            target_ssh,
            args.sensor_ip,
            port=int(job["port"]),
            packets=int(job["packets"]),
            payload_bytes=int(job["payload_bytes"]),
            rate_per_sec=float(job["rate_per_sec"]),
            duration_sec=float(job["duration_sec"]),
        )
        return
    if kind == "tcp_bruteforce":
        _trigger_tcp_bruteforce(
            target_ssh,
            args.sensor_ip,
            port=int(job["port"]),
            attempts=int(job["attempts"]),
            label=str(job["protocol_label"]),
            attempt_delay_sec=float(job["attempt_delay_sec"]),
        )
        return
    if kind == "http_login":
        _trigger_http_login_bruteforce(
            target_ssh,
            args.sensor_ip,
            port=int(job["port"]),
            attempts=int(job["attempts"]),
            uri=str(job["uri"]),
            attempt_delay_sec=float(job["attempt_delay_sec"]),
        )
        return
    if kind == "http_keyword":
        _trigger_http_suspicious_keyword(
            target_ssh,
            args.sensor_ip,
            port=int(job["port"]),
            requests=int(job["requests"]),
            uri=str(job["uri"]),
            request_delay_sec=float(job["request_delay_sec"]),
        )
        return
    raise RuntimeError(f"Unknown attack job kind: {kind}")


def _execute_attack_jobs(
    target_ssh: paramiko.SSHClient,
    args: argparse.Namespace,
    jobs: list[dict[str, Any]],
) -> None:
    if not jobs:
        return
    if not args.concurrent:
        for job in jobs:
            _run_attack_job_on_client(target_ssh, args, job)
        return

    def _priority(job: dict[str, Any]) -> tuple[int, str]:
        kind = str(job.get("kind", ""))
        # Start stateful application/service attempts before burstier traffic so
        # overlap runs preserve enough events for threshold-based detectors.
        rank_map = {
            "http_login": 0,
            "http_keyword": 1,
            "tcp_bruteforce": 2,
            "tcp_scan": 3,
            "dns_burst": 4,
            "dns_flood": 5,
            "udp_flood": 6,
        }
        return (rank_map.get(kind, 50), str(job.get("name", kind)))

    errors: list[tuple[str, str]] = []
    error_lock = threading.Lock()

    def _worker(job: dict[str, Any]) -> None:
        job_ssh = _connect(args.target_host, args.target_port, args.username, args.password)
        try:
            _run_attack_job_on_client(job_ssh, args, job)
        except Exception as exc:
            with error_lock:
                errors.append((str(job["name"]), str(exc)))
        finally:
            job_ssh.close()

    threads: list[threading.Thread] = []
    launch_jobs = sorted(jobs, key=_priority)

    for job in launch_jobs:
        thread = threading.Thread(target=_worker, args=(job,), daemon=True)
        thread.start()
        threads.append(thread)
        if args.concurrent_start_spacing_sec > 0:
            time.sleep(args.concurrent_start_spacing_sec)

    for thread in threads:
        thread.join()

    if errors:
        formatted = "\n".join(f"{name}: {message}" for name, message in errors)
        raise RuntimeError(f"One or more concurrent attack jobs failed:\n{formatted}")


def _start_runtime(
    sensor_ssh: paramiko.SSHClient,
    workspace: str,
    result_rel: str,
    *,
    config_relpath: str,
    sudo_password: str,
) -> int:
    result_abs = posixpath.join(workspace, result_rel)
    runtime_log = posixpath.join(result_abs, "runtime.log")
    pid_file = posixpath.join(result_abs, "nids.pid")
    inner = (
        f"mkdir -p {_quote_remote(result_abs)} && "
        f"cd {_quote_remote(workspace)} && "
        f"(nohup env PYTHONPATH={_quote_remote(workspace)} PYTHONUNBUFFERED=1 "
        f".venv/bin/python -u -m nids run "
        f"--interface enp0s3 "
        f"--rules rules/rules.yml "
        f"--config {shlex.quote(config_relpath)} "
        f"--output-dir {shlex.quote(result_rel)} "
        f"--sensor-id nids-ubuntu-sensor "
        f"--model models/model.pkl "
        f"--unsupervised "
        f"> {_quote_remote(runtime_log)} 2>&1 < /dev/null & "
        f"echo $! > {_quote_remote(pid_file)})"
    )
    _run_command(
        sensor_ssh,
        f"sudo -S bash -lc {shlex.quote(inner)}",
        sudo_password=sudo_password,
        timeout=120,
    )
    pid_text, _, _ = _run_command(sensor_ssh, f"cat {_quote_remote(pid_file)}", timeout=30)
    return int(pid_text.strip())


def _stop_runtime(
    sensor_ssh: paramiko.SSHClient,
    pid: int,
    *,
    sudo_password: str,
) -> None:
    _run_command(
        sensor_ssh,
        f"sudo -S kill -INT {pid}",
        sudo_password=sudo_password,
        timeout=30,
        check=False,
    )
    time.sleep(6)
    _, _, status = _run_command(
        sensor_ssh,
        f"ps -p {pid} >/dev/null 2>&1",
        timeout=30,
        check=False,
    )
    if status == 0:
        _run_command(
            sensor_ssh,
            f"sudo -S kill -TERM {pid}",
            sudo_password=sudo_password,
            timeout=30,
            check=False,
        )
        time.sleep(2)


def _stop_process(
    sensor_ssh: paramiko.SSHClient,
    pid: int,
    *,
    sudo_password: str | None = None,
) -> None:
    command = f"kill -TERM {pid}"
    if sudo_password:
        _run_command(
            sensor_ssh,
            f"sudo -S {command}",
            sudo_password=sudo_password,
            timeout=30,
            check=False,
        )
    else:
        _run_command(
            sensor_ssh,
            command,
            timeout=30,
            check=False,
        )
    time.sleep(1)


def _generate_reports(sensor_ssh: paramiko.SSHClient, workspace: str, result_rel: str) -> None:
    db_path = posixpath.join(result_rel, "nids.db")
    report_path = posixpath.join(result_rel, "serious_test_report.md")
    threshold_json = posixpath.join(result_rel, "threshold_tuning.json")
    threshold_md = posixpath.join(result_rel, "threshold_tuning.md")
    report_cmd = (
        f"cd {_quote_remote(workspace)} && "
        f"env PYTHONPATH={_quote_remote(workspace)} .venv/bin/python -m nids "
        f"report --from-db {shlex.quote(db_path)} --out {shlex.quote(report_path)}"
    )
    threshold_cmd = (
        f"cd {_quote_remote(workspace)} && "
        f"env PYTHONPATH={_quote_remote(workspace)} .venv/bin/python -m nids "
        f"threshold-report --from-db {shlex.quote(db_path)} "
        f"--out-json {shlex.quote(threshold_json)} --out-md {shlex.quote(threshold_md)} "
        f"--lookback-days 1"
    )
    _run_command(sensor_ssh, report_cmd, timeout=180)
    _run_command(sensor_ssh, threshold_cmd, timeout=180)


def _chown_result_dir(
    sensor_ssh: paramiko.SSHClient,
    workspace: str,
    result_rel: str,
    *,
    sudo_password: str,
) -> None:
    remote_result_dir = posixpath.join(workspace, result_rel)
    _run_command(
        sensor_ssh,
        f"sudo -S chown -R nidslab:nidslab {_quote_remote(remote_result_dir)}",
        sudo_password=sudo_password,
        timeout=120,
        check=False,
    )


def _collect_artifacts(
    sensor_ssh: paramiko.SSHClient,
    workspace: str,
    result_rel: str,
    local_result_dir: Path,
) -> None:
    remote_result_dir = posixpath.join(workspace, result_rel)
    for name in (
        "nids.db",
        "alerts.jsonl",
        "flows.jsonl",
        "runtime.log",
        "serious_test_report.md",
        "threshold_tuning.json",
        "threshold_tuning.md",
    ):
        try:
            _download_file(
                sensor_ssh,
                posixpath.join(remote_result_dir, name),
                local_result_dir / name,
            )
        except FileNotFoundError:
            continue


def _write_validation_summary(
    local_result_dir: Path,
    jobs: list[dict[str, Any]],
    *,
    concurrent: bool,
) -> tuple[Path, Path]:
    db_path = local_result_dir / "nids.db"
    if not db_path.exists():
        raise FileNotFoundError(f"Result DB not found at {db_path}")

    conn = sqlite3.connect(db_path)
    try:
        total_alerts = int(conn.execute("SELECT COUNT(*) FROM alerts").fetchone()[0])
        total_flows = int(conn.execute("SELECT COUNT(*) FROM flows").fetchone()[0])
        rule_counts = {
            str(rule_name): int(count)
            for rule_name, count in conn.execute(
                """
                SELECT COALESCE(rule_name, ''), COUNT(*)
                FROM alerts
                GROUP BY COALESCE(rule_name, '')
                """
            ).fetchall()
            if str(rule_name).strip()
        }
        engine_counts = {
            str(engine): int(count)
            for engine, count in conn.execute(
                """
                SELECT COALESCE(engine, ''), COUNT(*)
                FROM alerts
                GROUP BY COALESCE(engine, '')
                """
            ).fetchall()
            if str(engine).strip()
        }
    finally:
        conn.close()

    job_summaries: list[dict[str, Any]] = []
    for job in jobs:
        matched_rules = [
            {"rule_name": rule_name, "count": int(rule_counts.get(rule_name, 0))}
            for rule_name in job["expected_rules"]
            if int(rule_counts.get(rule_name, 0)) > 0
        ]
        job_summaries.append(
            {
                "attack_name": str(job["label"]),
                "job_name": str(job["name"]),
                "expected_rules": list(job["expected_rules"]),
                "matched_rules": matched_rules,
                "status": "pass" if matched_rules else "miss",
            }
        )

    summary = {
        "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "run_name": local_result_dir.name,
        "mode": "concurrent" if concurrent else "sequential",
        "total_flows": total_flows,
        "total_alerts": total_alerts,
        "rule_counts": rule_counts,
        "engine_counts": engine_counts,
        "jobs": job_summaries,
    }

    json_path = local_result_dir / "attack_validation_summary.json"
    md_path = local_result_dir / "attack_validation_summary.md"
    json_path.write_text(json.dumps(summary, indent=2), encoding="utf-8")

    lines = [
        "# Concurrent Attack Validation Summary",
        "",
        f"- Run: `{local_result_dir.name}`",
        f"- Mode: `{summary['mode']}`",
        f"- Total flows: `{total_flows}`",
        f"- Total alerts: `{total_alerts}`",
        "",
        "## Attack Results",
        "",
        "| Attack | Expected Rules | Detected Rules | Status |",
        "|---|---|---|---|",
    ]
    for item in job_summaries:
        expected_rules = ", ".join(f"`{rule}`" for rule in item["expected_rules"])
        detected_rules = ", ".join(
            f"`{entry['rule_name']}` ({entry['count']})" for entry in item["matched_rules"]
        ) or "none"
        lines.append(
            f"| {item['attack_name']} | {expected_rules} | {detected_rules} | `{item['status']}` |"
        )

    lines.extend(
        [
            "",
            "## Rule Counts",
            "",
            "| Rule | Count |",
            "|---|---:|",
        ]
    )
    for rule_name in sorted(rule_counts):
        lines.append(f"| `{rule_name}` | {rule_counts[rule_name]} |")

    lines.extend(
        [
            "",
            "## Engine Counts",
            "",
            "| Engine | Count |",
            "|---|---:|",
        ]
    )
    for engine_name in sorted(engine_counts):
        lines.append(f"| `{engine_name}` | {engine_counts[engine_name]} |")

    md_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return json_path, md_path


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Run live attack validation cases in the VM lab.")
    parser.add_argument("--sensor-host", default="127.0.0.1")
    parser.add_argument("--sensor-port", type=int, default=2223)
    parser.add_argument("--target-host", default="127.0.0.1")
    parser.add_argument("--target-port", type=int, default=2224)
    parser.add_argument("--username", default=lab_vm_username_default(), help="Lab VM username. Defaults to LAB_VM_USER.")
    parser.add_argument("--password", default=lab_vm_password_default(), help="Lab VM password. Defaults to LAB_VM_PASS.")
    parser.add_argument("--workspace", default="/opt/nids_workspace")
    parser.add_argument("--config-relpath", default="NIDS_TestLab/config/live_vm_profile.yml")
    parser.add_argument("--sensor-ip", default="10.77.0.30")
    parser.add_argument("--run-name", default=f"live-attack-validation-{_now_stamp()}")
    parser.add_argument("--dns-count", type=int, default=36)
    parser.add_argument("--dns-delay-sec", type=float, default=0.08)
    parser.add_argument("--dns-flood-rate-per-sec", type=float, default=0.0)
    parser.add_argument("--dns-flood-duration-sec", type=float, default=0.0)
    parser.add_argument("--dns-flood-qname", default="flood.test")
    parser.add_argument("--scan-start-port", type=int, default=0)
    parser.add_argument("--scan-port-count", type=int, default=0)
    parser.add_argument("--scan-delay-sec", type=float, default=0.02)
    parser.add_argument("--udp-flood-packets", type=int, default=0)
    parser.add_argument("--udp-flood-port", type=int, default=9999)
    parser.add_argument("--udp-flood-payload-bytes", type=int, default=256)
    parser.add_argument("--udp-flood-rate-per-sec", type=float, default=0.0)
    parser.add_argument("--udp-flood-duration-sec", type=float, default=0.0)
    parser.add_argument("--ssh-attempts", type=int, default=12)
    parser.add_argument("--ssh-attempt-delay-sec", type=float, default=0.2)
    parser.add_argument("--rdp-attempts", type=int, default=0)
    parser.add_argument("--rdp-attempt-delay-sec", type=float, default=0.2)
    parser.add_argument("--http-login-attempts", type=int, default=0)
    parser.add_argument("--http-login-port", type=int, default=8080)
    parser.add_argument("--http-login-uri", default="/login")
    parser.add_argument("--http-login-attempt-delay-sec", type=float, default=0.65)
    parser.add_argument("--http-keyword-requests", type=int, default=0)
    parser.add_argument("--http-keyword-port", type=int, default=0)
    parser.add_argument("--http-keyword-uri", default="/shell")
    parser.add_argument("--http-keyword-request-delay-sec", type=float, default=0.45)
    parser.add_argument("--concurrent", action="store_true", help="Run enabled attack primitives concurrently.")
    parser.add_argument("--concurrent-start-spacing-sec", type=float, default=0.15)
    parser.add_argument("--warmup-sec", type=float, default=5.0)
    parser.add_argument("--settle-sec", type=float, default=8.0)
    args = parser.parse_args(argv)
    require_lab_vm_credentials(parser, args)

    attack_jobs = _build_attack_jobs(args)

    result_rel = posixpath.join("NIDS_TestLab", "results", args.run_name)
    local_result_dir = REPO_ROOT / "NIDS_TestLab" / "results" / args.run_name
    local_result_dir.mkdir(parents=True, exist_ok=True)

    sensor = _connect(args.sensor_host, args.sensor_port, args.username, args.password)
    target = _connect(args.target_host, args.target_port, args.username, args.password)

    http_server_pids: list[int] = []
    udp_sink_pids: list[tuple[int, bool]] = []
    tcp_sink_pids: list[tuple[int, bool]] = []
    summary_md = local_result_dir / "attack_validation_summary.md"

    try:
        files_to_sync = [
            (
                REPO_ROOT / "src" / "NIDS" / "pipeline" / "parser.py",
                posixpath.join(args.workspace, "src", "NIDS", "pipeline", "parser.py"),
            ),
            (
                REPO_ROOT / "src" / "NIDS" / "pipeline" / "features.py",
                posixpath.join(args.workspace, "src", "NIDS", "pipeline", "features.py"),
            ),
            (
                REPO_ROOT / "src" / "NIDS" / "ingest" / "__init__.py",
                posixpath.join(args.workspace, "src", "NIDS", "ingest", "__init__.py"),
            ),
            (
                REPO_ROOT / "src" / "NIDS" / "ingest" / "live.py",
                posixpath.join(args.workspace, "src", "NIDS", "ingest", "live.py"),
            ),
            (
                REPO_ROOT / "src" / "NIDS" / "detect" / "anomaly.py",
                posixpath.join(args.workspace, "src", "NIDS", "detect", "anomaly.py"),
            ),
            (
                REPO_ROOT / "src" / "NIDS" / "detect" / "ml.py",
                posixpath.join(args.workspace, "src", "NIDS", "detect", "ml.py"),
            ),
            (
                REPO_ROOT / "src" / "NIDS" / "detect" / "ml_unsupervised.py",
                posixpath.join(args.workspace, "src", "NIDS", "detect", "ml_unsupervised.py"),
            ),
            (
                REPO_ROOT / "src" / "NIDS" / "runtime.py",
                posixpath.join(args.workspace, "src", "NIDS", "runtime.py"),
            ),
            (
                REPO_ROOT / "src" / "NIDS" / "config.py",
                posixpath.join(args.workspace, "src", "NIDS", "config.py"),
            ),
            (
                REPO_ROOT / "config" / "nids.yml",
                posixpath.join(args.workspace, "config", "nids.yml"),
            ),
            (
                REPO_ROOT / "rules" / "rules.yml",
                posixpath.join(args.workspace, "rules", "rules.yml"),
            ),
            (
                REPO_ROOT / Path(args.config_relpath),
                posixpath.join(args.workspace, args.config_relpath.replace("\\", "/")),
            ),
        ]
        for local_path, remote_path in files_to_sync:
            _upload_file(sensor, local_path, remote_path, sudo_password=args.password)

        http_ports: set[int] = set()
        if args.http_login_attempts > 0:
            http_ports.add(args.http_login_port)
        if args.http_keyword_requests > 0:
            http_ports.add(args.http_keyword_port if args.http_keyword_port > 0 else args.http_login_port)
        for http_port in sorted(http_ports):
            http_server_pid = _start_http_login_server(
                sensor,
                result_rel,
                port=http_port,
                sudo_password=args.password,
            )
            if http_server_pid not in {None, 0}:
                http_server_pids.append(http_server_pid)
            time.sleep(1)
        udp_ports: set[int] = set()
        if args.dns_count > 0 or (args.dns_flood_rate_per_sec > 0 and args.dns_flood_duration_sec > 0):
            udp_ports.add(53)
        if args.udp_flood_packets > 0:
            udp_ports.add(args.udp_flood_port)
        for udp_port in sorted(udp_ports):
            udp_sink_pid = _start_udp_sink(
                sensor,
                result_rel,
                port=udp_port,
                sudo_password=args.password,
            )
            if udp_sink_pid not in {None, 0}:
                udp_sink_pids.append((udp_sink_pid, udp_port < 1024))
            time.sleep(1)

        if args.rdp_attempts > 0:
            tcp_sink_pid = _start_tcp_sink(
                sensor,
                result_rel,
                port=3389,
                sudo_password=args.password,
            )
            if tcp_sink_pid not in {None, 0}:
                tcp_sink_pids.append((tcp_sink_pid, False))
            time.sleep(1)

        pid = _start_runtime(
            sensor,
            args.workspace,
            result_rel,
            config_relpath=args.config_relpath.replace("\\", "/"),
            sudo_password=args.password,
        )
        print(f"runtime_pid={pid}")
        time.sleep(args.warmup_sec)

        _execute_attack_jobs(target, args, attack_jobs)
        time.sleep(args.settle_sec)

        for http_server_pid in http_server_pids:
            _stop_process(sensor, http_server_pid, sudo_password=args.password)
        for udp_sink_pid, needs_sudo in udp_sink_pids:
            _stop_process(sensor, udp_sink_pid, sudo_password=args.password if needs_sudo else None)
        for tcp_sink_pid, needs_sudo in tcp_sink_pids:
            _stop_process(sensor, tcp_sink_pid, sudo_password=args.password if needs_sudo else None)
        _stop_runtime(sensor, pid, sudo_password=args.password)
        _chown_result_dir(sensor, args.workspace, result_rel, sudo_password=args.password)
        _generate_reports(sensor, args.workspace, result_rel)
        _collect_artifacts(sensor, args.workspace, result_rel, local_result_dir)
        _, summary_md = _write_validation_summary(
            local_result_dir,
            attack_jobs,
            concurrent=args.concurrent,
        )
    finally:
        for http_server_pid in http_server_pids:
            try:
                _stop_process(sensor, http_server_pid, sudo_password=args.password)
            except Exception:
                pass
        for udp_sink_pid, needs_sudo in udp_sink_pids:
            try:
                _stop_process(sensor, udp_sink_pid, sudo_password=args.password if needs_sudo else None)
            except Exception:
                pass
        for tcp_sink_pid, needs_sudo in tcp_sink_pids:
            try:
                _stop_process(sensor, tcp_sink_pid, sudo_password=args.password if needs_sudo else None)
            except Exception:
                pass
        sensor.close()
        target.close()

    print(f"local_result_dir={local_result_dir}")
    print(f"report={local_result_dir / 'serious_test_report.md'}")
    print(f"attack_validation_summary={summary_md}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
