"""Isolated Linux WireGuard lab. No host routes, firewall, or external peers."""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import shutil
import signal
import subprocess
import tempfile
import time
import uuid


def run(*args: str, check: bool = True, **kwargs) -> subprocess.CompletedProcess:
    # Never log command output that could contain a generated key.
    return subprocess.run(args, check=check, capture_output=True, text=True, timeout=15, **kwargs)


def exercise(output: Path) -> dict:
    if os.name != "posix" or os.geteuid() != 0:
        raise RuntimeError("Run inside a disposable Linux environment as root")
    for tool in ("ip", "wg", "ping", "tcpdump", "python3"):
        if not shutil.which(tool):
            raise RuntimeError(f"Missing dependency: {tool}")
    output.mkdir(parents=True, exist_ok=False)
    token = uuid.uuid4().hex[:10]
    client, gateway = f"fn-c-{token}", f"fn-g-{token}"
    created = []
    captures = []
    handles = []
    report = {"mode": "isolated-wireguard-lab", "pqc": False, "checks": {},
              "versions": {"kernel": run("uname", "-r").stdout.strip(),
                           "wireguard": run("wg", "--version").stdout.strip()}}
    try:
        with tempfile.TemporaryDirectory(prefix="fusion-wg-keys-") as keys:
            for ns in (client, gateway):
                run("ip", "netns", "add", ns)
                created.append(ns)
                run("ip", "-n", ns, "link", "set", "lo", "up")
            run("ip", "-n", client, "link", "add", "underlay", "type", "veth",
                "peer", "name", "underlay", "netns", gateway)
            pubs = {}
            for ns, outer, inner in ((client, "192.0.2.1", "10.203.0.1"),
                                     (gateway, "192.0.2.2", "10.203.0.2")):
                run("ip", "-n", ns, "addr", "add", outer + "/30", "dev", "underlay")
                run("ip", "-n", ns, "link", "set", "underlay", "up")
                run("ip", "-n", ns, "link", "add", "wg0", "type", "wireguard")
                key = run("wg", "genkey").stdout
                keyfile = Path(keys) / ns
                keyfile.touch(mode=0o600)
                keyfile.write_text(key)
                pubs[ns] = run("wg", "pubkey", input=key).stdout.strip()
                run("ip", "netns", "exec", ns, "wg", "set", "wg0", "private-key",
                    str(keyfile), "listen-port", "51820")
                run("ip", "-n", ns, "addr", "add", inner + "/30", "dev", "wg0")
                run("ip", "-n", ns, "link", "set", "wg0", "up")

            def peer(ns, public, endpoint, allowed):
                run("ip", "netns", "exec", ns, "wg", "set", "wg0", "peer", public,
                    "endpoint", endpoint + ":51820", "allowed-ips", allowed + "/32")

            peer(client, pubs[gateway], "192.0.2.2", "10.203.0.2")
            peer(gateway, pubs[client], "192.0.2.1", "10.203.0.1")
            for ns in (client, gateway):
                defaults = run("ip", "-n", ns, "route", "show", "default").stdout.strip()
                if defaults:
                    raise RuntimeError("Unexpected default route in isolated lab")
            report["checks"]["no_default_routes"] = True

            def ping():
                return run("ip", "netns", "exec", client, "ping", "-n", "-c", "2",
                           "-W", "1", "10.203.0.2", check=False).returncode

            if ping() != 0:
                raise RuntimeError("Initial tunnel connectivity failed")
            report["checks"]["connected"] = True
            handshake = run("ip", "netns", "exec", gateway, "wg", "show", "wg0", "latest-handshakes").stdout
            if not handshake.strip() or int(handshake.split()[-1]) <= 0:
                raise RuntimeError("No authenticated handshake observed")
            report["checks"]["handshake_observed"] = True

            # Capture only on interfaces inside the isolated gateway namespace.
            for iface, filename, capture_filter in (("wg0", "inner.pcap", "tcp"),
                                                     ("underlay", "outer.pcap", "udp port 51820")):
                log = (output / (filename + ".log")).open("w+")
                handles.append(log)
                proc = subprocess.Popen(["ip", "netns", "exec", gateway, "tcpdump", "-Z", "root",
                                         "-U", "-n", "-i", iface, "-w", str(output / filename), capture_filter],
                                        stdout=subprocess.DEVNULL, stderr=log)
                captures.append(proc)
                deadline = time.monotonic() + 5
                while True:
                    log.seek(0)
                    if "listening on" in log.read():
                        break
                    if proc.poll() is not None or time.monotonic() >= deadline:
                        raise RuntimeError("Capture did not become ready")
                    time.sleep(0.05)
            # A harmless TCP connect to a closed port creates real tunneled SYN/RST packets.
            probe = "import socket; s=socket.socket(); s.settimeout(2); s.connect_ex(('10.203.0.2',3389)); s.close()"
            run("ip", "netns", "exec", client, "python3", "-c", probe)
            time.sleep(1)
            for proc in captures:
                proc.send_signal(signal.SIGINT)
                proc.wait(timeout=5)
                if proc.returncode != 0:
                    raise RuntimeError("Packet capture failed")
            captures.clear()
            for name in ("inner.pcap", "outer.pcap"):
                if (output / name).stat().st_size <= 24:
                    raise RuntimeError(f"Empty capture: {name}")
            report["checks"]["inner_and_outer_captured"] = True
            run("ip", "netns", "exec", gateway, "wg", "set", "wg0", "peer", pubs[client], "remove")
            if ping() != 1:
                raise RuntimeError("Revocation must produce ping packet loss, not success or a command error")
            # Underlay remains reachable: revocation, not a broken cable, caused the loss.
            if run("ip", "netns", "exec", client, "ping", "-n", "-c", "1", "-W", "1",
                   "192.0.2.2", check=False).returncode != 0:
                raise RuntimeError("Underlay failed during revocation control")
            report["checks"]["revoked_tunnel_denied_underlay_alive"] = True
            peer(gateway, pubs[client], "192.0.2.1", "10.203.0.1")
            # Reset client session so reconnection need not wait for rekey timers.
            run("ip", "netns", "exec", client, "wg", "set", "wg0", "peer", pubs[gateway], "remove")
            peer(client, pubs[gateway], "192.0.2.2", "10.203.0.2")
            if ping() != 0:
                raise RuntimeError("Reauthorized peer did not reconnect")
            report["checks"]["reauthorized_reconnected"] = True
    finally:
        for proc in captures:
            if proc.poll() is None:
                proc.terminate()
                try:
                    proc.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    proc.kill()
                    proc.wait(timeout=5)
        for handle in handles:
            handle.close()
        failures = []
        for ns in reversed(created):
            if run("ip", "netns", "delete", ns, check=False).returncode:
                failures.append(ns)
        if failures:
            raise RuntimeError("Could not remove owned lab namespaces: " + ", ".join(failures))
    report["checks"]["resources_removed"] = True
    (output / "tunnel-report.json").write_text(json.dumps(report, indent=2) + "\n")
    return report


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True, help="New directory for synthetic lab captures")
    args = parser.parse_args()
    print(json.dumps(exercise(args.output.resolve()), indent=2))
