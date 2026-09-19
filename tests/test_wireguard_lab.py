import subprocess
from types import SimpleNamespace

import pytest
from scapy.layers.inet import IP, TCP, UDP
from scapy.utils import wrpcap

from scripts import wireguard_lab
from scripts.verify_wireguard_capture import verify


@pytest.mark.parametrize("created", [False, True])
def test_failure_cleanup_only_deletes_namespaces_created_by_this_run(tmp_path, monkeypatch, created):
    calls = []

    def fake_run(*args, **kwargs):
        calls.append(args)
        if args[:3] == ("ip", "netns", "add") and not created:
            raise subprocess.CalledProcessError(1, args)
        if args[:2] == ("ip", "-n"):
            raise subprocess.CalledProcessError(1, args)
        return SimpleNamespace(stdout="test version", returncode=0)

    monkeypatch.setattr(wireguard_lab, "os", SimpleNamespace(name="posix", geteuid=lambda: 0))
    monkeypatch.setattr(wireguard_lab.shutil, "which", lambda tool: tool)
    monkeypatch.setattr(wireguard_lab, "run", fake_run)
    with pytest.raises(subprocess.CalledProcessError):
        wireguard_lab.exercise(tmp_path / "run")
    deletes = [call for call in calls if call[:3] == ("ip", "netns", "delete")]
    assert len(deletes) == int(created)
    assert not (tmp_path / "run/tunnel-report.json").exists()


def test_capture_verifier_rejects_wrong_outer_endpoint(tmp_path):
    wrpcap(str(tmp_path / "inner.pcap"), IP(src="10.203.0.1", dst="10.203.0.2") / TCP(dport=3389))
    wrpcap(str(tmp_path / "outer.pcap"), IP(src="192.0.2.1", dst="203.0.113.7") / UDP(dport=51820))
    with pytest.raises(RuntimeError, match="Unexpected outer endpoint"):
        verify(tmp_path)
    assert not (tmp_path / "detection-report.json").exists()


def test_capture_verifier_needs_no_write_access_to_capture_directory(tmp_path, monkeypatch):
    wrpcap(str(tmp_path / "inner.pcap"), IP(src="10.203.0.1", dst="10.203.0.2") / TCP(dport=3389))
    wrpcap(str(tmp_path / "outer.pcap"), IP(src="192.0.2.1", dst="192.0.2.2") / UDP(dport=51820))

    def deny_write(*args, **kwargs):
        raise PermissionError("Root-owned capture directory")

    monkeypatch.setattr(type(tmp_path), "write_text", deny_write)
    assert verify(tmp_path)["signature_alerts"] == 1
    assert not (tmp_path / "detection-report.json").exists()
