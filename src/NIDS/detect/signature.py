from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml


class SignatureEngine:
    """YAML rule matcher with protocol-aware fields and payload checks."""

    def __init__(self, rules_path: str | Path) -> None:
        self.rules_path = Path(rules_path)
        self.rules = self._load_rules()

    def _load_rules(self) -> list[dict[str, Any]]:
        if not self.rules_path.exists():
            return []

        with self.rules_path.open("r", encoding="utf-8") as handle:
            payload = yaml.safe_load(handle) or []

        if isinstance(payload, dict):
            payload = [payload]
        if not isinstance(payload, list):
            return []

        return [item for item in payload if isinstance(item, dict)]

    def detect(self, event: dict[str, Any], features: dict[str, Any]) -> list[dict[str, Any]]:
        payload_text = bytes(event.get("payload", b""))[:2048].decode("utf-8", errors="ignore").lower()
        alerts: list[dict[str, Any]] = []

        for rule in self.rules:
            match = rule.get("match", {}) or {}
            if not isinstance(match, dict):
                continue

            if not self._matches(event, payload_text, match):
                continue

            alerts.append(
                {
                    "engine": "signature",
                    "severity": str(rule.get("severity", "medium")).lower(),
                    "rule_name": str(rule.get("name", "signature_rule")),
                    "summary": str(rule.get("summary") or f"Rule matched: {rule.get('name', 'signature_rule')}"),
                    "extra": {"match": match, "action": rule.get("action", "alert")},
                }
            )

        return alerts

    def _matches(self, event: dict[str, Any], payload_text: str, match: dict[str, Any]) -> bool:
        if not self._match_proto(event, match):
            return False
        if not self._match_ips(event, match):
            return False
        if not self._match_ports(event, match):
            return False
        if not self._match_dataset(event, match):
            return False
        if not self._match_protocol_fields(event, match):
            return False
        if not self._match_payload(payload_text, match):
            return False
        return True

    @staticmethod
    def _match_proto(event: dict[str, Any], match: dict[str, Any]) -> bool:
        proto = match.get("proto")
        if proto and str(event.get("proto", "")).upper() != str(proto).upper():
            return False
        return True

    @staticmethod
    def _match_ips(event: dict[str, Any], match: dict[str, Any]) -> bool:
        src_ips = {str(item) for item in (match.get("src_ips") or [])}
        if src_ips and str(event.get("src_ip")) not in src_ips:
            return False

        dst_ips = {str(item) for item in (match.get("dst_ips") or [])}
        if dst_ips and str(event.get("dst_ip")) not in dst_ips:
            return False

        return True

    @staticmethod
    def _match_ports(event: dict[str, Any], match: dict[str, Any]) -> bool:
        src_ports = {int(item) for item in (match.get("src_ports") or [])}
        if src_ports and int(event.get("src_port") or -1) not in src_ports:
            return False

        dst_ports = {int(item) for item in (match.get("dst_ports") or [])}
        if dst_ports and int(event.get("dst_port") or -1) not in dst_ports:
            return False

        return True

    @staticmethod
    def _match_dataset(event: dict[str, Any], match: dict[str, Any]) -> bool:
        datasets = {str(item).lower() for item in (match.get("dataset_sources") or [])}
        if datasets and str(event.get("dataset_source", "")).lower() not in datasets:
            return False
        return True

    @staticmethod
    def _match_protocol_fields(event: dict[str, Any], match: dict[str, Any]) -> bool:
        dns_qnames = [str(item).lower() for item in (match.get("dns_qnames") or [])]
        if dns_qnames:
            event_qname = str(event.get("dns_qname") or "").lower()
            if not any(token in event_qname for token in dns_qnames):
                return False

        http_hosts = [str(item).lower() for item in (match.get("http_hosts") or [])]
        if http_hosts:
            event_host = str(event.get("http_host") or "").lower()
            if not any(token in event_host for token in http_hosts):
                return False

        http_methods = [str(item).upper() for item in (match.get("http_methods") or [])]
        if http_methods:
            event_method = str(event.get("http_method") or "").upper()
            if event_method not in http_methods:
                return False

        http_uris = [str(item).lower() for item in (match.get("http_uris") or [])]
        if http_uris:
            event_uri = str(event.get("http_uri") or "").lower()
            if not any(token in event_uri for token in http_uris):
                return False

        tls_sni = [str(item).lower() for item in (match.get("tls_sni") or [])]
        if tls_sni:
            event_sni = str(event.get("tls_sni") or "").lower()
            if not any(token in event_sni for token in tls_sni):
                return False

        return True

    @staticmethod
    def _match_payload(payload_text: str, match: dict[str, Any]) -> bool:
        payload_contains = [str(item).lower() for item in (match.get("payload_contains") or [])]
        if payload_contains and not any(token in payload_text for token in payload_contains):
            return False
        return True
