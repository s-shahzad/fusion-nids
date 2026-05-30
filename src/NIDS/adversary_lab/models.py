from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


LAB_GENERATED_LABEL = "lab_generated"


@dataclass(frozen=True)
class SafetyPolicy:
    name: str = "offline-replay-only"
    offline_bundle_only: bool = True
    allow_loopback: bool = True
    allow_private_ranges: bool = True
    allow_documentation_ranges: bool = True
    allowed_cidrs: tuple[str, ...] = ()
    max_packets: int = 4096
    max_total_bytes: int = 1_500_000
    banner: str = (
        "Lab-generated adversary emulation only. Generate artifacts only for offline replay, "
        "localhost, containers, or explicitly configured isolated lab CIDRs."
    )


@dataclass(frozen=True)
class LabelEntry:
    attack_type: str
    label: str = LAB_GENERATED_LABEL
    pcap_file: str = ""
    start_time: float | None = None
    end_time: float | None = None
    src_ip: str | None = None
    dst_ip: str | None = None
    src_port: int | None = None
    dst_port: int | None = None
    proto: str | None = None

    def as_csv_row(self, pcap_name: str) -> dict[str, str]:
        return {
            "pcap_file": self.pcap_file or pcap_name,
            "start_time": "" if self.start_time is None else f"{self.start_time:.6f}",
            "end_time": "" if self.end_time is None else f"{self.end_time:.6f}",
            "src_ip": self.src_ip or "",
            "dst_ip": self.dst_ip or "",
            "src_port": "" if self.src_port is None else str(int(self.src_port)),
            "dst_port": "" if self.dst_port is None else str(int(self.dst_port)),
            "proto": "" if self.proto is None else str(self.proto).upper(),
            "label": self.label,
            "attack_type": self.attack_type,
        }


@dataclass
class ScenarioMaterial:
    scenario_id: str
    name: str
    description: str
    attack_type: str
    packets: list[Any]
    target_ips: tuple[str, ...]
    tags: tuple[str, ...] = ()
    notes: tuple[str, ...] = ()
    label_entries: list[LabelEntry] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)

