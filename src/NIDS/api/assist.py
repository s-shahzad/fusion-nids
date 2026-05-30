from __future__ import annotations

from collections import Counter
from typing import Protocol

from pydantic import BaseModel, Field


class AssistAlert(BaseModel):
    timestamp: str | None = None
    severity: str | None = None
    engine: str | None = None
    rule_name: str | None = None
    summary: str | None = None
    src_ip: str | None = None
    dst_ip: str | None = None
    proto: str | None = None


class AssistRunSummary(BaseModel):
    run_name: str
    output_dir: str
    flows: int
    alerts: int
    report_path: str | None = None
    visuals_path: str | None = None
    status: str


class SummarizeRunRequest(BaseModel):
    run_name: str | None = None
    summary: AssistRunSummary | None = None
    alert_limit: int = Field(default=20, ge=1, le=100)


class SummarizeRunResponse(BaseModel):
    executive_summary: str
    technical_summary: str
    key_findings: list[str]
    severity_overview: dict[str, int]
    analyst_notes: list[str]
    recommended_next_checks: list[str]


class ExplainAlertRequest(BaseModel):
    run_name: str | None = None
    alert_index: int | None = Field(default=None, ge=0, le=99)
    alert: AssistAlert | None = None


class ExplainAlertResponse(BaseModel):
    alert_explanation: str
    likely_trigger_reason: str
    relevant_fields: dict[str, str]
    likely_impact: str
    false_positive_considerations: list[str]
    analyst_follow_up: list[str]


class AnalyzeAlertsRequest(BaseModel):
    alerts: list[AssistAlert] = Field(min_length=1, max_length=100)


class AnalyzeAlertsResponse(BaseModel):
    pattern_summary: str
    repeated_rule_observations: list[str]
    engine_distribution: dict[str, int]
    severity_distribution: dict[str, int]
    possible_campaign_or_burst_commentary: str
    analyst_follow_up: list[str]


def _distribution(alerts: list[AssistAlert], attr: str) -> dict[str, int]:
    counts = Counter(str(getattr(alert, attr) or "unknown") for alert in alerts)
    return dict(sorted(counts.items(), key=lambda item: (-item[1], item[0])))


def _top_rules(alerts: list[AssistAlert], limit: int = 3) -> list[tuple[str, int]]:
    counts = Counter(str(alert.rule_name or "unknown") for alert in alerts)
    return counts.most_common(limit)


class AssistProvider(Protocol):
    provider_name: str

    def summarize_run(
        self,
        *,
        summary: AssistRunSummary,
        alerts: list[AssistAlert],
    ) -> SummarizeRunResponse: ...

    def explain_alert(self, *, alert: AssistAlert) -> ExplainAlertResponse: ...

    def analyze_alerts(self, *, alerts: list[AssistAlert]) -> AnalyzeAlertsResponse: ...


class DeterministicAssistProvider:
    provider_name = "deterministic"

    def summarize_run(
        self,
        *,
        summary: AssistRunSummary,
        alerts: list[AssistAlert],
    ) -> SummarizeRunResponse:
        severity_overview = _distribution(alerts, "severity") if alerts else {}
        engine_overview = _distribution(alerts, "engine") if alerts else {}
        top_rules = _top_rules(alerts)
        top_rule_text = ", ".join(f"{rule} ({count})" for rule, count in top_rules) if top_rules else "no alerts sampled"
        top_engine = next(iter(engine_overview.keys()), "unknown")
        key_findings = [
            f"Run status is {summary.status}.",
            f"Recorded {summary.flows} flows and {summary.alerts} alerts.",
            f"Top sampled rules: {top_rule_text}.",
        ]
        analyst_notes = [
            f"Assist output is derived from stored run artifacts only.",
            f"Sampled alert engine with highest frequency: {top_engine}.",
        ]
        return SummarizeRunResponse(
            executive_summary=(
                f"Run {summary.run_name} completed with {summary.flows} flows and {summary.alerts} alerts; "
                f"stored status is {summary.status}."
            ),
            technical_summary=(
                f"Summary derived from run metadata and {len(alerts)} bounded alert records. "
                f"Most frequent sampled engine: {top_engine}."
            ),
            key_findings=key_findings,
            severity_overview=severity_overview,
            analyst_notes=analyst_notes,
            recommended_next_checks=[
                "Review summary.md for the stored severity and engine breakdown.",
                "Inspect repeated rules in alerts.jsonl for clustering or duplicate noise.",
                "Compare this run against the validated 10-alert baseline if investigating drift.",
            ],
        )

    def explain_alert(self, *, alert: AssistAlert) -> ExplainAlertResponse:
        relevant_fields = {
            key: str(value)
            for key, value in alert.model_dump().items()
            if value not in (None, "")
        }
        likely_impact = {
            "critical": "High analyst priority due to critical severity.",
            "high": "Potentially actionable event that should be triaged promptly.",
            "medium": "Investigate for context before escalating.",
        }.get(str(alert.severity or "").lower(), "Review in context with adjacent alerts.")
        false_positive_considerations = [
            f"Engine source is {alert.engine or 'unknown'}; validate against nearby alerts and summary context.",
            "Treat repeated low-context pattern matches carefully before assuming confirmed malicious activity.",
        ]
        return ExplainAlertResponse(
            alert_explanation=(
                f"Alert {alert.rule_name or 'unknown'} was recorded by the {alert.engine or 'unknown'} engine"
                f" with severity {alert.severity or 'unknown'}."
            ),
            likely_trigger_reason=alert.summary or f"Triggered rule or engine path: {alert.rule_name or 'unknown'}.",
            relevant_fields=relevant_fields,
            likely_impact=likely_impact,
            false_positive_considerations=false_positive_considerations,
            analyst_follow_up=[
                "Check whether the same rule appears repeatedly in the run.",
                "Compare source and destination fields with adjacent alerts in the same run.",
                "Use summary and alerts endpoints to confirm whether this is isolated or part of a burst.",
            ],
        )

    def analyze_alerts(self, *, alerts: list[AssistAlert]) -> AnalyzeAlertsResponse:
        engine_distribution = _distribution(alerts, "engine")
        severity_distribution = _distribution(alerts, "severity")
        top_rules = _top_rules(alerts, limit=5)
        repeated = [f"{rule}: {count}" for rule, count in top_rules if count > 1]
        if not repeated:
            repeated = ["No repeated sampled rules above count 1."]
        src_counts = Counter(str(alert.src_ip or "unknown") for alert in alerts)
        dominant_src, dominant_count = src_counts.most_common(1)[0]
        burst_commentary = (
            f"Dominant sampled source is {dominant_src} with {dominant_count} alert records."
            if dominant_count > 1
            else "No dominant sampled source observed in the bounded alert set."
        )
        return AnalyzeAlertsResponse(
            pattern_summary=(
                f"Analyzed {len(alerts)} bounded alert records across "
                f"{len(engine_distribution)} engines and {len(severity_distribution)} severity buckets."
            ),
            repeated_rule_observations=repeated,
            engine_distribution=engine_distribution,
            severity_distribution=severity_distribution,
            possible_campaign_or_burst_commentary=burst_commentary,
            analyst_follow_up=[
                "Review whether repeated rules map to a single source/destination pair.",
                "Compare engine distribution with the run summary to see if the sample is representative.",
                "Escalate only after confirming repeated patterns in the stored artifacts.",
            ],
        )


def get_assist_provider() -> AssistProvider:
    return DeterministicAssistProvider()
