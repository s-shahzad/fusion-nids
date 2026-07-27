from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from ..providers.base import AIResponse
from ..providers.ollama_provider import OllamaProvider


@dataclass(frozen=True)
class ExplainerService:
    ollama_provider: OllamaProvider

    @classmethod
    def from_env(cls) -> "ExplainerService":
        return cls(ollama_provider=OllamaProvider.from_env())

    def explain_run(
        self,
        *,
        summary: dict[str, Any],
        metrics: dict[str, Any],
        alerts: list[dict[str, Any]],
        compare_summary: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        prompt = self._build_prompt(summary=summary, metrics=metrics, alerts=alerts, compare_summary=compare_summary)
        if self.ollama_provider.available():
            try:
                response = self.ollama_provider.generate(prompt=prompt)
                return self._pack_response(response=response, fallback_used=False)
            except Exception as exc:
                fallback = self._fallback_text(summary=summary, metrics=metrics, alerts=alerts, compare_summary=compare_summary)
                return self._pack_response(
                    response=AIResponse(provider="deterministic-fallback", model="local-rules", text=fallback),
                    fallback_used=True,
                    error=str(exc),
                )
        fallback = self._fallback_text(summary=summary, metrics=metrics, alerts=alerts, compare_summary=compare_summary)
        return self._pack_response(
            response=AIResponse(provider="deterministic-fallback", model="local-rules", text=fallback),
            fallback_used=True,
        )

    def _pack_response(self, *, response: AIResponse, fallback_used: bool, error: str | None = None) -> dict[str, Any]:
        return {
            "provider": response.provider,
            "model": response.model,
            "fallback_used": fallback_used,
            "summary": response.text,
            "error": error,
        }

    def _build_prompt(
        self,
        *,
        summary: dict[str, Any],
        metrics: dict[str, Any],
        alerts: list[dict[str, Any]],
        compare_summary: dict[str, Any] | None,
    ) -> str:
        top_alerts = "\n".join(
            f"- {item.get('timestamp')} | {item.get('severity')} | {item.get('engine')} | {item.get('rule_name')} | {item.get('summary')}"
            for item in alerts[:5]
        )
        compare_text = ""
        if compare_summary is not None:
            compare_text = (
                f"\nComparison run: {compare_summary.get('run_name')} "
                f"flows={compare_summary.get('flows')} alerts={compare_summary.get('alerts')} status={compare_summary.get('status')}"
            )
        return (
            "You are explaining a validated local NIDS run for an analyst. "
            "Do not change thresholds or speculate about unobserved data. "
            "Return a concise production-style explanation covering run outcome, why it matters, "
            "alert pattern highlights, and the next safe checks.\n\n"
            f"Run: {summary.get('run_name')}\n"
            f"Flows: {summary.get('flows')}\n"
            f"Alerts: {summary.get('alerts')}\n"
            f"Status: {summary.get('status')}\n"
            f"Engine distribution: {metrics.get('engine_distribution')}\n"
            f"Severity distribution: {metrics.get('severity_distribution')}\n"
            f"Baseline comparison: {metrics.get('baseline_comparison')}\n"
            f"Sample alerts:\n{top_alerts or '- none'}"
            f"{compare_text}\n"
        )

    def _fallback_text(
        self,
        *,
        summary: dict[str, Any],
        metrics: dict[str, Any],
        alerts: list[dict[str, Any]],
        compare_summary: dict[str, Any] | None,
    ) -> str:
        matched = bool(metrics.get("baseline_comparison", {}).get("matches_validated_result"))
        top_engine = next(iter(metrics.get("engine_distribution", {}) or {}), "unknown")
        top_severity = next(iter(metrics.get("severity_distribution", {}) or {}), "unknown")
        lines = [
            f"Run {summary.get('run_name')} produced {summary.get('flows')} flows and {summary.get('alerts')} alerts with status {summary.get('status')}.",
            f"Most represented engine in the stored alert set is {top_engine}; highest-volume severity bucket is {top_severity}.",
            "This explanation is derived from stored JSONL and summary artifacts only.",
        ]
        if matched:
            lines.append("The run matches the validated baseline of 509 flows and 10 alerts.")
        else:
            delta = metrics.get("baseline_comparison", {}).get("delta", {})
            lines.append(
                f"The run differs from the validated baseline by flows={delta.get('flows')} alerts={delta.get('alerts')} "
                f"alert_ratio_delta={delta.get('alert_ratio')}."
            )
        if alerts:
            first = alerts[0]
            lines.append(
                f"Sample alert focus: {first.get('rule_name')} from the {first.get('engine')} engine at severity {first.get('severity')}."
            )
        if compare_summary is not None:
            lines.append(
                f"Compared run {compare_summary.get('run_name')} recorded {compare_summary.get('flows')} flows and {compare_summary.get('alerts')} alerts."
            )
        lines.append("Next checks: review summary.md, inspect repeated rule names, and compare against the validated 10-alert baseline before changing anything.")
        return " ".join(lines)
