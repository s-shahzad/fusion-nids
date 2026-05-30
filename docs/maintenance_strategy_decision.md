# Maintenance Strategy Decision

Last updated: March 12, 2026

## Decision

Restart-based maintenance is acceptable for the intended controlled release scope. Keep restart-based maintenance workflows for the controlled pre-deployment candidate and engineer hot reload before any real-world deployment that requires uninterrupted detection coverage.

## Supporting Evidence

| Scenario ID | Objective | Environment | Expected outcome | Actual outcome | Evidence path | Verdict |
|---|---|---|---|---|---|---|
| `PREP-ENV-007` | Run a sustained prepared-environment soak with resource tracking and midpoint restart stability evidence. | Windows orchestration host, Ubuntu sensor VM, Ubuntu target VM, tuned live profile via `tcpdump` | Resource, storage, and restart evidence should be retained during the soak pilot. | `4742` flows and `0` alerts recorded; midpoint restart completed with `13.251s` reload latency and counts increased from `2199` to `4742` flows. | `NIDS_TestLab/results/phase5-soak/phase5-extended-soak-20260312-165051/` | `pass` for pilot |
| `PREP-ENV-008` | Validate restart-based rule refresh while live DNS traffic is active. | Windows orchestration host, Ubuntu sensor VM, Ubuntu target VM, tuned live profile via `tcpdump` | The custom DNS signature should begin matching only after the refresh. | `321` flows and `1` signature alert recorded; reload latency `13.238s`; post-refresh rule count increased from `0` to `1`. | `NIDS_TestLab/results/phase5-operator/phase5-operator-rule-refresh-20260312-201250/` | `pass` |
| `PREP-ENV-009` | Validate restart-based supervised model swap during live traffic. | Windows orchestration host, Ubuntu sensor VM, Ubuntu target VM, tuned live profile via `tcpdump` | Flow continuity and detection continuity should persist after the model-path swap. | `330` flows and `2` anomaly alerts recorded; reload latency `13.201s`; counts increased from `228` to `330` flows. | `NIDS_TestLab/results/phase5-operator/phase5-operator-model-swap-20260312-164422/` | `pass` |
| `PREP-ENV-010` | Validate restart-based config override from the baseline profile to the tuned profile while benign traffic remains active. | Windows orchestration host, Ubuntu sensor VM, Ubuntu target VM, baseline-to-tuned live profile via `tcpdump` | Flow continuity should persist across the profile swap and the tuned benign sample should stay quiet. | `394` flows and `0` alerts recorded; reload latency `13.268s`; counts increased from `125` to `394` flows. | `NIDS_TestLab/results/phase5-operator/phase5-operator-config-override-20260312-164850/` | `pass` |

## Reload Latency Evidence

- `PREP-ENV-008`: `13.238s`
- `PREP-ENV-009`: `13.201s`
- `PREP-ENV-010`: `13.268s`
- `PREP-ENV-007` midpoint restart: `13.251s`
- Mean observed reload latency: `13.240s`

## Operational Impact

What the evidence supports directly:

- restart-based workflows complete cleanly on the prepared sensor VM
- flow counts continue growing after the restart event
- rule refresh, model swap, and config override all produced the intended post-restart behavior
- the latest `PREP-ENV-008` rerun matched the earlier restart behavior on the same tuned profile bound to `release/rc1/`
- the soak pilot did not show restart-induced corruption or operator-visible instability

What remains an inference from the restart model plus the measured timings:

- the detector is not inspecting traffic during the roughly `13s` restart window
- environments that require uninterrupted coverage still carry blind-window risk during restart-based maintenance

## Recommendation

Recommendation for the current release posture:

- keep restart-based maintenance workflows for the controlled pre-deployment candidate
- accept restart-based maintenance for the intended controlled release scope only
- require a planned maintenance window for rule refresh, model swap, and config override actions
- do not claim uninterrupted coverage during restart-based maintenance
- keep the current release posture tied to the hash-frozen evidence in `release/rc1/`
- complete the running full-duration soak before using maintenance evidence to support any stronger promotion claim

Recommendation before unrestricted real-world deployment:

- engineer hot reload, or an equivalent zero-downtime handoff strategy, before any environment that cannot tolerate a roughly `13s` detection gap
- validate the final maintenance approach again during the full `PREP-ENV-007` duration run so restart behavior is evidenced under the same sustained traffic window used for release promotion
