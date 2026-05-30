# Final Tuned Baseline

This document records the final validated offline replay baseline for Universal NIDS.

## Final Config Values

- `ml.unsupervised_confirmation_hits = 2`
- `fusion.min_agreement_count = 3`

## Validated Replay Result

- PCAP: `NIDS_TestLab/pcaps/serious_synthetic_20260310.pcap`
- Rules: `rules/rules.yml`
- Flows: `509`
- Alerts: `10`
- Alert ratio: `1.96%`

## Tuning Outcome

The final baseline reflects combined ML and fusion tuning.

- ML refinement reduced unsupervised noise by requiring repeated confirmation before alerting.
- Fusion refinement reduced repeated `Hybrid Fusion Decision` noise by requiring stronger agreement.
- Final validation retained signature alerts and critical multi-engine fusion alerts in the tuned 10-alert run.

## Run Note

Always use a fresh output directory for replay validation runs.

The runtime writes SQLite and JSONL artifacts into the selected output directory. Reusing an earlier output directory can mix results across runs because SQLite state is appended rather than automatically reset.
