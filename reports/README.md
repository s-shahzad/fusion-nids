# reports/

**Everything else in this directory is generated and is not tracked in git.**

It used to be committed — roughly 30 files of chart renders, metric dumps, and
threshold-tuning output. That inflated diffs and made the repository read as a
working directory rather than a project. The outputs are reproducible, so the
commands that produce them are tracked instead of the results.

## Regenerating

Run a pipeline over a capture, then produce the reports and visualisations:

```sh
python -m nids run --pcap <capture.pcap> --out output/<run-name>
python -m nids report --from-db output/<run-name>/nids.db
```

Model evaluation and threshold tuning write here as well:

```sh
python -m nids evaluate --from-db <db> --model models/model.pkl   # reports/ml_evaluation.json
```

Incident reports written through the API are confined to this directory; a path
that escapes it is rejected.

## What is tracked instead

| Content | Location | Why |
|---|---|---|
| Curated showcase charts | `docs/figures/` | A small, captioned set worth reading in the repository |
| Prepared-environment evidence | `NIDS_TestLab/reports/*.json` and `*.md` | The record behind the validation claims. Deliberately kept — see below |

## Why the lab evidence stays tracked

`NIDS_TestLab/reports/prepared_env_validation_index.json` is about 1 MB, which
is large for a tracked file. It is kept anyway because it is the evidence behind
every prepared-environment number this project reports — queue loss, benign
false positives, restart recovery, the six-hour soak. Untracking it would leave
the claims in the documentation with nothing to check them against.

Generated renders are disposable. Evidence is not. The two are treated
differently on purpose.
