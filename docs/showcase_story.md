# Showcase Story

## What The Project Is

Universal NIDS is a hybrid network intrusion detection workspace built to unify live packet capture, offline replay, optional adapter ingest, artifact static analysis, detection, storage, and visualization in one repository. It combines signature rules, statistical anomaly logic, supervised ML, optional unsupervised scoring, and fusion-based alerting so the project can be evaluated as a working security workflow rather than a single isolated model.

## What Problem It Solves

Many student and research IDS projects stop at a good model score or a one-off demo. That leaves open the harder questions:

- Does the system behave cleanly across live and offline paths?
- Can it retain evidence that an analyst can actually review?
- Can it survive tuning, restart, and maintenance workflows?
- Can it show where the false-positive and operational boundaries still are?

This project addresses that gap by combining detection logic with retained evidence, scenario execution, prepared-environment validation, and analyst-facing outputs.

## What Makes It Different

- It is not only an ML classifier. It blends signature, anomaly, supervised, optional unsupervised, and fusion logic.
- It supports both live and offline analysis in the same workspace.
- It retains evidence in SQLite, JSONL, charts, reports, and scenario bundles rather than treating detections as disposable console output.
- It documents operational realities such as packet loss, restart behavior, and false-positive tuning instead of hiding them.
- It distinguishes implemented capability from partially validated or planned work.

## What Was Validated

The current repo state supports the following evidence-backed claims:

- `152` tests are collected under the current suite configuration.
- The default suite result is `144 passed, 8 deselected` with `0` active pytest warnings.
- Coverage is `79.16%` with a `72%` enforced floor.
- `5` latest offline lab scenarios passed.
- `10` latest prepared-environment scenarios passed across `17` retained manifests.
- Prepared-environment evidence covers live capture, malformed-packet handling, queue-loss accounting, benign-soak tuning, restart recovery, and restart-based rule/model/config workflows.
- `PREP-ENV-005` reduced the exercised benign-soak sample to `0` alerts across `1416` flows after a targeted unsupervised-tuning change.
- `LAB-SCN-005` retained network and artifact evidence together with `7` flows, `1` network alert, `4` artifact rows, and `2` quarantined high-risk artifacts.

## Current Readiness State

The project is beyond prototype-only validation and is suitable for controlled pre-deployment review. It is not yet ready to be presented as production-ready.

Current boundaries that should remain explicit:

- the longer soak is still a `900s` pilot toward a `21600s` target
- benign false-positive adjudication is strong for the exercised sample, not for every benign environment
- operator workflows are restart-based; validated zero-downtime hot reload is not part of the current evidence

## What Comes Next

- complete the full `6` to `12` hour soak
- broaden benign traffic adjudication
- add a suppression-focused prepared-environment exercise
- decide whether restart-based maintenance is sufficient or whether hot reload is required
- package redacted evidence for publication, portfolio use, and demo delivery

## Recruiter Explanation

Universal NIDS is a portfolio-ready cybersecurity project that goes beyond a typical IDS demo. It combines live traffic analysis, offline replay, hybrid detection, reporting, and lab validation in one workspace. The strongest part of the project is that it is supported by real validation evidence, including `152` collected tests, `79.16%` coverage, repeatable attack scenarios, prepared-environment runs, and documented false-positive tuning. The current story is "evidence-backed security engineering with honest readiness boundaries," not "finished commercial product."

## Technical Interviewer Explanation

This project is a hybrid NIDS workspace built around one normalized pipeline: ingest, parse, extract features, run multiple detectors, fuse the outputs, persist the evidence, and expose the results through reports and a dashboard. The interesting engineering work is less about any one detector and more about how the system behaves under different execution modes and maintenance operations. The repo now includes repeatable offline scenarios, prepared-environment live validation, queue-loss accounting, restart recovery, and restart-based rule/model/config workflow evidence. I would describe it as a security engineering and validation project with applied ML components, not as a finished SOC product.

## Professor / Research Audience Explanation

This project studies how to validate a practical hybrid intrusion detection workspace without reducing the entire evaluation to offline classification metrics. The contribution is an evidence-driven validation method spanning deterministic software tests, repeatable offline scenarios, prepared-environment live capture, false-positive adjudication, and retained operator evidence. The current results support a controlled pre-deployment candidate and provide a clean base for a paper, thesis section, poster, or applied-security demonstration. The current limitations remain part of the story: incomplete full-duration soak evidence, incomplete benign-corpus breadth, and restart-based rather than hot-reload operator workflows.
