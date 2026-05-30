# Resume Project Bullets

Use only the bullets you can defend clearly in an interview. Favor the versions that best match the role, and keep the wording aligned to the current repo state.

## Cybersecurity Roles

### Short Bullet Set

- Built a hybrid network intrusion detection workspace spanning live capture, offline replay, multi-engine detection, retained evidence, and analyst-facing reporting.
- Expanded validation coverage to `152` collected tests with `144` passing in the default suite and `79.16%` coverage under a `72%` CI floor.

### Stronger Technical Bullet Set

- Implemented a unified IDS pipeline covering live traffic ingest, offline PCAP replay, signature rules, anomaly scoring, supervised ML, optional unsupervised detection, fusion, SQLite/JSONL retention, and dashboard/report outputs.
- Added evidence-backed lab validation across `5` latest offline scenario passes and `10` latest prepared-environment scenario passes retained across `17` manifests.

### Research-Oriented Bullet Set

- Framed a hybrid IDS project around evidence-backed validation rather than model metrics alone, documenting code-level testing, repeatable scenario execution, false-positive tuning, and prepared-environment results.
- Produced a controlled pre-deployment validation record with explicit boundaries around soak duration, benign-corpus breadth, and restart-based maintenance workflows.

## Detection Engineer Roles

### Short Bullet Set

- Built and validated a fusion-based IDS workflow that correlates signature, anomaly, supervised, and optional unsupervised signals.
- Tuned the live unsupervised path to reduce the exercised benign-soak sample to `0` alerts across `1416` flows.

### Stronger Technical Bullet Set

- Engineered a hybrid detection stack combining YAML signatures, statistical anomaly logic, supervised ensemble scoring, optional unsupervised scoring, and fusion-based alert decisions in one normalized pipeline.
- Added prepared-environment evidence for queue-loss accounting, restart recovery, rule refresh, model swap, and config override using retained scenario manifests and summary indexes.

### Research-Oriented Bullet Set

- Documented how offline replay results and prepared live validation complement each other when evaluating a detection system intended for analyst review.
- Preserved detection claims conservatively by separating implemented capability from partially validated and planned work.

## SOC / Threat Detection Roles

### Short Bullet Set

- Built an IDS workspace that retains alerts, flows, metrics, and evidence bundles for analyst review instead of one-off console output.
- Validated repeatable attack and tuning scenarios across offline replay and prepared live environments.

### Stronger Technical Bullet Set

- Added operator-focused evidence for restart-based rule refresh, model swap, and configuration override under live traffic, with reload latencies of about `13.2s` in the latest prepared-environment runs.
- Created an artifact-plus-network correlation scenario that retained `7` flows, `1` network alert, `4` artifact rows, and `2` quarantined high-risk artifacts in one evidence bundle.

### Research-Oriented Bullet Set

- Used structured scenario bundles and indexed manifests to make threat-detection validation easier to audit, present, and resume.
- Documented false-positive handling with analyst adjudication instead of presenting alert reduction as an unsupported claim.

## Security Research Roles

### Short Bullet Set

- Built a research-ready hybrid NIDS workspace with repeatable scenario execution and prepared-environment evidence retention.
- Turned project validation into paper- and thesis-ready material with explicit readiness boundaries and reproducible evidence paths.

### Stronger Technical Bullet Set

- Evaluated the current supervised ensemble on `25000` labeled flows with `0.99784` accuracy and `0.99792` weighted F1 in the current offline evaluation report.
- Documented layered validation results including `152` collected tests, `79.16%` coverage, `5` latest offline scenario passes, and `10` latest prepared-environment passes across `17` manifests.

### Research-Oriented Bullet Set

- Studied the gap between benchmark-style IDS evaluation and prepared-environment operational evidence by combining software testing, scenario replay, live capture validation, and analyst tuning records in one repo.
- Preserved methodological rigor by explicitly treating the `900s` soak as a pilot toward a `21600s` target rather than overstating operational maturity.

## Network Security Roles

### Short Bullet Set

- Built a network-security lab workspace that supports live capture, offline replay, and multi-engine intrusion detection in one pipeline.
- Validated packet-processing behavior under both normal scenarios and queue-pressure conditions in a prepared lab environment.

### Stronger Technical Bullet Set

- Recorded live queue-pressure evidence showing `8127` packets received, `23` processed, `8100` dropped, and `99.6678%` loss without crashing the runtime, giving a clear view of degraded behavior under stress.
- Validated live capture through both `tcpdump` and `scapy` backends and retained scenario-level evidence for malformed traffic handling, restart recovery, and tuned benign traffic.

### Research-Oriented Bullet Set

- Used prepared-environment validation to move beyond isolated packet parsing or model training and toward a defendable pre-deployment network-security narrative.
- Documented platform and readiness boundaries clearly, including Linux runtime emphasis, Windows lab-host strength, and incomplete macOS validation.

## Four Strong General-Purpose Bullets

- Built a hybrid network intrusion detection workspace that combines signature, anomaly, supervised ML, optional unsupervised scoring, and fusion-based alerting across live capture and offline replay paths.
- Expanded project validation to `152` collected tests with `144` passing in the default suite and `79.16%` coverage under a `72%` CI floor.
- Added evidence-backed prepared-environment validation for live capture, queue-loss accounting, benign-soak tuning, and restart-based operator workflows across `10` current passing scenarios.
- Tuned live false positives in the exercised benign-soak sample to `0` alerts across `1416` flows while preserving a conservative readiness verdict and tracking the remaining soak and benign-corpus gaps.
