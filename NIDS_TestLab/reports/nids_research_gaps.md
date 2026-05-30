# NIDS Research Gaps and Repo Actions

Generated: 2026-03-11 20:35 UTC

This note is a thesis-oriented, representative primary-source review for the current `NIDS_Workspace` work. It is not a claim that every NIDS paper has been exhaustively reviewed. The goal is narrower and practical: identify recurring problems in the literature, map them to the current repo, and record which ones were addressed immediately.

## Primary Sources Reviewed

| Theme | Source | Why it matters for this repo |
|---|---|---|
| Port-based evasion / protocol inference | Dreger, Feldmann, Mai, Paxson, Sommer, "Dynamic Application-Layer Protocol Analysis for Network Intrusion Detection," USENIX Security 2006. https://www.usenix.org/legacy/events/sec06/tech/full_papers/dreger/dreger.pdf | Shows why fixed-port assumptions are brittle and why protocol semantics should drive analysis. |
| Dataset defects in legacy IDS evaluation | Tavallaee, Bagheri, Lu, Ghorbani, "A Detailed Analysis of the KDD CUP 99 Data Set," IEEE CISDA 2009. https://www.ee.torontomu.ca/~bagheri/papers/cisda.pdf | Important because this repo still uses bootstrapped supervised training data derived from old benchmark-style corpora. |
| Broader dataset suitability and evaluation criteria | Ring et al., "A Survey of Network-based Intrusion Detection Data Sets," 2019. https://arxiv.org/abs/1903.02460 | Useful for choosing what kind of data is needed for realistic evaluation and for explaining current dataset limitations. |
| More realistic modern dataset generation | Sharafaldin, Lashkari, Ghorbani, "Toward Generating a New Intrusion Detection Dataset and Intrusion Traffic Characterization," ICISSP 2018. https://www.scitepress.org/Papers/2018/66398/66398.pdf | Supports moving away from older benchmark-only training and toward realistic, behavior-based traffic generation. |
| Concept drift in streaming IDS | "Concept Drift–Based Intrusion Detection For Evolving Data Stream Classification In IDS: Approaches And Comparative Study," The Computer Journal 2024. https://academic.oup.com/comjnl/article-abstract/67/7/2529/7618465 | Relevant because live NIDS traffic changes over time and static models degrade. |
| Adversarial robustness of ML-NIDS | Han et al., "Evaluating and Improving Adversarial Robustness of Machine Learning-Based Network Intrusion Detectors," 2020. https://arxiv.org/abs/2005.07519 | Relevant because this repo already uses ML and hybrid scoring, and robustness against evasion is a real research requirement. |

## Recurrent Problems in the Literature

### 1. Port-based assumptions are weak

Dreger et al. show that protocol analysis tied to well-known ports is fragile and that real traffic often appears on non-standard ports. That is directly relevant here because the repo had HTTP suspicious-keyword logic constrained to `80/443/8080/8443`, which is an evasion surface.

Repo action completed:

- [signature.py](C:/NIDS_Workspace/src/NIDS/detect/signature.py) now supports `http_methods` and `http_uris` rule fields.
- [rules.yml](C:/NIDS_Workspace/rules/rules.yml) now drives `HTTP Suspicious Keyword` from parsed HTTP semantics instead of a fixed destination-port list.
- Regression coverage is in [test_signature.py](C:/NIDS_Workspace/tests/test_signature.py).

### 2. Old benchmark datasets can overstate results

Tavallaee et al. identify major redundancy issues in KDD Cup 99. Ring et al. emphasize evaluating dataset suitability explicitly. Sharafaldin et al. argue for more realistic traffic generation and updated attack coverage.

Repo impact:

- The current supervised model is still stronger as an engineering baseline than as a final research claim because it was bootstrapped from old-style labeled corpora and synthetic lab traffic.
- The right next step is to replace benchmark-heavy training with labeled lab traffic and real replay captures from this VM testbed.

### 3. Concept drift matters in live NIDS

The concept-drift literature is directly relevant to this repo because the runtime is live and long-lived, while the supervised model is static unless retrained manually.

Repo impact:

- We already added persistent unsupervised baselines and threshold-tuning reports, but there is no explicit drift-monitor or retraining trigger yet.
- A drift-report and retraining recommendation path should be added before making strong long-term deployment claims.

### 4. ML-based NIDS is vulnerable to adversarial evasion

Han et al. show that ML-based NIDS models are vulnerable to adversarial manipulation. This repo is hybrid, which helps, but the ML components still need explicit robustness testing.

Repo impact:

- Hybrid design remains the right direction because it reduces dependence on a single model.
- The repo still needs adversarial evaluation cases and robustness notes before claiming strong ML-NIDS resilience.

### 5. Host and network evidence need to stay correlated

The literature focuses heavily on network-only evaluation, but thesis-grade experimental work needs preserved host context too. For this repo, that means persistence artifacts, service state, cleanup state, and the sensor evidence should stay in the same result folder.

Repo action completed:

- [ubuntu_os_defense_validation.py](C:/NIDS_Workspace/scripts/ubuntu_os_defense_validation.py) now packages target-host artifacts and sensor artifacts together.
- The OS-defense runs now emit thesis-style `.docx` reports inside their result folders.

## Repo Actions Completed This Turn

1. Port-evasion hardening for suspicious HTTP detection
   Files:
   [signature.py](C:/NIDS_Workspace/src/NIDS/detect/signature.py)
   [rules.yml](C:/NIDS_Workspace/rules/rules.yml)
   [test_signature.py](C:/NIDS_Workspace/tests/test_signature.py)

2. Ubuntu OS-defense automation and thesis reporting
   Files:
   [ubuntu_os_defense_validation.py](C:/NIDS_Workspace/scripts/ubuntu_os_defense_validation.py)
   [RUN_UBUNTU_OS_DEFENSE_TEST.ps1](C:/NIDS_Workspace/NIDS_TestLab/RUN_UBUNTU_OS_DEFENSE_TEST.ps1)
   [os_defense_profile.yml](C:/NIDS_Workspace/NIDS_TestLab/config/os_defense_profile.yml)

3. Thesis-ready evidence outputs
   Successful cases:
   [ubuntu-os-cron-http-beacon-20260311-161200](C:/NIDS_Workspace/NIDS_TestLab/results/ubuntu-os-cron-http-beacon-20260311-161200)
   [ubuntu-os-systemd-dns-beacon-20260311-162948](C:/NIDS_Workspace/NIDS_TestLab/results/ubuntu-os-systemd-dns-beacon-20260311-162948)
   Preserved failed systemd iterations:
   [ubuntu-os-systemd-dns-beacon-20260311-165700](C:/NIDS_Workspace/NIDS_TestLab/results/ubuntu-os-systemd-dns-beacon-20260311-165700)
   [ubuntu-os-systemd-dns-beacon-20260311-170500](C:/NIDS_Workspace/NIDS_TestLab/results/ubuntu-os-systemd-dns-beacon-20260311-170500)

## Current Research-Relevant Gaps Still Open

1. The supervised model still depends too much on benchmark-style or synthetic labels.

2. There is no dedicated concept-drift monitor or retraining trigger yet.

3. There is no explicit adversarial-evaluation harness for the ML path yet.

4. Low-rate periodic beaconing is still under-tested even though the current `systemd + DNS beacon` burst-style case now passes.

## Next Recommended Research-Backed Implementations

1. Add a drift-report and retraining trigger for live runtime data.

2. Add a lower-rate DNS beacon / periodicity detector that is distinct from the current DNS burst threshold path.

3. Build labeled training data from this VM lab and replay corpus instead of relying mainly on old benchmark-derived data.

4. Add adversarial evaluation cases against the supervised ensemble and document the observed failure modes.

5. Continue moving protocol-aware detections away from fixed-port assumptions.
