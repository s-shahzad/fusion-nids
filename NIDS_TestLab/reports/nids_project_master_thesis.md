# 1. Title Page

## Project Title
Universal Hybrid Network Intrusion Detection System for Live, Offline, and Multi-Format Threat Analysis

## Author
Shaik

## Institution
Institution to be updated

## Supervisor
Supervisor to be updated

## Date
March 11, 2026

## Project Version
research-snapshot-2026.03.11

# 2. Abstract

Universal NIDS addresses the practical gap between traditional packet-centric intrusion-detection systems and the heterogeneous evidence generated in modern security operations. The implemented system in `NIDS_Workspace` combines live monitoring, offline replay, artifact triage, supervised learning, unsupervised anomaly scoring, fusion-based alerting, visualization, and thesis-grade evidence retention. The runtime supports live interfaces, offline PCAPs, optional Suricata and Zeek adapters, and static handling of CSV, DOCX / Word documents, HTML, JSON, PDF, PE / EXE files, Python scripts, XLSX spreadsheets, ZIP archives. Rather than relying on a single classifier, the current system combines signature logic, statistical anomaly detection, a supervised ensemble, optional unsupervised scoring, and a weighted fusion engine. On the current benchmark-derived labeled flow corpus of 25000 samples, the supervised path achieved training accuracy 0.99536 and weighted F1 0.99560; the recorded evaluation run achieved accuracy 0.99784 and weighted F1 0.99792. Experimental evidence in the isolated VirtualBox lab confirms detection of web-path abuse, DNS bursts, brute-force activity, port scanning, DoS-rate anomalies, and 3 completed OS-defense cases. The main research contribution is therefore a real repository-grounded hybrid NIDS and a continuously updated thesis record that preserves both successful detections and unresolved gaps.

# 3. Introduction

## 3.1 Background
Network intrusion detection is still a central cybersecurity problem because defenders must classify legitimate and malicious activity under high traffic volume, protocol diversity, and incomplete labels. Foundational work established the value of real-time protocol-aware monitoring and operational IDS design [1]-[3].

## 3.2 Motivation
Modern security work rarely involves packets alone. Analysts must correlate PCAPs, logs, documents, scripts, executables, and model outputs. This repository was built to keep those evidence paths inside one system and one research narrative.

## 3.3 Need for an Advanced NIDS
The literature shows that fixed signatures alone are insufficient, while pure anomaly models and purely supervised models also have clear weaknesses [4]-[8]. A hybrid architecture is therefore justified for this project.

## 3.4 Research Objective Statement
The research objective is to build and continuously document a universal hybrid NIDS that supports heterogeneous data, live and offline analysis, machine-learning-assisted detection, and reproducible attack evidence.

# 4. Problem Statement

## 4.1 Heterogeneous Inputs
Problem: security evidence arrives in many formats.
Impact: analysts lose context when network and file evidence are separated.
Existing Limitation: many IDS workflows only inspect traffic or only inspect files.
Need for Improvement: one architecture should process both streams.

## 4.2 Real-Time Detection Constraints
Problem: live scoring must remain fast enough for operational use.
Impact: expensive scoring can degrade alert quality under load.
Existing Limitation: single-engine designs are either too narrow or too fragile.
Need for Improvement: hybrid detection with selective scoring is required.

## 4.3 Labeled-Data Dependence
Problem: benchmark-driven accuracy can overstate deployment readiness.
Impact: models may not transfer cleanly to live environments.
Existing Limitation: many IDS claims rely on data with realism limitations.
Need for Improvement: labeled and unlabeled paths must coexist.

## 4.4 Research Traceability
Problem: security experiments often lose failed runs.
Impact: reviewers cannot verify what was fixed and what remains open.
Existing Limitation: engineering notes, metrics, and screenshots are usually fragmented.
Need for Improvement: the thesis record must evolve with the repository.

# 5. Research Objectives

1. Build a universal NIDS for live and offline monitoring.
2. Support heterogeneous file and network evidence.
3. Implement hybrid detection instead of a single-model pipeline.
4. Preserve an evidence trail for attack testing, malware triage, and OS-defense validation.
5. Provide visualization, reporting, and reproducible research outputs.
6. Keep the architecture modular and scalable.

# 6. Literature Review

## 6.1 Signature and Protocol-Aware IDS
Early work by Paxson and later operational guidance from NIST demonstrate why protocol-aware inspection is foundational for practical intrusion detection [1][2]. Dreger et al. further showed that application-layer analysis must not rely blindly on destination ports [3].

## 6.2 Dataset Realism and Machine Learning
Tavallaee et al., Sharafaldin et al., and Ring et al. collectively show that data quality, traffic realism, and benchmark diversity strongly influence IDS claims [4][5][6]. This is directly relevant because the current supervised model still depends on benchmark-derived training data.

## 6.3 Online Anomaly Detection and Representation Learning
Kitsune is relevant because it demonstrates that lightweight representation learning can be used for online intrusion detection [7]. The present repository takes a pragmatic hybrid route rather than claiming a full deep-learning runtime.

## 6.4 Concept Drift
Recent work on concept drift indicates that intrusion-detection models must adapt to changing traffic distributions [8]. This remains future work in the current repository.

## 6.5 Research Inference
Taken together, these sources imply that no single detector family is sufficient. This thesis therefore adopts a hybrid design as an explicit inference from the literature.

# 7. System Architecture

## 7.1 System Layers
The system is organized into ingestion, parsing, feature extraction, detection, storage, and visualization layers.

## 7.2 Offline Pipeline
Offline PCAP replay enters through `src/NIDS/ingest/offline.py`, then follows the same parsing and detection path as live traffic.

## 7.3 Live Monitoring Pipeline
Live capture enters through `src/NIDS/ingest/live.py`, is normalized by the pipeline, scored by multiple engines, and persisted to SQLite and JSONL outputs.

## 7.4 Component Interaction
Runtime coordination is centered in `src/NIDS/runtime.py`, with detection modules in `src/NIDS/detect/`, storage in `src/NIDS/storage/`, and visualization in `src/NIDS/visuals/`.

## 7.5 Diagram Sources
- `thesis/diagrams/system_architecture.mmd`
- `thesis/diagrams/threat_workflow.mmd`

# 8. Data Handling and Classification

## 8.1 Multi-Format Support
The system currently supports CSV, DOCX / Word documents, HTML, JSON, PDF, PE / EXE files, Python scripts, XLSX spreadsheets, ZIP archives, plus logs, live packets, offline PCAPs, and adapter JSON feeds.

## 8.2 Parsing and Normalization
Artifact parsers operate in `src/NIDS/artifacts/parsers/`, while network normalization is handled by `src/NIDS/pipeline/parser.py`.

## 8.3 Feature Extraction
The current feature set includes packet_len, payload_len, src_port, dst_port, is_tcp, is_udp, is_icmp, tcp_syn, tcp_ack, packet_rate_dst, unique_dst_ports_src_window, unique_dst_hosts_src_window, has_dns_qname, has_http_host, has_tls_sni.

## 8.4 Labeled and Unlabeled Paths
Labeled flow data supports supervised training and evaluation, while unlabeled traffic can be scored through the unsupervised path with warmup calibration and baseline persistence.

# 9. Detection Algorithms

## 9.1 Signature Rules
YAML-driven signature rules provide deterministic detection of known malicious patterns.

## 9.2 Statistical Anomaly Detection
Threshold logic, EWMA-style behavior, z-score logic, and DNS burst handling provide fast interpretable streaming detection.

## 9.3 Supervised Ensemble
The current active supervised ensemble uses random_forest, extra_trees, hist_gradient_boosting, xgboost.

## 9.4 Unsupervised Hybrid Detection
The optional unsupervised path combines Isolation Forest with a shallow autoencoder.

## 9.5 Fusion
The fusion engine combines signature, anomaly, supervised, and unsupervised signals into one final decision.

# 10. Threat Detection Workflow

1. Ingest data from a live interface, offline PCAP, or adapter source.
2. Parse and normalize the event.
3. Extract features.
4. Evaluate signature and anomaly rules.
5. Score the event with supervised and optional unsupervised ML.
6. Fuse the active signals.
7. Persist alerts, flows, and metrics.
8. Expose the result to reports, charts, dashboards, and thesis evidence.

# 11. Graphical Threat Pattern Analysis

## 11.1 Offline Analytics
`src/NIDS/visuals/charts.py` and `src/NIDS/visuals/export.py` support chart generation and evidence packaging.

## 11.2 Live Dashboard
`src/NIDS/visuals/dashboard.py` exposes rolling metrics, alerts, sensor comparison, and incident-oriented views.

## 11.3 Analyst Value
Visualization improves interpretability by showing how multiple detectors align across time and severity.

# 12. Implementation Details

## 12.1 Languages and Core Modules
The project is primarily implemented in Python under `src/NIDS/`.

## 12.2 Frameworks and Libraries
The active dependency set includes scapy>=2.5.0, PyYAML>=6.0.1, rich>=13.7.1, fastapi>=0.115.0, uvicorn[standard]>=0.30.6, joblib>=1.4.2, numpy>=1.26.4, pytest>=8.3.2, plotly>=5.24.1, pandas>=2.2.2, kaleido>=0.2.1, pypdf>=5.1.0, python-docx>=1.1.2, openpyxl>=3.1.5, beautifulsoup4>=4.12.3, lxml>=5.3.0, pefile>=2024.8.26, scikit-learn>=1.5.2, python-magic>=0.4.27, xgboost>=3.2.0.

## 12.3 Storage and Reporting
SQLite and JSONL are the primary runtime outputs, while Markdown and DOCX support formal reporting.

## 12.4 Tooling
Testing is performed with `pytest`; visualization relies on Plotly and Kaleido; dashboard services use FastAPI and Uvicorn.

# 13. Experimental Evaluation

## 13.1 Datasets and Evidence Sources
The current supervised path is still trained on benchmark-derived data, while experimental validation also uses offline replay, live VM lab scenarios, and static artifact families.

## 13.2 Metrics
The recorded metrics include accuracy, weighted precision, weighted recall, weighted F1, and confusion matrices.

## 13.3 Performance Summary
- Training samples: 25000
- Training accuracy: 0.99536
- Training weighted F1: 0.99560
- Evaluation samples: 25000
- Evaluation accuracy: 0.99784
- Evaluation weighted F1: 0.99792

## 13.4 Validated Cases
- HTTP suspicious keyword / web-shell style request: pass
- DNS burst / DGA-like activity: pass
- SSH brute force: pass
- RDP brute force: pass
- HTTP login brute force: pass
- Port scan signature and anomaly threshold: pass
- DoS / packet-rate threshold: pass

## 13.5 Static and OS Evidence
- phishing docs / scripts: pass
- PE droppers / loaders: pass
- credential stealer: pass
- RAT / backdoor: pass
- ransomware: pass
- Ubuntu cron persistence + suspicious HTTP beacon: pass
- Ubuntu systemd persistence + DNS beacon: pass
- Ubuntu defense-tamper simulation + service-stop intent: pass

## 13.6 Concurrent Overlap Evidence
- live-multi-attack-20260311-141800: blocked - 0 flows and 0 alerts; HTTP helper path regression or runtime issue
- live-multi-attack-no-http-20260311-142600: partial - 81 flows and 2 alerts; only Suspicious Port Scan survived concurrent overlap
- live-multi-attack-balanced-20260311-142900: partial - 26 flows and 1 alert; only Suspicious Port Scan survived concurrent overlap
- live-multi-attack-fixed-20260311-144100: partial - 340 flows and 1 alert; DoS survived concurrent overlap after the UDP sink and repaired HTTP helper path
- live-multi-attack-overlap-20260311-145000: partial - 70 flows and 1 alert; DNS Burst survived concurrent overlap with lighter composition
- live-multi-attack-dns-http-scan-20260311-145300: partial - 49 flows and 3 alerts; DNS Burst, Suspicious Port Scan, and Hybrid Fusion Decision fired in the same mixed run

# 14. Improvements Over Existing Systems

## 14.1 Multi-Format Ingestion
Problem: traditional IDS platforms rarely unify packets and suspicious files.
Previous Limitation: analysts must switch tools.
Proposed Solution: implemented artifact intake plus network pipelines.
Result: one workspace now preserves both contexts.

## 14.2 Hybrid Detection
Problem: no single detector family is sufficient.
Previous Limitation: rule-only and model-only designs both miss important behaviors.
Proposed Solution: signature, anomaly, supervised, unsupervised, and fusion logic are combined.
Result: the runtime can preserve deterministic alerts while still handling unknown patterns.

## 14.3 Evidence Preservation
Problem: failed detections are often lost.
Previous Limitation: security projects over-report only successful cases.
Proposed Solution: coverage matrix, test ledger, OS-defense plan, and thesis outputs are maintained together.
Result: the current project keeps both passes and misses in scope.

# 15. Current System Version

## 15.1 Version
research-snapshot-2026.03.11

## 15.2 Completed Modules
- Live and offline runtime
- Signature, anomaly, supervised, unsupervised, and fusion detection
- SQLite and JSONL persistence
- Static artifact triage
- Dashboard and chart export
- Attack-lab evidence ledger and thesis documentation

## 15.3 Modules Under Development
- Lower-rate periodic beacon detection and C2-oriented beacon analysis beyond the current burst-style DNS validation
- More same-window multi-attack validation
- Real-sample malware execution only inside the isolated lab
- Next OS-defense focus: Ubuntu staged archive exfil over HTTP or DNS

# 16. Future Work

## 16.1 Remaining Attack Families
- SQL injection / web exploit
- Beaconing / C2
- Exfiltration
- Lateral movement
- Low-and-slow stealth scan
- Worm / self-propagation
- real RAT/backdoor samples
- real ransomware samples
- real credential-stealer samples
- load/stress testing

## 16.2 Remaining OS Cases
- Ubuntu staged archive exfil over HTTP or DNS
- Windows safe-only posture validation on the host
- Windows full attack-and-defense validation after a dedicated VM is added
- macOS target validation after a dedicated VM is added

## 16.3 Research Expansion
Future work should add drift handling, adversarial evaluation, SIEM integration, distributed deployment, and deeper sequence-aware models only where the data justifies them.

# 17. Conclusion

Universal NIDS is no longer just a detection script; it is a repository-grounded hybrid research platform. Its current value lies in the combination of operational code, measurable evaluation, isolated-lab validation, and honest preservation of unresolved gaps.

# 18. References

[1] V. Paxson, "Bro: A System for Detecting Network Intruders in Real-Time," USENIX Security Symposium, 1998. URL: https://www.usenix.org/legacy/publications/library/proceedings/sec98/full_papers/paxson/paxson.pdf
[2] K. Scarfone and P. Mell, Guide to Intrusion Detection and Prevention Systems (IDPS), NIST SP 800-94, 2007. URL: https://csrc.nist.gov/pubs/sp/800/94/final
[3] H. Dreger, A. Feldmann, V. Paxson, and R. Sommer, "Dynamic Application-Layer Protocol Analysis for Network Intrusion Detection," USENIX Security Symposium, 2006. URL: https://www.usenix.org/legacy/events/sec06/tech/full_papers/dreger/dreger.pdf
[4] M. Tavallaee, E. Bagheri, W. Lu, and A. A. Ghorbani, "A Detailed Analysis of the KDD CUP 99 Data Set," IEEE CISDA, 2009. URL: https://www.ee.torontomu.ca/~bagheri/papers/cisda.pdf
[5] I. Sharafaldin, A. H. Lashkari, and A. A. Ghorbani, "Toward Generating a New Intrusion Detection Dataset and Intrusion Traffic Characterization," ICISSP, 2018. URL: https://www.scitepress.org/Papers/2018/66398/66398.pdf
[6] M. Ring, S. Wunderlich, D. Scheuring, D. Landes, and A. Hotho, "A Survey of Network-based Intrusion Detection Data Sets," Computers & Security, 2019. URL: https://arxiv.org/abs/1903.02460
[7] Y. Mirsky, T. Doitshman, Y. Elovici, and A. Shabtai, "Kitsune: An Ensemble of Autoencoders for Online Network Intrusion Detection," NDSS, 2018. URL: https://www.ndss-symposium.org/ndss-paper/kitsune-an-ensemble-of-autoencoders-for-online-network-intrusion-detection/
[8] S. Seth, "Concept Drift-Based Intrusion Detection Using Incremental Learning," The Computer Journal, 2024. URL: https://academic.oup.com/comjnl/article-abstract/67/7/2529/7618465
