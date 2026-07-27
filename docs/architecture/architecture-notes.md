# Architecture Documentation

    Generated: 2026-03-11 23:08 UTC

    Universal NIDS is implemented as a layered platform inside `NIDS_Workspace`. Live capture, offline replay, adapter ingest, artifact intake, detection, storage, and visualization all converge into one repository-grounded workflow.

    ## Component Map

    - Ingest: `src/NIDS/ingest/live.py` and `src/NIDS/ingest/offline.py`
    - Parsing: `src/NIDS/pipeline/parser.py`
    - Feature extraction: `src/NIDS/pipeline/features.py`
    - Detection: `src/NIDS/detect/`
    - Storage: `src/NIDS/storage/`
    - Visualization: `src/NIDS/visuals/`
    - Artifact analysis: `src/NIDS/artifacts/`

    ## Feature Set

    The current supervised report exposes: packet_len, payload_len, src_port, dst_port, is_tcp, is_udp, is_icmp, tcp_syn, tcp_ack, packet_rate_dst, unique_dst_ports_src_window, unique_dst_hosts_src_window, has_dns_qname, has_http_host, has_tls_sni.

    ## Diagram Sources

    - `thesis/diagrams/system_architecture.mmd`
    - `thesis/diagrams/threat_workflow.mmd`

    ```mermaid
    flowchart LR
A[Live Capture] --> P[Parser and Feature Extraction]
B[Offline PCAP Replay] --> P
C[Suricata and Zeek Adapters] --> P
D[Artifact Intake] --> E[Artifact Parsers and Analyzer]
P --> F[Signature Engine]
P --> G[Statistical Anomaly Engine]
P --> H[ML Router]
H --> I[Supervised Ensemble]
H --> J[Unsupervised Hybrid Detector]
F --> K[Fusion Engine]
G --> K
I --> K
J --> K
K --> L[Alert Suppression and Storage]
L --> M[Dashboard, Charts, Reports]
E --> L
    ```

    ```mermaid
    flowchart TD
S1[1. Data ingestion] --> S2[2. Parsing and normalization]
S2 --> S3[3. Feature extraction]
S3 --> S4[4. Signature and anomaly analysis]
S4 --> S5[5. ML scoring]
S5 --> S6[6. Fusion decision]
S6 --> S7[7. Alert persistence]
S7 --> S8[8. Visualization and thesis evidence]
    ```
