# NIDS Architecture Diagram

This figure document captures the current repository architecture in publication-ready text form. It intentionally reflects the current validated system structure and the evidence-driven validation layer that surrounds it.

## ASCII Architecture Diagram

```text
                                      +----------------------------------+
                                      |      VALIDATION FRAMEWORK        |
                                      |----------------------------------|
                                      | Offline lab scenarios            |
                                      | Prepared-environment scenarios   |
                                      | Benign adjudication              |
                                      | Suppression validation           |
                                      | Soak validation                  |
                                      | Operator workflow validation     |
                                      +----------------+-----------------+
                                                       |
                                                       v
+--------------------+      +--------------------+      +---------------------------+
|    INPUT SOURCES   | ---> |    INGEST LAYER    | ---> | PARSER / NORMALIZATION    |
|--------------------|      |--------------------|      |---------------------------|
| Live NIC capture   |      | Live capture       |      | Packet parsing            |
| Offline PCAP replay|      | Offline replay     |      | Flow normalization        |
| Suricata ingest    |      | Adapter ingest     |      | Event shaping             |
| Zeek ingest        |      | Artifact intake    |      | Common schema output      |
| Artifact/file input|      +--------------------+      +-------------+-------------+
+--------------------+                                             |
                                                                   v
                                                     +---------------------------+
                                                     |    FEATURE EXTRACTION     |
                                                     |---------------------------|
                                                     | Flow features             |
                                                     | Statistical features      |
                                                     | ML-ready feature vectors  |
                                                     +-------------+-------------+
                                                                   |
                                                                   v
                                              +-------------------------------------------+
                                              |          DETECTION ENGINES                |
                                              |-------------------------------------------|
                                              | Signature detection                       |
                                              | Statistical anomaly detection             |
                                              | Supervised ML                             |
                                              | Optional unsupervised ML                  |
                                              | Fusion engine / alert adjudication        |
                                              +------------------+------------------------+
                                                                 |
                                                                 v
                              +----------------------------------+----------------------------------+
                              |                                 STORAGE                               |
                              |------------------------------------------------------------------------|
                              | SQLite                                                                 |
                              | JSONL evidence storage                                                 |
                              +----------------------------------+----------------------------------+
                                                                 |
                                                                 v
                                  +------------------------------+------------------------------+
                                  |                             OUTPUT                            |
                                  |---------------------------------------------------------------|
                                  | Dashboard                                                      |
                                  | Reports                                                        |
                                  | Evidence bundles                                               |
                                  +---------------------------------------------------------------+
```

## Mermaid Diagram

```mermaid
flowchart TB
    subgraph INPUT["INPUT SOURCES"]
        IN1["Live NIC capture"]
        IN2["Offline PCAP replay"]
        IN3["Suricata ingest"]
        IN4["Zeek ingest"]
        IN5["Artifact/file intake"]
    end

    subgraph INGEST["INGEST LAYER"]
        IG1["Live capture ingest"]
        IG2["Offline replay ingest"]
        IG3["External adapter ingest"]
        IG4["Artifact intake"]
    end

    subgraph PARSE["PARSER / NORMALIZATION"]
        PN1["Packet parsing"]
        PN2["Event normalization"]
        PN3["Common schema shaping"]
    end

    subgraph FEAT["FEATURE EXTRACTION"]
        FE1["Flow features"]
        FE2["Statistical features"]
        FE3["ML feature vectors"]
    end

    subgraph DET["DETECTION ENGINES"]
        DE1["Signature detection"]
        DE2["Statistical anomaly detection"]
        DE3["Supervised ML"]
        DE4["Optional unsupervised ML"]
        DE5["Fusion engine"]
    end

    subgraph STORE["STORAGE"]
        ST1["SQLite"]
        ST2["JSONL evidence storage"]
    end

    subgraph OUT["OUTPUT"]
        OU1["Dashboard"]
        OU2["Reports"]
        OU3["Evidence bundles"]
    end

    subgraph VAL["VALIDATION FRAMEWORK"]
        VA1["Offline lab scenarios"]
        VA2["Prepared-environment scenarios"]
        VA3["Benign adjudication"]
        VA4["Suppression validation"]
        VA5["Soak validation"]
        VA6["Operator workflow validation"]
    end

    INPUT --> INGEST --> PARSE --> FEAT --> DET --> STORE --> OUT
    VAL -.evidence and verification.-> INGEST
    VAL -.evidence and verification.-> DET
    VAL -.evidence and verification.-> OUT
```

## Figure Use Note

Use the ASCII version where monospaced diagrams are preferred and the Mermaid version where markdown rendering or conversion tooling is available.
