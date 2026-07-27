# Documentation

Single documentation tree. Three separate trees (`docs/`, `documentation/`,
`NIDS_Docs/`) used to exist with no indication which was canonical; they have
been merged here.

## Layout

| Directory | Contents |
|---|---|
| `architecture/` | System design, data flow, detection engines, ML pipeline, runtime execution, dependency inventory |
| `validation/` | Evidence and methodology: soak-claim audit, final baseline, experiments |
| `case_studies/` | Worked examples |
| `figures/` | Curated diagrams and showcase charts referenced from documentation |

## Start here

- **[architecture/system_architecture_overview.md](architecture/system_architecture_overview.md)** — the whole picture
- **[architecture/detection_engine_architecture.md](architecture/detection_engine_architecture.md)** — the four engines and the fusion layer
- **[validation/soak-claim-audit.md](validation/soak-claim-audit.md)** — what the soak result does and does not show. Read before citing any number from this project

## Read this before quoting results

The soak result (87,533 flows, 0 alerts) demonstrates **stability under sustained
load, not detection quality** — the run contained no attacks. `validation/soak-claim-audit.md`
exists specifically to prevent that misreading.

The project wiki carries the same material in a shorter form, including a
[Known Limitations](https://github.com/s-shahzad/fusion-nids/wiki/Known-Limitations)
page.

## Generated content

Chart and metric output under `reports/` is generated and untracked; see
`reports/README.md` for how to regenerate it. Curated figures worth keeping in
the repository live in `figures/`.
