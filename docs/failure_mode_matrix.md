# Failure Mode Matrix

## Purpose

This matrix formalizes how the current offline replay workflow is expected to behave under common failure conditions. It is a review aid and does not change runtime behavior.

| Failure mode | Trigger | Expected behavior | Current coverage | Gap |
|---|---|---|---|---|
| Missing replay input | `--pcap-dir` path missing | replay run fails early with readable error | `run_local_pipeline` input validation and tests in `tests/test_local_pipeline_runtime.py` | low |
| Missing rules file | rules path missing | replay run fails early with readable error | `run_local_pipeline` input validation | low |
| Non-fresh output directory | API `run-local` target already populated | controlled rejection to avoid mixed SQLite-backed artifacts | API wrapper validation in `src/NIDS/api/app.py` and tests | low |
| SQLite append drift | replay reuses old output directory | historical counts can mix; current docs require fresh output directory | documented in README and evaluation docs | medium: still policy/documentation dependent outside API path |
| Runtime stage failure | parser, storage, or runtime exception during local replay | `run-local` and helper paths should raise readable stage-specific failure | `src/NIDS/pipeline/runtime.py` wraps runtime/report/visualization stages | medium |
| Report generation failure | DB exists but markdown report generation fails | stage-specific error returned rather than silent success | `run_local_pipeline` report wrapper | low |
| Visualization failure | chart export fails | stage-specific failure returned in `run_local_pipeline`; scenario runner can skip visualization | runtime wrapper plus runner flag | low |
| Metrics generation failure | invalid or missing ground truth | evaluation stage fails clearly and does not silently fabricate metrics | `write_replay_metrics` and tests in `tests/test_replay_metrics.py` | low |
| Fusion trace generation failure | trace artifact missing or malformed | replay should still produce core outputs; aggregation should fall back cleanly | matrix aggregation records missing optional artifact notes | medium |
| Taxonomy mapping missing | scenario has no static mapping entry | taxonomy files still generate with explicit `unmapped` status and notes | `tests/test_taxonomy.py` | low |
| Robustness matrix partial artifacts | one scenario bundle lacks optional files | matrix generation continues with notes instead of crashing | `tests/test_robustness_matrix.py` | low |
| Comparison baseline mode failure | one ablation-mode run fails | comparison helper currently fails the study rather than emitting partial success | deterministic helper exists, but partial-mode continuation is not implemented | medium |
| Artifact triage failure | staged artifacts cannot be processed or reported | artifact-specific command failure should be visible in scenario logs and verdict | scenario runner command logs and artifact tests | medium |
| Malformed live-style input | malformed packets during prepared-environment validation | runtime should survive and continue processing valid traffic | documented prepared-environment evidence in `docs/testing_validation_master.md` | low for documented path, medium for broader untested malformed cases |
| API auth failure | missing or invalid `X-API-Key` | controlled `401` or `503` response | `tests/test_control_layer_api.py` | low |
| API rate limit failure | repeated calls to protected or bounded routes | controlled `429` JSON response | `tests/test_control_layer_api.py` | low |
| Partial bundle generation | scenario run produces some but not all expected artifacts | manifest, logs, and status should expose the partial state | scenario runner verdict logic and bundle logs | medium |

## Summary

The strongest current failure handling is around:

- early replay input validation
- API auth/rate limit control
- metrics artifact error handling
- matrix best-effort aggregation

The weakest current failure handling is around:

- partial continuation in multi-step comparison studies
- broader artifact/report partial-failure formalization
- enforcing fresh output discipline everywhere, not just through the API wrapper
