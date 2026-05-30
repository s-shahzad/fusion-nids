# Platform Support Matrix

Last audited: March 12, 2026

This matrix is based on code and script audit plus the current automated validation footprint. It reflects practical support, not theoretical Python portability.

## Summary

| Area | Windows | Linux | macOS | Notes |
|---|---|---|---|---|
| Core CLI, storage, reporting, artifact parsing, and visuals | Supported | Supported | Supported | Core code primarily uses `pathlib` and standard Python APIs. |
| Default fast pytest suite | Supported | Supported | Supported | No hardware capture required. |
| Live capture via Scapy interface sniffing | Conditional | Conditional | Conditional | Requires elevated permissions and interface-specific setup. |
| Live capture via `tcpdump` + FIFO | Not supported by code path | Supported | Conditional | `src/NIDS/ingest/live.py` explicitly disables `tcpdump` backend on `nt`; POSIX path requires `mkfifo` and a working `tcpdump`. |
| Dashboard API and export | Supported | Supported | Supported | `uvicorn`/FastAPI paths are cross-platform; browser/runtime dependencies still need local packaging validation. |
| VirtualBox / PowerShell lab orchestration | First-class host path | Partial | Partial | Current host automation is PowerShell-centric and Windows-focused. |
| Linux guest attack scripts and remote validation | Via hosted lab | First-class target path | Future target path | Remote scripts intentionally use `posixpath` and Linux command assumptions. |

## Findings by Platform

### Windows

Status: `supported for development, default testing, dashboard, and lab hosting`

Strengths:

- Current host environment and VirtualBox lab tooling are clearly optimized for Windows.
- PowerShell automation under `scripts/` and `NIDS_TestLab/` is strongest here.
- Default pytest, coverage, docs generation, artifact analysis, and dashboard paths work locally.

Constraints:

- `src/NIDS/ingest/live.py` intentionally falls back away from `tcpdump` because FIFO capture is not supported on `nt`.
- Several lab summaries and setup docs embed absolute Windows paths; this is operationally acceptable for the current host but not cross-platform-neutral.
- Some native dependencies such as `python-magic` remain packaging-sensitive on Windows hosts.

### Linux

Status: `supported for runtime and capture, partial for host-side lab orchestration`

Strengths:

- Runtime, storage, dashboard, and artifact paths are mostly platform-neutral.
- POSIX features needed by the `tcpdump`/FIFO backend are available.
- Remote validation scripts target Linux guests and are operationally aligned with Linux behavior.

Constraints:

- PowerShell/VirtualBox host automation is not maintained as a first-class Linux-host workflow.
- Host-side convenience scripts are Windows-oriented even when guest-side validation is Linux-focused.

### macOS

Status: `conditional for core runtime, partial for capture, not first-class for lab hosting`

Strengths:

- Core Python package layout should run where dependencies install cleanly.
- POSIX semantics mean the `tcpdump`/FIFO path is theoretically available if `tcpdump` and permissions are present.

Constraints:

- No dedicated macOS automation or target VM workflow exists in the current repo.
- Interface naming, permission model, and native dependency packaging need explicit validation.
- Existing lab plan treats macOS as future target coverage rather than active validated coverage.

## Known Portability Risks

| Risk ID | Area | Impact | Current state |
|---|---|---|---|
| PLAT-001 | `tcpdump` FIFO capture on Windows | Live backend unavailable | Handled by explicit fallback to Scapy |
| PLAT-002 | Absolute Windows paths in lab summaries/docs | Cosmetic or operator confusion on non-Windows hosts | Documented, not a core runtime blocker |
| PLAT-003 | PowerShell-only setup flows | Limits non-Windows host automation | Accepted for current lab design |
| PLAT-004 | Native dependency packaging (`python-magic`, packet capture stack) | Install friction across OSes | Requires environment-specific validation |
| PLAT-005 | Interface naming differences (`Ethernet`, `eth0`, `en0`) | Capture startup/operator error | Needs platform-specific operator guidance |

## Recommended Actions

1. Keep core runtime code path-neutral and continue using `pathlib` for file handling.
2. Treat Windows as the primary lab-host platform until host automation is generalized.
3. Validate Linux capture with real `tcpdump` and privilege boundaries before production deployment.
4. Add a macOS smoke validation pass only after packaging and interface assumptions are documented.
5. Keep environment-marked capture tests outside default CI.
