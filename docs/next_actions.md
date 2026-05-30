# Next Actions

Phase 15A deployment-workflow preparation is complete. The next session should execute the first real Oracle Ubuntu VM validation run while keeping the clean active platform boundary, the lab-only adversary-emulation boundary, and the single-node deployment guardrails intact.

Priority order for the next session:

1. Copy `deployment/oracle_vm.env.example` to `deployment/oracle_vm.env`, fill in the Oracle VM host, user, SSH key path, and bounded project root, then keep the real file out of Git.
2. Create or confirm the Oracle Ubuntu VM, upload the SSH public key, and keep Oracle ingress limited to TCP `22` only.
3. Run `scripts/oracle_remote_bootstrap.ps1` from Windows PowerShell or `scripts/oracle_remote_bootstrap.sh` from a Bash-capable shell to install Docker, Docker Compose support, and the bounded `/opt/universal-nids/cloud_data` layout.
4. Execute one real replay validation run with `scripts/oracle_remote_run.ps1 -RunMode replay` or `scripts/oracle_remote_run.sh --run-mode replay` and one `lab_generated` bundle, using `rsync`, bundle upload, or remote `git` clone as the repo sync method.
5. Collect runtime logs, reports, manifests, and optionally runtime output with `scripts/oracle_remote_collect.ps1` or `scripts/oracle_remote_collect.sh`, then retain the resulting evidence under the bounded cloud storage layout.
6. Apply bounded cleanup with `scripts/oracle_remote_cleanup.ps1` or `scripts/oracle_remote_cleanup.sh` after collection, keeping reports and archives intact by default.
7. Collect storage-lifecycle evidence on the Oracle VM profile, including runtime output growth, report growth, replay staging turnover, archive size, and bounded cleanup behavior across a `20-50 GB` disk budget.
8. Decide the public versus private release boundary for retained evidence, generated indexes, manifests, and other internal-only research artifacts.
9. Close the remaining third-party distribution review, especially the `scapy` licensing decision for any future public or commercial packaging story.
10. Keep deployment claims conservative unless hot reload or equivalent zero-downtime maintenance is implemented.

## Nice-to-Have Follow-Ups

- Add an SSH config alias for the Oracle VM once the host key and public IP are stable.
- Add a compact cloud-run evidence checklist that pairs each staged replay bundle with retained runtime output, reports, manifests, and archive-closeout notes.
- Generate a machine-readable SBOM once the dependency review posture is settled.
- Prepare a sanitized public-facing research bundle only after the legal and packaging decisions are explicit.
