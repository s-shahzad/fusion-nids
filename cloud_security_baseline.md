# Cloud Security Baseline

This baseline is for the Universal NIDS single-node cloud validation profile.
It is conservative by design.

## Authentication

- Use SSH key authentication only.
- Do not enable password-based SSH login for the VM.
- Keep private keys on trusted administrator systems only.
- Rotate keys if a laptop, workstation, or shared admin host is compromised.

## Network Exposure

- Restrict inbound firewall rules to SSH only.
- Limit SSH to your source IP or VPN egress IP where possible.
- Keep the NIDS dashboard disabled by default.
- If the dashboard is needed, keep it loopback-bound and access it through SSH
  tunneling instead of public exposure.

## Storage

- Use encrypted disks where the provider supports it.
- Keep runtime outputs, logs, reports, replay inputs, and archives separated
  under the Phase 14B cloud storage boundary.
- Do not place secrets inside replay bundles, retained evidence, or report
  exports.

## Runtime Boundary

- Use the cloud-specific runtime profile:
  - [config/nids_cloud_single_node.yml](C:/NIDS_Workspace/config/nids_cloud_single_node.yml)
- Use the cloud-specific compose file:
  - [docker-compose.cloud-single-node.yml](C:/NIDS_Workspace/docker-compose.cloud-single-node.yml)
- Do not expose additional ports unless a specific validation need requires it
  and the change is documented.

## Outbound Traffic

- Keep outbound access limited to what the VM actually needs for:
  - package installation
  - Git clone or update
  - optional provider metadata and time sync
- Do not use the cloud VM for open internet scanning or external traffic
  generation.

## Operations

- Keep `.env` and provider credentials out of version control.
- Review `cloud_data/` usage regularly during larger validation runs.
- Archive only the evidence bundles that you need to retain.
- Clean replay staging after each completed remote replay validation.

## Lab-Only Scope

- Use only `lab_generated` replay bundles for adversary-lab scenarios.
- Keep remote validation bounded to the research environment you control.
- Do not treat this workflow as a public attack-simulation platform.
