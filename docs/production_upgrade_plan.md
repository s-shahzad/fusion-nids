# Production-Style Upgrade Plan

## Objective

Upgrade `NIDS_Workspace` into a production-style, offline-first defensive platform without changing validated detection logic in:

- `src/NIDS/detect/`
- `src/NIDS/ml/`
- `src/NIDS/pipeline/`
- `src/NIDS/runtime.py`

The upgrade wraps existing logic with cleaner operational boundaries, stricter API patterns, environment-aware settings, and deployment scaffolding.

## Architecture Plan

### Preserve

- Signature, anomaly, supervised ML, unsupervised ML, and fusion behavior
- Existing CLI commands and dashboard behavior
- Existing SQLite-backed runtime outputs and reports

### Add Around The Core

1. Platform layer
   - Centralized settings from environment variables
   - Structured logging bootstrap
   - Shared error model and exception handlers
   - Health probes for liveness and readiness

2. Service layer
   - Runtime orchestration wrapper
   - Reporting and alert retrieval service
   - Health/status aggregation service
   - Run inspection service for validated replay outputs
   - Portfolio export service for public-safe bundles
   - Optional local AI explainer service using Ollama with deterministic fallback

3. API boundary
   - Versioned production router
   - Token-based route protection
   - Local-only default access model
   - Restricted mutating routes
   - Pydantic request validation

4. Storage abstraction
   - Protocol/interface for alert/report storage
   - SQLite remains primary
   - PostgreSQL preparation stub with explicit parity target

5. Deployment boundary
   - Environment-specific config examples
   - Production Dockerfile / compose scaffold
   - Local deployment, controlled cloud deployment, and rollback docs

## Service Boundaries

- Detection Core: existing pipeline and detector modules
- Runtime Service: controlled execution of validated pipeline entrypoints
- Alert Service: read-focused access to alerts and run metadata
- Reporting Service: generation/export of incident and summary outputs
- Run Inspection Service: read-only access to stored run summaries, alerts, distributions, and baseline comparison
- Export Service: bounded generation of portfolio-safe case-study artifacts
- Explainer Service: local explanation only, isolated from detection and replay execution
- Health Service: dependency and storage readiness checks
- API Layer: secure, validated access to the services above

## Proposed Folder Structure

```text
src/NIDS/
  api/
    app.py                      # existing lightweight API/dashboard app
    assist.py                   # existing assist endpoints
    dashboard_page.py           # control-layer dashboard page
    dependencies.py             # new auth/local-only dependencies
    production_app.py           # new production FastAPI app factory
    router_v1.py                # new secured versioned routes
  ai/
    providers/
      base.py
      ollama_provider.py
    services/
      explainer_service.py
  detect/                       # unchanged validated detection logic
  ml/                           # unchanged validated ML logic
  pipeline/                     # unchanged validated pipeline logic
  platform/
    __init__.py
    errors.py
    health.py
    logging_config.py
    settings.py
  services/
    __init__.py
    health_service.py
    export_service.py
    report_service.py
    run_inspection_service.py
    runtime_service.py
  storage/
    __init__.py
    base.py
    jsonl_store.py              # existing
    incident_store.py           # existing
    postgres_store.py           # new migration-prep scaffold
    sqlite_store.py             # existing primary store

config/
  environments/
    local.yml.example
    cloud-controlled.yml.example

deployment/
  Dockerfile.production
  docker-compose.production.yml

docs/
  production_upgrade_plan.md
  deployment_local.md
  deployment_controlled_cloud.md
  rollback_plan.md

scripts/
  run_production_api.py
```

## Milestone Roadmap

1. Platform Foundation
   - Add settings, logging, errors, and health scaffolding
   - No detector behavior changes

2. Secure API Boundary
   - Add versioned production API
   - Enforce local-only default and token auth

3. Control Layer
   - Add read-only run inspection endpoints
   - Add bounded portfolio export generation
   - Add optional Ollama explanations with deterministic fallback
   - Restrict mutating routes by policy toggle

3. Storage Abstraction
   - Define storage protocol
   - Keep SQLite active
   - Add PostgreSQL compatibility stub

4. Deployment Hardening
   - Add environment examples
   - Add production Docker assets
   - Document local and controlled cloud rollouts

5. Controlled Migration
   - Introduce PostgreSQL implementation behind interface
   - Add data migration tooling later
   - Keep SQLite fallback path until parity is proven

## Non-Goals

- No changes to validated detector thresholds or fusion math
- No offensive capabilities
- No default internet dependency
- No forced database migration in this phase

## Immediate Scaffold Deliverables

- Production app factory
- Secure dependencies and route skeleton
- Service wrappers
- Storage abstraction
- PostgreSQL prep stub
- Deployment and rollback documentation
