# Hot/Cold Realtime Pipeline

The realtime lab now supports a minimal hot/cold split to keep latency-sensitive execution separate from heavier post-processing.

## Hot Path

- live packet capture
- existing runtime processing
- alert emission
- realtime metrics capture
- alert JSON output

## Cold Path

- incident report generation
- large realtime summary generation

## Design Notes

- queue/thread based only
- no Redis, Kafka, Celery, or external infrastructure
- detector, fusion, ML, and threshold behavior are unchanged
- cold task failure is observable but non-fatal to the runtime

## Current Limitation

The current cold path is intentionally narrow. It defers heavyweight artifact generation, not the core detection work itself.
