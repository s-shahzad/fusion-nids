# Security Policy

## Reporting a Vulnerability

To report a security vulnerability in NIDS, email:

**shaikazhadshahzad@gmail.com**

Include:
- Description of the vulnerability
- Steps to reproduce
- Potential impact

Expect a response within 7 days. Please do not open a public GitHub issue for security vulnerabilities.

## Scope

This policy covers:
- The NIDS core detection engine (`src/NIDS/`)
- The REST API (`src/NIDS/api/`)
- Lab scripts (`scripts/`, `NIDS_TestLab/`)

## Security Notes

- The API is designed for **local use only** (127.0.0.1). Do not expose it publicly without adding authentication middleware.
- LLM endpoints (`/llm/*`) are rate-limited but unauthenticated; suitable for localhost deployment only.
- Lab scripts require separate VM credentials supplied via `LAB_VM_PASS` environment variable — no defaults are hardcoded.
