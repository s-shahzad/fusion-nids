# FastAPI authentication migration (M6)

Both `src.nids.api.app:create_app` and
`src.nids.api.production_app:create_app` use `PlatformSettings` and the same
read/action dependencies. The independent capture dashboard (`nids dashboard`)
is not one of these apps and keeps its existing dashboard token options.

## Operator migration

1. Replace `UNIVERSAL_NIDS_API_KEY` with `NIDS_API_TOKEN` (a nonempty secret).
2. Set a distinct `NIDS_ACTION_TOKEN` for privileged operations and explicitly
   set `NIDS_ALLOW_MUTATING_ROUTES=true` if those operations are needed.
3. Keep `NIDS_ALLOW_REMOTE_API=false` for loopback clients; enable it explicitly
   for remote clients. The production app also enforces `NIDS_TRUSTED_HOSTS`.
4. Restart the app after changing configuration. Settings are captured by each
   app factory; changing environment variables does not rotate a running app.
5. Migrate clients from `X-API-Key` to `X-API-Token` or `Authorization: Bearer`.
   Send `X-Action-Token` separately for privileged requests.

The legacy environment variable and header are no longer accepted. An old key
alone grants no access. Loopback no longer bypasses token checks. Empty and
whitespace-only configured tokens are treated as missing. Use HTTPS for remote
deployment because these are bearer credentials.

## Access rules

| Operation | Required authorization |
| --- | --- |
| `/status`, `/runs`, `/runs/{name}/summary`, `/runs/{name}/alerts`, `/runs/{name}/metrics` | Read token |
| `/v1/alerts/recent`, production `/health/ready` | Read token |
| `/run-local`, `/exports/portfolio-bundle`, `/v1/reports/incident` | Read token + action token + privileged operations enabled |
| `/runs/{name}/explain`, all `/llm/*` POSTs | Same privileged policy (provider calls can send data or incur cost) |
| Health/live, version, baseline, route listing, dashboard HTML, schema/docs | Public where implemented |

For every protected route, non-loopback callers are denied with 403 when remote
access is disabled. A missing read token configuration returns 503; missing or
incorrect supplied read credentials return 401. Privileged requests then check
the enablement gate (403), action configuration (503), and action credential
(401), in that order. Authentication completes before route work executes.

Bearer is exclusively a read credential. It never substitutes for or overrides
`X-Action-Token`. If both read headers are sent they must agree. A malformed
Authorization header is rejected even if `X-API-Token` is correct.

Example headers for a privileged request:

```http
Authorization: Bearer <read-secret>
X-Action-Token: <action-secret>
Content-Type: application/json
```

The control dashboard accepts credentials in password fields. Connect/refresh
loads protected data; action credentials are sent only with privileged requests.
Credentials stay in the current page and are not saved in browser storage or
URLs. Closing/reloading the page clears them.
