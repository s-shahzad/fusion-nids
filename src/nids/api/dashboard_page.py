from __future__ import annotations


def render_dashboard_html(default_run_name: str | None = None) -> str:
    run_value = default_run_name or ""
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Universal NIDS Control Layer</title>
  <style>
    :root {{
      color-scheme: light;
      --bg: #f4f0e8;
      --panel: #fffdf8;
      --ink: #1e1a16;
      --muted: #6a6359;
      --line: #ddd0bd;
      --accent: #0f6a57;
      --accent-soft: #ddf0ea;
    }}
    * {{ box-sizing: border-box; }}
    body {{
      margin: 0;
      background: radial-gradient(circle at top, #efe4d0 0%, var(--bg) 48%);
      color: var(--ink);
      font: 15px/1.55 Georgia, "Times New Roman", serif;
    }}
    .page {{
      max-width: 1240px;
      margin: 0 auto;
      padding: 28px 18px 48px;
      display: grid;
      gap: 18px;
    }}
    .hero, .panel {{
      background: rgba(255, 253, 248, 0.96);
      border: 1px solid var(--line);
      border-radius: 18px;
      box-shadow: 0 12px 30px rgba(58, 42, 24, 0.08);
    }}
    .hero {{
      padding: 26px 22px;
      display: grid;
      gap: 10px;
    }}
    h1, h2, h3 {{ margin: 0; line-height: 1.1; }}
    h1 {{ font-size: 2.2rem; }}
    h2 {{ font-size: 1.15rem; margin-bottom: 12px; }}
    p {{ margin: 0; }}
    .lead {{ color: var(--muted); max-width: 800px; }}
    .grid {{
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
      gap: 14px;
    }}
    .panel {{ padding: 18px; }}
    .stat {{
      border: 1px solid var(--line);
      border-radius: 12px;
      padding: 12px;
      background: #fff;
    }}
    .label {{ color: var(--muted); font-size: 0.8rem; text-transform: uppercase; letter-spacing: 0.04em; }}
    .value {{ font-size: 1.45rem; font-weight: 700; margin-top: 4px; }}
    .tools {{
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
      gap: 12px;
      align-items: end;
    }}
    label {{
      display: grid;
      gap: 6px;
      font-weight: 700;
    }}
    input, select {{
      width: 100%;
      padding: 10px 12px;
      border: 1px solid var(--line);
      border-radius: 10px;
      background: #fff;
      color: var(--ink);
    }}
    button {{
      padding: 10px 14px;
      border: 0;
      border-radius: 10px;
      background: var(--accent);
      color: #fff;
      font-weight: 700;
      cursor: pointer;
    }}
    .btn-row {{
      display: flex;
      flex-wrap: wrap;
      gap: 10px;
      margin-top: 10px;
    }}
    .kv {{
      display: grid;
      grid-template-columns: auto 1fr;
      gap: 6px 10px;
    }}
    .kv dt {{ color: var(--muted); }}
    .kv dd {{ margin: 0; word-break: break-word; }}
    table {{
      width: 100%;
      border-collapse: collapse;
      font-size: 0.94rem;
    }}
    th, td {{
      text-align: left;
      padding: 10px 8px;
      border-bottom: 1px solid var(--line);
      vertical-align: top;
    }}
    th {{ color: var(--muted); font-weight: 700; }}
    .mono {{ font-family: Consolas, monospace; font-size: 0.92em; }}
    .pill {{
      display: inline-block;
      margin: 3px 6px 0 0;
      padding: 4px 8px;
      border-radius: 999px;
      background: var(--accent-soft);
      color: var(--accent);
      font-size: 0.82rem;
      font-weight: 700;
    }}
    .muted {{ color: var(--muted); }}
    .error {{
      display: none;
      border: 1px solid #e2b9b2;
      background: #fff2ef;
      color: #8b3025;
      border-radius: 12px;
      padding: 12px;
    }}
    pre {{
      margin: 0;
      white-space: pre-wrap;
      background: #fbf7f0;
      border: 1px solid var(--line);
      border-radius: 12px;
      padding: 14px;
      font: 13px/1.55 Consolas, monospace;
    }}
  </style>
</head>
<body>
  <main class="page">
    <section class="hero">
      <h1>Universal NIDS Control Layer</h1>
      <p class="lead">Read-only inspection and public-safe export surface around the validated hybrid NIDS. The detector, tuned ML confirmation, fusion agreement rules, and CLI workflow remain unchanged.</p>
      <div class="grid">
        <div class="stat"><div class="label">Validated flows</div><div id="baseline-flows" class="value">-</div></div>
        <div class="stat"><div class="label">Validated alerts</div><div id="baseline-alerts" class="value">-</div></div>
        <div class="stat"><div class="label">Alert ratio</div><div id="baseline-ratio" class="value">-</div></div>
        <div class="stat"><div class="label">Fusion agreement</div><div id="baseline-fusion" class="value">-</div></div>
      </div>
    </section>

    <section class="panel">
      <h2>Run Control</h2>
      <div class="tools">
        <label>Run name
          <select id="run-select"></select>
        </label>
        <label>Manual run name
          <input id="run-name" value="{run_value}" placeholder="api-run-local-auth-ok-20260319-151038">
        </label>
        <label>Alert limit
          <input id="alert-limit" type="number" min="1" max="25" value="10">
        </label>
        <label>Compare run
          <select id="compare-run"><option value="">None</option></select>
        </label>
      </div>
      <div class="btn-row">
        <button id="inspect-btn" type="button">Inspect run</button>
        <button id="explain-btn" type="button">Explain run</button>
        <button id="export-btn" type="button">Export portfolio bundle</button>
      </div>
      <div id="error-box" class="error" aria-live="polite"></div>
    </section>

    <section class="grid">
      <section class="panel">
        <h2>Recent Runs</h2>
        <div id="recent-runs" class="muted">Loading…</div>
      </section>
      <section class="panel">
        <h2>Run Summary</h2>
        <dl id="run-summary" class="kv"></dl>
      </section>
      <section class="panel">
        <h2>Run Metrics</h2>
        <div id="metric-pills"></div>
        <dl id="baseline-comparison" class="kv" style="margin-top:12px;"></dl>
      </section>
    </section>

    <section class="grid">
      <section class="panel">
        <h2>Alert Table</h2>
        <table>
          <thead>
            <tr>
              <th>Timestamp</th>
              <th>Severity</th>
              <th>Engine</th>
              <th>Rule</th>
              <th>Summary</th>
            </tr>
          </thead>
          <tbody id="alerts-body"></tbody>
        </table>
      </section>
      <section class="panel">
        <h2>Explanation</h2>
        <div id="explain-meta" class="muted">No explanation generated yet.</div>
        <pre id="explain-text">Select a run and choose Explain run.</pre>
      </section>
    </section>

    <section class="grid">
      <section class="panel">
        <h2>Engine Distribution</h2>
        <div id="engine-distribution" class="muted">No data loaded yet.</div>
      </section>
      <section class="panel">
        <h2>Severity Distribution</h2>
        <div id="severity-distribution" class="muted">No data loaded yet.</div>
      </section>
      <section class="panel">
        <h2>Export Status</h2>
        <pre id="export-result">No export created yet.</pre>
      </section>
    </section>
  </main>
  <script>
    async function fetchJson(url, options) {{
      const response = await fetch(url, Object.assign({{ headers: {{ Accept: "application/json" }} }}, options || {{}}));
      const payload = await response.json().catch(() => ({{}}));
      if (!response.ok) {{
        throw new Error(payload.detail || payload.message || "Request failed.");
      }}
      return payload;
    }}

    function activeRunName() {{
      const select = document.getElementById("run-select");
      const manual = document.getElementById("run-name").value.trim();
      return manual || select.value;
    }}

    function renderKv(target, rows) {{
      target.innerHTML = rows.map(([k, v]) => `<dt>${{k}}</dt><dd>${{v ?? ""}}</dd>`).join("");
    }}

    function renderDistribution(targetId, data) {{
      const target = document.getElementById(targetId);
      const entries = Object.entries(data || {{}});
      if (!entries.length) {{
        target.innerHTML = '<span class="muted">No data</span>';
        return;
      }}
      target.innerHTML = entries.map(([key, value]) => `<span class="pill">${{key}}: ${{value}}</span>`).join("");
    }}

    function showError(message) {{
      const box = document.getElementById("error-box");
      box.textContent = message;
      box.style.display = "block";
    }}

    function clearError() {{
      const box = document.getElementById("error-box");
      box.textContent = "";
      box.style.display = "none";
    }}

    async function loadRuns() {{
      const payload = await fetchJson("/runs?limit=12");
      const runs = payload.runs || [];
      const select = document.getElementById("run-select");
      const compare = document.getElementById("compare-run");
      select.innerHTML = runs.map((item) => `<option value="${{item.run_name}}">${{item.run_name}}</option>`).join("");
      compare.innerHTML = '<option value="">None</option>' + runs.map((item) => `<option value="${{item.run_name}}">${{item.run_name}}</option>`).join("");
      if (!document.getElementById("run-name").value && runs.length) {{
        document.getElementById("run-name").value = runs[0].run_name;
      }}
      document.getElementById("recent-runs").innerHTML = runs.map((item) =>
        `<div><strong>${{item.run_name}}</strong> <span class="muted">flows=${{item.flows}} alerts=${{item.alerts}} status=${{item.status}}</span></div>`
      ).join("");
    }}

    async function loadBaseline() {{
      const baseline = await fetchJson("/baseline");
      document.getElementById("baseline-flows").textContent = baseline.validated_result.flows;
      document.getElementById("baseline-alerts").textContent = baseline.validated_result.alerts;
      document.getElementById("baseline-ratio").textContent = baseline.validated_result.alert_ratio;
      document.getElementById("baseline-fusion").textContent = baseline.fusion.min_agreement_count;
    }}

    async function inspectRun() {{
      clearError();
      const runName = activeRunName();
      const limit = Math.max(1, Math.min(25, Number(document.getElementById("alert-limit").value || 10)));
      if (!runName) {{
        showError("Enter or select a run name first.");
        return;
      }}
      document.getElementById("run-name").value = runName;
      const [summary, alerts, metrics] = await Promise.all([
        fetchJson(`/runs/${{encodeURIComponent(runName)}}/summary`),
        fetchJson(`/runs/${{encodeURIComponent(runName)}}/alerts?limit=${{limit}}`),
        fetchJson(`/runs/${{encodeURIComponent(runName)}}/metrics`),
      ]);
      renderKv(document.getElementById("run-summary"), [
        ["Run", summary.run_name],
        ["Output", summary.output_dir],
        ["Flows", summary.flows],
        ["Alerts", summary.alerts],
        ["Report", summary.report_path || "Unavailable"],
        ["Visuals", summary.visuals_path || "Unavailable"],
        ["Status", summary.status],
      ]);
      renderKv(document.getElementById("baseline-comparison"), [
        ["Matches validated baseline", String(metrics.baseline_comparison.matches_validated_result)],
        ["Flow delta", metrics.baseline_comparison.delta.flows],
        ["Alert delta", metrics.baseline_comparison.delta.alerts],
        ["Alert ratio delta", metrics.baseline_comparison.delta.alert_ratio],
      ]);
      document.getElementById("metric-pills").innerHTML =
        `<span class="pill">flows=${{metrics.flows}}</span><span class="pill">alerts=${{metrics.alerts}}</span>`;
      renderDistribution("engine-distribution", metrics.engine_distribution);
      renderDistribution("severity-distribution", metrics.severity_distribution);
      const tbody = document.getElementById("alerts-body");
      tbody.innerHTML = (alerts.alerts || []).map((item) =>
        `<tr><td class="mono">${{item.timestamp || ""}}</td><td>${{item.severity || ""}}</td><td>${{item.engine || ""}}</td><td>${{item.rule_name || ""}}</td><td>${{item.summary || ""}}</td></tr>`
      ).join("");
      if (!tbody.innerHTML) {{
        tbody.innerHTML = '<tr><td colspan="5" class="muted">No alerts found for this run.</td></tr>';
      }}
    }}

    async function explainRun() {{
      clearError();
      const runName = activeRunName();
      if (!runName) {{
        showError("Select a run first.");
        return;
      }}
      const compareRunName = document.getElementById("compare-run").value || null;
      const payload = await fetchJson(`/runs/${{encodeURIComponent(runName)}}/explain`, {{
        method: "POST",
        headers: {{ "Content-Type": "application/json", Accept: "application/json" }},
        body: JSON.stringify({{ compare_run_name: compareRunName, alert_limit: 10 }}),
      }});
      document.getElementById("explain-meta").textContent =
        `provider=${{payload.provider}} model=${{payload.model}} fallback=${{payload.fallback_used}}`;
      document.getElementById("explain-text").textContent = payload.summary || "No explanation returned.";
    }}

    async function exportBundle() {{
      clearError();
      const runName = activeRunName();
      if (!runName) {{
        showError("Select a run first.");
        return;
      }}
      const payload = await fetchJson("/exports/portfolio-bundle", {{
        method: "POST",
        headers: {{ "Content-Type": "application/json", Accept: "application/json" }},
        body: JSON.stringify({{ run_name: runName }}),
      }});
      document.getElementById("export-result").textContent = JSON.stringify(payload, null, 2);
    }}

    document.getElementById("inspect-btn").addEventListener("click", () => inspectRun().catch((error) => showError(error.message)));
    document.getElementById("explain-btn").addEventListener("click", () => explainRun().catch((error) => showError(error.message)));
    document.getElementById("export-btn").addEventListener("click", () => exportBundle().catch((error) => showError(error.message)));
    document.getElementById("run-select").addEventListener("change", (event) => {{
      document.getElementById("run-name").value = event.target.value;
    }});

    Promise.all([loadBaseline(), loadRuns()]).then(() => inspectRun()).catch((error) => showError(error.message));
  </script>
</body>
</html>"""
