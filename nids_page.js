const ATTACK_CATALOG = [
  {
    key: "dos_ddos",
    label: "DoS / DDoS",
    description: "Flooding behavior and connection pressure patterns."
  },
  {
    key: "mitm_arp",
    label: "MITM / ARP Spoof",
    description: "Address resolution anomalies and interception indicators."
  },
  {
    key: "port_scan",
    label: "Port Scan",
    description: "Rapid multi-port probing from remote hosts."
  },
  {
    key: "unauthorized_access",
    label: "Unauthorized Access",
    description: "Attempts against sensitive service ports."
  },
  {
    key: "malware_payload",
    label: "Malware / Payload",
    description: "Suspicious executable/script indicators in dropped files."
  },
  {
    key: "data_tampering",
    label: "Data Corruption / Tampering",
    description: "Corruption and tamper signatures in dropped files."
  }
];

const refs = {
  dropZone: document.getElementById("dropZone"),
  archiveInput: document.getElementById("archiveInput"),
  selectedFileLabel: document.getElementById("selectedFileLabel"),
  scanFileBtn: document.getElementById("scanFileBtn"),
  fileStatus: document.getElementById("fileStatus"),

  filesScanned: document.getElementById("filesScanned"),
  corruptedFiles: document.getElementById("corruptedFiles"),
  suspiciousFiles: document.getElementById("suspiciousFiles"),
  riskScore: document.getElementById("riskScore"),
  fileFindingsBody: document.getElementById("fileFindingsBody"),

  startScanBtn: document.getElementById("startScanBtn"),
  stopScanBtn: document.getElementById("stopScanBtn"),
  scanStatus: document.getElementById("scanStatus"),

  activeConnections: document.getElementById("activeConnections"),
  externalIps: document.getElementById("externalIps"),
  unauthAttempts: document.getElementById("unauthAttempts"),
  suspiciousEvents: document.getElementById("suspiciousEvents"),
  dosScore: document.getElementById("dosScore"),
  mitmScore: document.getElementById("mitmScore"),
  portScanScore: document.getElementById("portScanScore"),
  topRemote: document.getElementById("topRemote"),

  attackMatrix: document.getElementById("attackMatrix"),
  eventTableBody: document.getElementById("eventTableBody"),
  trendBars: document.getElementById("trendBars"),
  trendMeta: document.getElementById("trendMeta"),
  footerStamp: document.getElementById("footerStamp")
};

const state = {
  selectedFile: null,
  pollHandle: null,
  running: false,
  history: []
};

function formatNumber(value) {
  const numeric = Number(value);
  if (Number.isFinite(numeric)) {
    return numeric.toLocaleString("en-US");
  }
  return String(value ?? "-");
}

function severityToBadgeClass(value) {
  const raw = String(value || "").toLowerCase();
  if (raw === "high" || raw === "alert" || raw === "critical") {
    return "high";
  }
  if (raw === "medium" || raw === "monitor" || raw === "warning") {
    return "medium";
  }
  return "low";
}

function computeTrendScore(item) {
  return Math.min(
    100,
    Math.max(
      Number(item.dos_score || 0),
      Number(item.mitm_score || 0),
      Number(item.port_scan_score || 0),
      Number(item.unauthorized_score || 0),
      Number(item.suspicious_events || 0) * 12
    )
  );
}

function timestampLabel(stamp) {
  if (!stamp) {
    return "-";
  }
  const parts = String(stamp).split(" ");
  if (parts.length >= 2) {
    return parts[1];
  }
  return String(stamp);
}

function setScanStatus(running, message) {
  refs.scanStatus.textContent = message || (running ? "Status: Running" : "Status: Idle");
  refs.scanStatus.classList.toggle("running", running);
  refs.scanStatus.classList.toggle("idle", !running);

  refs.startScanBtn.disabled = running;
  refs.stopScanBtn.disabled = !running;
  state.running = running;
}

function setFileStatus(message) {
  refs.fileStatus.textContent = message;
}

function setSelectedFile(file) {
  state.selectedFile = file || null;
  if (state.selectedFile) {
    refs.selectedFileLabel.textContent = `${state.selectedFile.name} (${formatNumber(state.selectedFile.size)} bytes)`;
  } else {
    refs.selectedFileLabel.textContent = "No file selected";
  }
}

function renderFindingRows(findings) {
  refs.fileFindingsBody.innerHTML = "";
  if (!Array.isArray(findings) || findings.length === 0) {
    const row = document.createElement("tr");
    row.innerHTML = "<td colspan=\"3\">No findings available.</td>";
    refs.fileFindingsBody.appendChild(row);
    return;
  }

  for (const finding of findings) {
    const row = document.createElement("tr");

    const name = document.createElement("td");
    name.textContent = finding.name || "-";

    const value = document.createElement("td");
    value.textContent = finding.value == null ? "-" : String(finding.value);

    const severity = document.createElement("td");
    const badge = document.createElement("span");
    const level = finding.severity || "low";
    badge.className = `badge ${severityToBadgeClass(level)}`;
    badge.textContent = String(level).toUpperCase();
    severity.appendChild(badge);

    row.appendChild(name);
    row.appendChild(value);
    row.appendChild(severity);
    refs.fileFindingsBody.appendChild(row);
  }
}

function renderFileScanResult(result) {
  refs.filesScanned.textContent = formatNumber(result.total_files || 0);
  refs.corruptedFiles.textContent = formatNumber(result.corrupted_files || 0);
  refs.suspiciousFiles.textContent = formatNumber(result.suspicious_files || 0);
  refs.riskScore.textContent = formatNumber(result.risk_score || 0);

  renderFindingRows(result.findings || []);
  setFileStatus(`Scan complete: ${result.verdict || "unknown"} (${result.risk_score || 0}/100).`);
}

function renderAttackMatrix(matrixData) {
  refs.attackMatrix.innerHTML = "";

  for (const item of ATTACK_CATALOG) {
    const data = (matrixData && matrixData[item.key]) || {};
    const score = Number.isFinite(Number(data.score)) ? Number(data.score) : 0;
    const status = data.status || "normal";
    const summary = data.summary || "No strong indicator detected in current snapshot.";

    const row = document.createElement("article");
    row.className = "attack-row";

    const head = document.createElement("div");
    head.className = "head";

    const title = document.createElement("span");
    title.className = "title";
    title.textContent = item.label;

    const badge = document.createElement("span");
    badge.className = `badge ${severityToBadgeClass(status)}`;
    badge.textContent = `${status.toUpperCase()} | ${score}`;

    const meta = document.createElement("div");
    meta.className = "meta";
    meta.textContent = `${item.description} ${summary}`;

    head.appendChild(title);
    head.appendChild(badge);
    row.appendChild(head);
    row.appendChild(meta);
    refs.attackMatrix.appendChild(row);
  }
}

function renderEvents(events) {
  refs.eventTableBody.innerHTML = "";
  if (!Array.isArray(events) || events.length === 0) {
    const row = document.createElement("tr");
    row.innerHTML = "<td colspan=\"4\">No events yet. Run network scan to collect telemetry.</td>";
    refs.eventTableBody.appendChild(row);
    return;
  }

  for (const event of events.slice(0, 25)) {
    const row = document.createElement("tr");

    const time = document.createElement("td");
    time.textContent = event.time || "-";

    const type = document.createElement("td");
    type.textContent = event.type || "-";

    const severity = document.createElement("td");
    const badge = document.createElement("span");
    badge.className = `badge ${severityToBadgeClass(event.severity)}`;
    badge.textContent = String(event.severity || "info").toUpperCase();
    severity.appendChild(badge);

    const summary = document.createElement("td");
    summary.textContent = event.summary || "-";

    row.appendChild(time);
    row.appendChild(type);
    row.appendChild(severity);
    row.appendChild(summary);
    refs.eventTableBody.appendChild(row);
  }
}

function renderTrend(history) {
  refs.trendBars.innerHTML = "";

  if (!Array.isArray(history) || history.length === 0) {
    refs.trendMeta.textContent = "No trend data yet.";
    return;
  }

  const recent = history.slice(-20);
  for (const item of recent) {
    const score = computeTrendScore(item);
    const row = document.createElement("div");
    row.className = "trend-row";

    const stamp = document.createElement("span");
    stamp.className = "stamp";
    stamp.textContent = timestampLabel(item.timestamp);

    const track = document.createElement("div");
    track.className = "bar-track";
    const fill = document.createElement("div");
    fill.className = "bar-fill";
    fill.style.width = `${Math.max(2, score)}%`;
    track.appendChild(fill);

    const scoreLabel = document.createElement("span");
    scoreLabel.className = "score";
    scoreLabel.textContent = String(score);

    row.appendChild(stamp);
    row.appendChild(track);
    row.appendChild(scoreLabel);
    refs.trendBars.appendChild(row);
  }

  const avg = Math.round(recent.reduce((acc, item) => acc + computeTrendScore(item), 0) / recent.length);
  refs.trendMeta.textContent = `Snapshots: ${history.length} | Recent average risk: ${avg}/100`;
}

function renderNetworkSnapshot(snapshot) {
  const counters = snapshot.counters || {};
  refs.activeConnections.textContent = formatNumber(counters.active_connections || 0);
  refs.externalIps.textContent = formatNumber(counters.unique_external_ips || 0);
  refs.unauthAttempts.textContent = formatNumber(counters.unauthorized_attempts || 0);
  refs.suspiciousEvents.textContent = formatNumber(counters.suspicious_events || 0);

  refs.dosScore.textContent = formatNumber(counters.dos_score || 0);
  refs.mitmScore.textContent = formatNumber(counters.mitm_score || 0);
  refs.portScanScore.textContent = formatNumber(counters.port_scan_score || 0);

  refs.topRemote.textContent = snapshot.top_remote || "-";

  renderAttackMatrix(snapshot.attack_matrix || {});
  renderEvents(snapshot.events || []);

  const stamp = snapshot.timestamp || new Date().toLocaleString();
  refs.footerStamp.textContent = `Live snapshot: ${stamp} | Engine: local heuristic scanner`;
}

async function scanDroppedFile() {
  if (!state.selectedFile) {
    setFileStatus("Please select or drop a file first.");
    return;
  }

  setFileStatus("Scanning file...");
  refs.scanFileBtn.disabled = true;

  const formData = new FormData();
  formData.append("archive", state.selectedFile);

  try {
    const response = await fetch("/api/scan/file-drop", {
      method: "POST",
      body: formData
    });

    const payload = await response.json();
    if (!response.ok) {
      throw new Error(payload.error || "File scan failed");
    }

    renderFileScanResult(payload);
    if (payload.attack_matrix_fragment) {
      renderAttackMatrix(payload.attack_matrix_fragment);
    }
  } catch (error) {
    setFileStatus(`Scan failed: ${error.message}`);
  } finally {
    refs.scanFileBtn.disabled = false;
  }
}

async function fetchHistory() {
  try {
    const response = await fetch("/api/scan/network/history", { method: "GET" });
    const payload = await response.json();
    if (!response.ok) {
      throw new Error(payload.error || "Unable to fetch history");
    }

    state.history = payload.history || [];
    renderTrend(state.history);
  } catch (error) {
    refs.trendMeta.textContent = `Trend unavailable: ${error.message}`;
  }
}

async function fetchSnapshot() {
  try {
    const response = await fetch("/api/scan/network/snapshot", { method: "GET" });
    const payload = await response.json();
    if (!response.ok) {
      throw new Error(payload.error || "Network snapshot failed");
    }

    renderNetworkSnapshot(payload);
    setScanStatus(Boolean(payload.running), payload.running ? "Status: Running" : "Status: Idle");
  } catch (error) {
    setScanStatus(false, `Status: Error (${error.message})`);
  }
}

async function startNetworkScan() {
  try {
    const response = await fetch("/api/scan/network/start", { method: "POST" });
    const payload = await response.json();
    if (!response.ok) {
      throw new Error(payload.error || "Unable to start scan");
    }

    setScanStatus(true, "Status: Running");
    await fetchSnapshot();
    await fetchHistory();

    if (state.pollHandle) {
      clearInterval(state.pollHandle);
    }

    state.pollHandle = setInterval(async () => {
      await fetchSnapshot();
      await fetchHistory();
    }, 3000);
  } catch (error) {
    setScanStatus(false, `Status: Start Failed (${error.message})`);
  }
}

async function stopNetworkScan() {
  try {
    const response = await fetch("/api/scan/network/stop", { method: "POST" });
    const payload = await response.json();
    if (!response.ok) {
      throw new Error(payload.error || "Unable to stop scan");
    }

    if (state.pollHandle) {
      clearInterval(state.pollHandle);
      state.pollHandle = null;
    }

    setScanStatus(false, "Status: Idle");
    await fetchSnapshot();
    await fetchHistory();
  } catch (error) {
    setScanStatus(false, `Status: Stop Failed (${error.message})`);
  }
}

function wireDropZone() {
  refs.dropZone.addEventListener("dragover", (event) => {
    event.preventDefault();
    refs.dropZone.classList.add("dragover");
  });

  refs.dropZone.addEventListener("dragleave", () => {
    refs.dropZone.classList.remove("dragover");
  });

  refs.dropZone.addEventListener("drop", (event) => {
    event.preventDefault();
    refs.dropZone.classList.remove("dragover");

    const [file] = Array.from(event.dataTransfer.files || []);
    if (file) {
      setSelectedFile(file);
    }
  });

  refs.archiveInput.addEventListener("change", (event) => {
    const [file] = Array.from(event.target.files || []);
    setSelectedFile(file || null);
  });
}

function initialize() {
  wireDropZone();
  renderAttackMatrix();
  renderEvents([]);
  renderTrend([]);

  refs.scanFileBtn.addEventListener("click", scanDroppedFile);
  refs.startScanBtn.addEventListener("click", startNetworkScan);
  refs.stopScanBtn.addEventListener("click", stopNetworkScan);

  fetchSnapshot()
    .then(fetchHistory)
    .catch((error) => {
      refs.footerStamp.textContent = `Initialization error: ${error.message}`;
    });
}

document.addEventListener("DOMContentLoaded", initialize);
