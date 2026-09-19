'use strict';
const $ = (id) => document.getElementById(id);
const initialDevices = () => [
  { id: 1, name: 'Design workstation', state: 'approved' },
  { id: 2, name: 'Studio laptop', state: 'approved' },
  { id: 3, name: 'New team member', state: 'pending' },
];
let devices = initialDevices();
let nextId = 4;
let alerts = [];
let evidence = null;
const states = {
  healthy: ['Capture healthy', 'The simulated worker is running and receiving events.'],
  idle: ['Capture idle', 'The simulated worker is alive, but no recent traffic is visible. This does not prove a fault.'],
  stale: ['Capture stale', 'No recent simulated heartbeat. Monitoring availability is unknown; check the worker.'],
  failed: ['Capture failed', 'The simulated capture worker stopped. Traffic is not being inspected.'],
};
function announce(message) { $('announcement').textContent = message; }
function renderDevices() {
  $('device-list').replaceChildren();
  for (const device of devices) {
    const row = document.createElement('tr');
    const name = document.createElement('td'); name.textContent = device.name;
    const status = document.createElement('td');
    const badge = document.createElement('span'); badge.className = `state ${device.state}`;
    badge.textContent = device.state; status.append(badge);
    const actions = document.createElement('td');
    for (const [label, target] of device.state === 'pending' ? [['Approve', 'approved'], ['Revoke', 'revoked']] : device.state === 'approved' ? [['Revoke', 'revoked']] : []) {
      const button = document.createElement('button'); button.textContent = label;
      button.setAttribute('aria-label', `${label} ${device.name}`);
      button.onclick = () => { device.state = target; renderDevices(); announce(`${device.name}: demo access ${target}.`); $('device-name').focus(); };
      actions.append(button);
    }
    if (device.state === 'revoked') actions.textContent = 'Access removed in demo';
    row.append(name, status, actions); $('device-list').append(row);
  }
  $('approved-count').textContent = devices.filter(d => d.state === 'approved').length;
  $('pending-count').textContent = devices.filter(d => d.state === 'pending').length;
}
function renderHealth() {
  const [label, detail] = states[$('capture-state').value];
  $('health-label').textContent = label; $('health-detail').textContent = detail;
}
function renderAlerts() {
  $('alert-count').textContent = alerts.length; $('alerts').replaceChildren();
  if (!alerts.length) {
    const empty = document.createElement('li'); empty.className = 'empty';
    empty.textContent = 'No demo alerts replayed yet.'; $('alerts').append(empty);
  }
  for (const alert of [...alerts].reverse()) {
    const item = document.createElement('li');
    const title = document.createElement('strong'); title.textContent = alert.rule_name;
    const detail = document.createElement('p'); detail.textContent = alert.summary;
    const meta = document.createElement('p'); meta.textContent = `${alert.severity.toUpperCase()} · SYNTHETIC REPLAY · ${alert.engine} · alert only, not blocked`;
    item.append(title, detail, meta); $('alerts').append(item);
  }
}
$('device-form').onsubmit = (event) => {
  event.preventDefault(); const name = $('device-name').value.trim();
  if (!name) { announce('Enter a fictional device name.'); return; }
  if (devices.length >= 5) { announce('Demo limit reached: five devices. Reset to start again.'); return; }
  if (devices.some(d => d.name.toLowerCase() === name.toLowerCase())) { announce('That demo device already exists.'); return; }
  devices.push({ id: nextId++, name, state: 'pending' }); $('device-name').value = '';
  renderDevices(); announce('Demo device added. Approve it to simulate access.');
};
$('capture-state').onchange = () => { renderHealth(); announce(states[$('capture-state').value][0]); };
$('replay').onclick = () => {
  if (!evidence) return;
  alerts.push(...evidence.alerts); alerts = alerts.slice(-20); renderAlerts();
  announce('Saved synthetic detector result replayed. No new traffic was captured.');
};
$('reset').onclick = () => {
  devices = initialDevices(); nextId = 4; alerts = []; $('device-name').value = '';
  $('capture-state').value = 'healthy'; renderDevices(); renderHealth(); renderAlerts(); announce('Demo reset.');
};
$('export').onclick = () => {
  const report = { mode: 'demo-only', generated_at: new Date().toISOString(),
    disclaimer: 'Simulated devices and VPN. Saved synthetic detector results. No live capture or access enforcement.',
    devices, simulated_capture_state: $('capture-state').value, replayed_alerts: alerts,
    detector_evidence: evidence, };
  const url = URL.createObjectURL(new Blob([JSON.stringify(report, null, 2)], { type: 'application/json' }));
  const link = document.createElement('a'); link.href = url; link.download = 'fusion-demo-report.json';
  link.click(); setTimeout(() => URL.revokeObjectURL(url), 1000); announce('Demo report exported.');
};
async function loadEvidence() {
  try {
    const response = await fetch('evidence.json');
    if (!response.ok) throw new Error('Missing evidence');
    const data = await response.json();
    if (data.mode !== 'synthetic-offline' || !Array.isArray(data.alerts) || data.alerts.length !== 1 || data.positive_alert_count !== 1 || data.negative_alert_count !== 0) throw new Error('Invalid evidence');
    if (!data.alerts.every(alert => alert && ['rule_name', 'summary', 'severity', 'engine'].every(key => typeof alert[key] === 'string' && alert[key].length > 0))) throw new Error('Invalid alert');
    evidence = data;
    $('evidence-status').textContent = 'Verified fixture: restricted-port event → 1 signature alert · benign control → 0 alerts. Saved evidence, not live detection.';
    $('replay').disabled = false; $('replay').textContent = 'Replay synthetic alert →';
  } catch {
    $('evidence-status').textContent = 'Evidence unavailable. Run the documented build command and serve this demo locally.';
    $('replay').textContent = 'Evidence unavailable';
  }
}
renderDevices(); renderHealth(); renderAlerts(); loadEvidence();
