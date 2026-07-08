let _filter = 'all';
let _traces = [];
let _stats  = {};
let _donut, _lat, _cats, _gate;

function esc(v) {
  return String(v).replace(/[&<>"']/g, c => ({
    '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;',
  }[c]));
}

// Charts
Chart.defaults.color = '#718096';
Chart.defaults.borderColor = '#E2E8F0';
Chart.defaults.font.family = "Inter, -apple-system, sans-serif";

_donut = new Chart(document.getElementById('chart-donut'), {
  type: 'doughnut',
  data: { labels: ['Pass','Block','Mask'], datasets: [{ data: [0,0,0],
    backgroundColor: ['#16A34A22','#DC262622','#D9770622'],
    borderColor: ['#16A34A','#DC2626','#D97706'], borderWidth: 2 }] },
  options: { cutout: '65%', plugins: { legend: { position: 'bottom', labels: { boxWidth: 10, padding: 12, font: { size: 11 } } } }, animation: false }
});

_lat = new Chart(document.getElementById('chart-lat'), {
  type: 'line',
  data: { labels: [], datasets: [{ label: 'ms', data: [],
    borderColor: '#2161D8', backgroundColor: '#2161D811', fill: true,
    tension: 0.4, pointRadius: 2, borderWidth: 2 }] },
  options: { scales: {
    x: { display: false },
    y: { grid: { color: '#E2E8F0' }, ticks: { font: { size: 10 } } }
  }, plugins: { legend: { display: false } }, animation: false }
});

_cats = new Chart(document.getElementById('chart-cats'), {
  type: 'bar',
  data: { labels: [], datasets: [{ data: [],
    backgroundColor: '#DC262622', borderColor: '#DC2626', borderWidth: 1, borderRadius: 4 }] },
  options: { indexAxis: 'y',
    scales: {
      x: { grid: { color: '#E2E8F0' }, ticks: { font: { size: 10 } } },
      y: { ticks: { font: { size: 10 } } }
    }, plugins: { legend: { display: false } }, animation: false }
});

_gate = new Chart(document.getElementById('chart-gate'), {
  type: 'doughnut',
  data: { labels: ['Input','Output'], datasets: [{ data: [0,0],
    backgroundColor: ['#2161D822','#0D948822'],
    borderColor: ['#2161D8','#0D9488'], borderWidth: 2 }] },
  options: { cutout: '60%', plugins: { legend: { position: 'bottom', labels: { boxWidth: 10, padding: 10, font: { size: 11 } } } }, animation: false }
});

// Navigation
const VIEW_TITLES = {
  traces: ['Traces', 'Real-time GuardEx screening events · auto-refresh 2s'],
  analytics: ['Analytics', 'Aggregated metrics across all screening events'],
  security: ['Security Events', 'Blocked threats intercepted by GuardEx'],
  pii: ['PII Events', 'Screening calls where personal data was detected and masked'],
  settings: ['Settings', 'Dashboard and OTel configuration'],
};
function showView(name, el) {
  document.querySelectorAll('.view').forEach(v => v.classList.remove('active'));
  document.querySelectorAll('.nav-item').forEach(n => n.classList.remove('active'));
  document.getElementById('view-' + name).classList.add('active');
  el.classList.add('active');
  document.getElementById('view-title').textContent = VIEW_TITLES[name][0];
  document.getElementById('view-sub').textContent   = VIEW_TITLES[name][1];
  document.getElementById('trace-filters').style.display = name === 'traces' ? 'flex' : 'none';
  if (name !== 'traces') closeDetail();
}

// Trace filter
function setFilter(f, el) {
  _filter = f;
  document.querySelectorAll('.filter-btn').forEach(b => b.classList.remove('active'));
  el.classList.add('active');
  renderTraces();
}
function filtered() {
  if (_filter === 'all') return _traces;
  return _traces.filter(t => t.action === _filter || t.gate === _filter);
}

// Helpers
function ts(ms) {
  const d = new Date(ms);
  return d.toLocaleTimeString('en-GB', { hour12: false }) + '.' + String(d.getMilliseconds()).padStart(3,'0');
}

// Render traces
function renderTraces() {
  const rows = filtered();
  const el = document.getElementById('trace-list');
  if (!rows.length) { el.innerHTML = '<div class="empty-state">No traces match the current filter.</div>'; return; }
  el.innerHTML = rows.map(t => `
    <div class="trace-row" data-trace-id="${esc(t.trace_id)}">
      <span class="mono" style="font-size:11px">${ts(t.start_ms)}</span>
      <span><span class="badge badge-${esc(t.gate)}">${esc(t.gate)}</span></span>
      <span><span class="badge badge-${esc(t.action)}">${esc(t.action.toUpperCase())}</span></span>
      <span style="color:${t.category ? 'var(--block)' : 'var(--muted)'};font-size:11px">${esc(t.category || '—')}</span>
      <span>${esc(t.latency_ms)} <span style="color:var(--muted);font-size:10px">ms</span></span>
      <span>${t.pii ? '<span class="pii-dot" title="PII detected"></span>' : '<span style="color:var(--border)">●</span>'}</span>
      <span class="mono" style="font-size:10px;color:var(--muted)">${esc(t.trace_id.slice(0,16))}…</span>
    </div>`).join('');
}

// Render security view
function renderSecurity() {
  const blocks = _traces.filter(t => t.action === 'block');
  const cats = _stats.categories || {};
  document.getElementById('sec-summary').innerHTML =
    `<strong>${blocks.length} threats blocked</strong> out of ${_traces.length} total screens - <strong style="color:var(--block)">${esc(_stats.block_rate || 0)}% block rate</strong>. ` +
    `Categories: ${esc(Object.keys(cats).join(', ') || 'none yet')}.`;
  document.getElementById('sec-cat-list').innerHTML = Object.entries(cats).length
    ? Object.entries(cats).map(([cat,n]) => `
        <div class="alert-row">
          <span class="alert-icon">🚨</span>
          <div><div class="alert-label">${esc(cat)}</div><div class="alert-sub">${esc(n)} event${n>1?'s':''}</div></div>
          <span style="margin-left:auto;font-weight:700;color:var(--block)">${esc(n)}</span>
        </div>`).join('')
    : '<div class="empty-state" style="padding:24px">No threats detected yet.</div>';
  document.getElementById('sec-list').innerHTML = blocks.length
    ? blocks.map(t => {
        const conf = t.attrs && t.attrs['guardex.confidence'];
        return `
        <div class="trace-row" style="grid-template-columns:130px 160px 85px 1fr" data-trace-id="${esc(t.trace_id)}">
          <span class="mono" style="font-size:11px">${ts(t.start_ms)}</span>
          <span style="color:var(--block);font-size:11px;font-weight:600">${esc(t.category || '—')}</span>
          <span style="font-size:11px">${conf != null && conf !== '' ? esc(conf) : '—'}</span>
          <span class="mono" style="font-size:10px;color:var(--muted)">${esc(t.trace_id.slice(0,16))}…</span>
        </div>`;
      }).join('')
    : '<div class="empty-state">No blocked events yet.</div>';
  document.getElementById('block-badge').textContent = blocks.length;
}

// Render PII view
function renderPII() {
  const pii = _traces.filter(t => t.pii);
  document.getElementById('pii-summary').innerHTML =
    `<strong>${pii.length} event${pii.length===1?'':'s'} with PII detected</strong> - <strong style="color:var(--mask)">${esc(_stats.pii_rate || 0)}% PII rate</strong>.`;
  document.getElementById('pii-list').innerHTML = pii.length
    ? pii.map(t => `
        <div class="trace-row" style="grid-template-columns:130px 80px 100px 1fr" data-trace-id="${esc(t.trace_id)}">
          <span class="mono" style="font-size:11px">${ts(t.start_ms)}</span>
          <span><span class="badge badge-${esc(t.gate)}">${esc(t.gate)}</span></span>
          <span style="color:var(--mask);font-weight:600;font-size:11px">${esc(t.pii_count)} entit${t.pii_count===1?'y':'ies'}</span>
          <span class="mono" style="font-size:10px;color:var(--muted)">${esc(t.trace_id.slice(0,16))}…</span>
        </div>`).join('')
    : '<div class="empty-state">No PII events yet.</div>';
}

// Detail panel
function openDetailById(tid) {
  const t = _traces.find(x => x.trace_id === tid);
  if (t) openDetail(t);
}
function openDetail(t) {
  if (!t) return;
  document.getElementById('detail-title').textContent = t.name;
  document.querySelectorAll('.trace-row').forEach(r =>
    r.classList.toggle('selected', r.dataset.traceId === t.trace_id));
  document.getElementById('detail-body').innerHTML = `
    <div class="detail-section">
      <div class="detail-section-title">Overview</div>
      <div class="detail-row"><span class="detail-key">Action</span><span class="detail-val ${esc(t.action)}">${esc(t.action.toUpperCase())}</span></div>
      <div class="detail-row"><span class="detail-key">Safe</span><span class="detail-val ${t.safe?'pass':'block'}">${esc(t.safe)}</span></div>
      <div class="detail-row"><span class="detail-key">Gate</span><span class="detail-val">${esc(t.gate)}</span></div>
      <div class="detail-row"><span class="detail-key">Category</span><span class="detail-val ${t.category?'block':''}">${esc(t.category||'—')}</span></div>
    </div>
    <div class="detail-section">
      <div class="detail-section-title">Performance</div>
      <div class="detail-row"><span class="detail-key">Server latency</span><span class="detail-val">${esc(t.latency_ms)} ms</span></div>
      <div class="detail-row"><span class="detail-key">Span duration</span><span class="detail-val">${esc(t.dur_ms)} ms</span></div>
      <div class="detail-row"><span class="detail-key">Timestamp</span><span class="detail-val">${ts(t.start_ms)}</span></div>
    </div>
    <div class="detail-section">
      <div class="detail-section-title">PII</div>
      <div class="detail-row"><span class="detail-key">Detected</span><span class="detail-val ${t.pii?'mask':''}">${esc(t.pii)}</span></div>
      <div class="detail-row"><span class="detail-key">Entity count</span><span class="detail-val">${esc(t.pii_count)}</span></div>
    </div>
    <div class="detail-section">
      <div class="detail-section-title">Identifiers</div>
      <div class="detail-row"><span class="detail-key">Trace ID</span><span class="detail-val" style="font-size:10px">${esc(t.trace_id)}</span></div>
      <div class="detail-row"><span class="detail-key">Span ID</span><span class="detail-val" style="font-size:10px">${esc(t.span_id)}</span></div>
      <div class="detail-row"><span class="detail-key">Request ID</span><span class="detail-val" style="font-size:10px">${esc(t.request_id||'—')}</span></div>
      <div class="detail-row"><span class="detail-key">OTel Status</span><span class="detail-val">${esc(t.status)}</span></div>
    </div>
    <div class="detail-section">
      <div class="detail-section-title">All guardex.* Attributes</div>
      ${Object.entries(t.attrs).map(([k,v])=>
        `<div class="detail-row"><span class="detail-key">${esc(k)}</span><span class="detail-val">${esc(v)}</span></div>`
      ).join('')}
    </div>`;
  document.getElementById('detail-panel').classList.add('open');
  document.getElementById('overlay').classList.add('open');
}
function closeDetail() {
  document.getElementById('detail-panel').classList.remove('open');
  document.getElementById('overlay').classList.remove('open');
  document.querySelectorAll('.trace-row').forEach(r => r.classList.remove('selected'));
}

['trace-list', 'sec-list', 'pii-list'].forEach(id => {
  document.getElementById(id).addEventListener('click', e => {
    const row = e.target.closest('.trace-row');
    if (row && row.dataset.traceId) openDetailById(row.dataset.traceId);
  });
});

// Connection state
function setLive(ok) {
  const pill = document.getElementById('live-pill');
  if (!pill) return;
  pill.classList.toggle('offline', !ok);
  document.getElementById('live-label').textContent = ok ? 'Live' : 'Disconnected';
}

// Main refresh loop
async function refresh() {
  let traces, stats;
  try {
    [traces, stats] = await Promise.all([
      fetch('/api/traces').then(r=>r.json()),
      fetch('/api/stats').then(r=>r.json()),
    ]);
  } catch {
    setLive(false);
    return;
  }
  setLive(true);
  _traces = traces;
  _stats  = stats;

  // Stat cards
  document.getElementById('s-total').textContent = stats.total;
  document.getElementById('s-pass').textContent  = stats.passed;
  document.getElementById('s-block').textContent = stats.blocked;
  document.getElementById('s-mask').textContent  = stats.masked;
  document.getElementById('s-lat').textContent   = stats.avg_lat;
  document.getElementById('s-p95').textContent   = stats.p95_lat;
  document.getElementById('s-block-rate').textContent = `${stats.block_rate}% block rate`;
  document.getElementById('s-pii-rate').textContent   = `${stats.pii_rate}% PII rate`;
  document.getElementById('s-pass-pct').textContent   = stats.total ? `${Math.round(stats.passed/stats.total*100)}% of screens` : '—';

  // Analytics stats
  document.getElementById('a-total').textContent = stats.total;
  document.getElementById('a-brate').textContent = stats.block_rate + '%';
  document.getElementById('a-prate').textContent = stats.pii_rate + '%';
  document.getElementById('a-lat').textContent   = stats.avg_lat + ' ms';
  document.getElementById('a-p95').textContent   = stats.p95_lat + ' ms';

  // Charts
  _donut.data.datasets[0].data = [stats.passed, stats.blocked, stats.masked];
  _donut.update();

  const pts = stats.lat_series.slice(-30);
  _lat.data.labels = pts.map((_,i)=>i);
  _lat.data.datasets[0].data = pts.map(p=>p.v);
  _lat.update();

  const cats = stats.categories||{};
  _cats.data.labels = Object.keys(cats);
  _cats.data.datasets[0].data = Object.values(cats);
  _cats.update();

  const inp = traces.filter(t=>t.gate==='input').length;
  const out = traces.filter(t=>t.gate==='output').length;
  _gate.data.datasets[0].data = [inp, out];
  _gate.update();

  renderTraces();
  renderSecurity();
  renderPII();
}

// Dynamic config (port, otel version)
fetch('/api/info').then(r => r.json()).then(info => {
  const portEl = document.getElementById('cfg-port');
  if (portEl && info.port) portEl.textContent = info.port;
  const otelEl = document.getElementById('cfg-otel-version');
  if (otelEl && info.otel_version) otelEl.textContent = 'opentelemetry ' + info.otel_version;
  const footerEl = document.getElementById('footer-otel');
  if (footerEl && info.otel_version) footerEl.textContent = info.otel_version;
}).catch(() => {});

refresh();
setInterval(refresh, 2000);
