/* ─────────────────────────────────────────────────────────────
   Cryptographic Amnesia — Dashboard Controller
   Live polling · Memory cards · Audit log · Shred animations
   ───────────────────────────────────────────────────────────── */

const API_BASE = 'http://localhost:3747';
const POLL_INTERVAL = 800; // ms

// ── STATE ─────────────────────────────────────────────────────────────────
let knownIds = new Set();
let knownEventIds = new Set();
let pollTimer = null;

// ── DOM REFS ──────────────────────────────────────────────────────────────
const statusDot  = document.getElementById('status-dot');
const statusText = document.getElementById('status-text');
const memGrid    = document.getElementById('memory-grid');
const emptyState = document.getElementById('empty-state');
const auditLog   = document.getElementById('audit-log');
const logCount   = document.getElementById('log-count');

const statActiveVal  = document.getElementById('stat-active-val');
const statShredVal   = document.getElementById('stat-shredded-val');
const statTotalVal   = document.getElementById('stat-total-val');
const statAuditVal   = document.getElementById('stat-audit-val');
const statUptimeVal  = document.getElementById('stat-uptime-val');

const openModalBtn  = document.getElementById('open-modal-btn');
const modalOverlay  = document.getElementById('modal-overlay');
const modalClose    = document.getElementById('modal-close');
const modalCancel   = document.getElementById('modal-cancel');
const modalSubmit   = document.getElementById('modal-submit');
const inputLabel    = document.getElementById('input-label');
const inputText     = document.getElementById('input-plaintext');
const inputTtl      = document.getElementById('input-ttl');
const ttlDisplay    = document.getElementById('ttl-display');
const shredOverlay  = document.getElementById('shred-overlay');
const shredProof    = document.getElementById('shred-proof-text');

// ── PARTICLE CANVAS ───────────────────────────────────────────────────────
(function initParticles() {
  const canvas = document.getElementById('particle-canvas');
  const ctx = canvas.getContext('2d');
  let W, H, particles = [];

  function resize() {
    W = canvas.width = window.innerWidth;
    H = canvas.height = window.innerHeight;
  }
  window.addEventListener('resize', resize);
  resize();

  class Particle {
    constructor() { this.reset(); }
    reset() {
      this.x = Math.random() * W;
      this.y = Math.random() * H;
      this.r = Math.random() * 1.5 + 0.3;
      this.vx = (Math.random() - 0.5) * 0.25;
      this.vy = (Math.random() - 0.5) * 0.25;
      this.alpha = Math.random() * 0.5 + 0.1;
      this.color = Math.random() > 0.5 ? '#a855f7' : '#06b6d4';
    }
    update() {
      this.x += this.vx;
      this.y += this.vy;
      if (this.x < 0 || this.x > W || this.y < 0 || this.y > H) this.reset();
    }
    draw() {
      ctx.beginPath();
      ctx.arc(this.x, this.y, this.r, 0, Math.PI * 2);
      ctx.fillStyle = this.color;
      ctx.globalAlpha = this.alpha;
      ctx.fill();
    }
  }

  for (let i = 0; i < 120; i++) particles.push(new Particle());

  function animate() {
    ctx.clearRect(0, 0, W, H);
    ctx.globalAlpha = 1;
    particles.forEach(p => { p.update(); p.draw(); });
    requestAnimationFrame(animate);
  }
  animate();
})();

// ── MODAL ─────────────────────────────────────────────────────────────────
function openModal() { modalOverlay.classList.add('open'); inputLabel.focus(); }
function closeModal() {
  modalOverlay.classList.remove('open');
  inputLabel.value = '';
  inputText.value = '';
  inputTtl.value = 10000;
  updateTtlDisplay();
}

openModalBtn.addEventListener('click', openModal);
modalClose.addEventListener('click', closeModal);
modalCancel.addEventListener('click', closeModal);
modalOverlay.addEventListener('click', e => { if (e.target === modalOverlay) closeModal(); });

inputTtl.addEventListener('input', updateTtlDisplay);
function updateTtlDisplay() {
  const ms = parseInt(inputTtl.value);
  ttlDisplay.textContent = ms >= 60000 ? `${(ms/60000).toFixed(0)}m` : `${(ms/1000).toFixed(0)}s`;
}
updateTtlDisplay();

modalSubmit.addEventListener('click', async () => {
  const label     = inputLabel.value.trim();
  const plaintext = inputText.value.trim();
  const ttlMs     = parseInt(inputTtl.value);

  if (!label || !plaintext) {
    inputLabel.style.borderColor = !label ? '#f43f5e' : '';
    inputText.style.borderColor  = !plaintext ? '#f43f5e' : '';
    return;
  }

  modalSubmit.disabled = true;
  modalSubmit.textContent = 'Encrypting...';

  try {
    const res = await fetch(`${API_BASE}/memory/store`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ label, plaintext, ttlMs }),
    });
    if (res.ok) { closeModal(); }
  } catch (err) {
    console.error('Store failed:', err);
  } finally {
    modalSubmit.disabled = false;
    modalSubmit.textContent = '🔐 Encrypt & Store';
  }
});

// ── SHRED OVERLAY ─────────────────────────────────────────────────────────
function showShredOverlay(attestation) {
  if (attestation) {
    shredProof.textContent =
      `Record ID   : ${attestation.recordId}\n` +
      `Key Hash    : ${attestation.keyFingerprint.substring(0, 32)}...\n` +
      `Shredded At : ${attestation.shredAt}\n` +
      `Signature   : ${attestation.signature.substring(0, 32)}...`;
  }
  shredOverlay.classList.add('show');
  setTimeout(() => shredOverlay.classList.remove('show'), 3000);
}

// ── SHRED ACTION ──────────────────────────────────────────────────────────
async function forceShred(id) {
  const card = document.getElementById(`card-${id}`);
  if (card) card.classList.add('shredding');

  try {
    const res = await fetch(`${API_BASE}/memory/${id}`, { method: 'DELETE' });
    if (res.ok) {
      const data = await res.json();
      setTimeout(() => {
        if (card) card.remove();
        showShredOverlay(data.proofOfErasure);
        knownIds.delete(id);
        checkEmpty();
      }, 600);
    }
  } catch (err) {
    console.error('Shred failed:', err);
    if (card) card.classList.remove('shredding');
  }
}

// ── MEMORY CARD RENDERING ─────────────────────────────────────────────────
function renderCard(record) {
  const existing = document.getElementById(`card-${record.id}`);
  if (existing) {
    // Just update the TTL bar
    updateCardTtl(record);
    return;
  }

  knownIds.add(record.id);
  emptyState && emptyState.remove();

  const card = document.createElement('div');
  card.className = 'memory-card';
  card.id = `card-${record.id}`;

  const shortId = record.id.split('-')[0];
  const created = new Date(record.createdAt).toLocaleTimeString();

  card.innerHTML = `
    <div class="card-header">
      <div>
        <div class="card-label">${escapeHtml(record.label)}</div>
        <div class="card-id">${shortId}…</div>
      </div>
      <div class="card-actions">
        <button class="btn-danger" onclick="forceShred('${record.id}')">💥 Shred</button>
      </div>
    </div>
    <div class="card-meta">
      <span>🕐 Created ${created}</span>
      <span>⏱ TTL ${(record.ttlMs / 1000).toFixed(0)}s</span>
    </div>
    <div class="ttl-bar-wrap">
      <div class="ttl-bar" id="bar-${record.id}" style="width:100%"></div>
    </div>
    <div class="ttl-remaining" id="rem-${record.id}"></div>
  `;

  memGrid.prepend(card);
  updateCardTtl(record);
}

function updateCardTtl(record) {
  const bar = document.getElementById(`bar-${record.id}`);
  const rem = document.getElementById(`rem-${record.id}`);
  if (!bar || !rem) return;

  const pct = Math.max(0, (record.remainingMs / record.ttlMs) * 100);
  bar.style.width = `${pct}%`;

  if (pct < 20) { bar.className = 'ttl-bar critical'; }
  else if (pct < 40) { bar.className = 'ttl-bar warning'; }
  else { bar.className = 'ttl-bar'; }

  const remS = (record.remainingMs / 1000).toFixed(1);
  rem.textContent = `${remS}s remaining`;

  // Auto-remove expired cards
  if (record.remainingMs <= 0) {
    const card = document.getElementById(`card-${record.id}`);
    if (card && !card.classList.contains('shredding')) {
      card.classList.add('shredding');
      setTimeout(() => { card.remove(); knownIds.delete(record.id); checkEmpty(); }, 600);
    }
  }
}

function checkEmpty() {
  if (memGrid.children.length === 0) {
    const empty = document.createElement('div');
    empty.className = 'empty-state';
    empty.id = 'empty-state';
    empty.innerHTML = `<div class="empty-icon">🧠</div><p>No active memories in the vault.</p><p class="empty-sub">Encrypt a new memory to watch it countdown to oblivion.</p>`;
    memGrid.appendChild(empty);
  }
}

// ── AUDIT LOG RENDERING ───────────────────────────────────────────────────
function renderAuditEvents(events) {
  const newEvents = events.filter(e => !knownEventIds.has(e.eventId));
  if (!newEvents.length) return;

  // Clear placeholder on first event
  if (knownEventIds.size === 0) auditLog.innerHTML = '';

  newEvents.forEach(event => {
    knownEventIds.add(event.eventId);

    const entry = document.createElement('div');
    entry.className = 'log-entry';
    const time = new Date(event.timestamp).toLocaleTimeString();

    entry.innerHTML = `
      <div class="log-dot ${event.type}"></div>
      <div class="log-body">
        <div class="log-type ${event.type}">${event.type}</div>
        <div class="log-label">${escapeHtml(event.label)}</div>
        <div class="log-time">${time}</div>
      </div>
    `;

    auditLog.prepend(entry);
  });

  logCount.textContent = `${events.length} event${events.length !== 1 ? 's' : ''}`;
}

// ── POLLING ───────────────────────────────────────────────────────────────
async function poll() {
  try {
    // Fetch health + memory + audit in parallel
    const [healthRes, memRes, auditRes] = await Promise.all([
      fetch(`${API_BASE}/health`),
      fetch(`${API_BASE}/memory`),
      fetch(`${API_BASE}/audit/log`),
    ]);

    if (!healthRes.ok) throw new Error('Daemon offline');

    // ── STATUS
    statusDot.className = 'status-indicator online';
    statusText.textContent = 'Daemon Online';

    // ── STATS
    const health = await healthRes.json();
    statActiveVal.textContent  = health.stats.active;
    statShredVal.textContent   = health.stats.shredded;
    statTotalVal.textContent   = health.stats.total;
    statAuditVal.textContent   = health.stats.auditEvents;
    statUptimeVal.textContent  = health.uptime.toFixed(0);

    // ── MEMORY CARDS
    const memData = await memRes.json();
    const activeIds = new Set(memData.records.map(r => r.id));

    // Remove cards no longer active
    knownIds.forEach(id => {
      if (!activeIds.has(id)) {
        const card = document.getElementById(`card-${id}`);
        if (card && !card.classList.contains('shredding')) {
          card.classList.add('shredding');
          setTimeout(() => { card.remove(); knownIds.delete(id); checkEmpty(); }, 600);
        }
      }
    });

    memData.records.forEach(r => renderCard(r));
    if (memData.records.length === 0 && memGrid.children.length === 0) checkEmpty();

    // ── AUDIT LOG
    const auditData = await auditRes.json();
    renderAuditEvents(auditData.events);

  } catch (err) {
    statusDot.className = 'status-indicator offline';
    statusText.textContent = 'Daemon Offline';
  }
}

// ── HELPERS ───────────────────────────────────────────────────────────────
function escapeHtml(str) {
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

// ── START ─────────────────────────────────────────────────────────────────
poll();
setInterval(poll, POLL_INTERVAL);
