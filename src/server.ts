import express, { Request, Response, NextFunction } from 'express';
import cors from 'cors';
import path from 'path';
import { AmnesiaVault } from './vault';
import { AmnesiaCrypto } from './crypto';

// ─── SETUP ──────────────────────────────────────────────────────────────────

const app = express();
const PORT = process.env.PORT || 3747;
const vault = new AmnesiaVault();

app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname, '..', 'dashboard')));

// ─── REQUEST LOGGER ─────────────────────────────────────────────────────────

app.use((req: Request, _res: Response, next: NextFunction) => {
  const ts = new Date().toISOString();
  console.log(`  [${ts}] ${req.method} ${req.path}`);
  next();
});

// ─── HEALTH ─────────────────────────────────────────────────────────────────

app.get('/health', (_req: Request, res: Response) => {
  res.json({
    status: 'operational',
    service: 'cryptographic-amnesia',
    version: '1.0.0',
    uptime: process.uptime(),
    stats: vault.getStats(),
    timestamp: new Date().toISOString(),
  });
});

// ─── MEMORY ROUTES ──────────────────────────────────────────────────────────

/**
 * POST /memory/store
 * Body: { label: string, plaintext: string, ttlMs: number }
 * Encrypts and stores a context payload with a finite TTL.
 */
app.post('/memory/store', (req: Request, res: Response) => {
  const { label, plaintext, ttlMs } = req.body as {
    label?: string;
    plaintext?: string;
    ttlMs?: number;
  };

  if (!label || !plaintext || !ttlMs) {
    res.status(400).json({
      error: 'BAD_REQUEST',
      message: 'Fields required: label (string), plaintext (string), ttlMs (number)',
    });
    return;
  }

  if (typeof ttlMs !== 'number' || ttlMs <= 0 || ttlMs > 86_400_000) {
    res.status(400).json({
      error: 'BAD_REQUEST',
      message: 'ttlMs must be a positive number ≤ 86400000 (24h)',
    });
    return;
  }

  try {
    const id = vault.store(label, plaintext, ttlMs);
    const records = vault.listActive();
    const record = records.find(r => r.id === id);

    res.status(201).json({
      success: true,
      id,
      label,
      expiresAt: record?.expiresAt,
      ttlMs,
      message: `Memory '${label}' secured with AES-256-GCM. Key shreds in ${ttlMs}ms.`,
    });
  } catch (err: any) {
    res.status(500).json({ error: 'STORE_FAILED', message: err.message });
  }
});

/**
 * GET /memory
 * Returns all active (non-shredded) memory records (no ciphertext or keys).
 */
app.get('/memory', (_req: Request, res: Response) => {
  res.json({ records: vault.listActive() });
});

/**
 * GET /memory/:id
 * JIT-decrypts and returns the context if the key is still alive.
 */
app.get('/memory/:id', (req: Request, res: Response) => {
  const { id } = req.params;
  const plaintext = vault.retrieve(id);

  if (plaintext === null) {
    res.status(404).json({
      error: 'NOT_FOUND_OR_SHREDDED',
      message: `Memory '${id}' is not accessible. It may have been shredded or never existed.`,
    });
    return;
  }

  res.json({ id, plaintext });
});

/**
 * DELETE /memory/:id
 * Immediately shreds the encryption key. Returns a signed Proof of Erasure.
 */
app.delete('/memory/:id', (req: Request, res: Response) => {
  const { id } = req.params;
  const attestation = vault.shred(id);

  if (!attestation) {
    res.status(404).json({
      error: 'NOT_FOUND_OR_ALREADY_SHREDDED',
      message: `Memory '${id}' could not be shredded. Already gone or never existed.`,
    });
    return;
  }

  // Verify the attestation we just generated (self-audit)
  const valid = AmnesiaCrypto.verifyErasure(attestation);

  res.json({
    success: true,
    message: 'Memory has been cryptographically shredded. It is permanently inaccessible.',
    proofOfErasure: attestation,
    attestationValid: valid,
  });
});

// ─── AUDIT ROUTES ───────────────────────────────────────────────────────────

/**
 * GET /audit/log
 * Returns the full immutable audit log of all vault events.
 */
app.get('/audit/log', (_req: Request, res: Response) => {
  const log = vault.getAuditLog();
  res.json({
    total: log.length,
    events: log,
  });
});

/**
 * GET /audit/stats
 * Returns vault statistics.
 */
app.get('/audit/stats', (_req: Request, res: Response) => {
  res.json(vault.getStats());
});

// ─── START ──────────────────────────────────────────────────────────────────

app.listen(PORT, () => {
  console.log('');
  console.log('  ╔══════════════════════════════════════════════════════╗');
  console.log('  ║      CRYPTOGRAPHIC AMNESIA — DAEMON v1.0.0           ║');
  console.log('  ║      AES-256-GCM · HMAC-SHA256 · Proof-of-Erasure    ║');
  console.log('  ╚══════════════════════════════════════════════════════╝');
  console.log('');
  console.log(`  API Server   →  http://localhost:${PORT}`);
  console.log(`  Dashboard    →  http://localhost:${PORT}/index.html`);
  console.log(`  Health       →  http://localhost:${PORT}/health`);
  console.log(`  Audit Log    →  http://localhost:${PORT}/audit/log`);
  console.log('');
  console.log('  Waiting for agent memory requests...\n');
});

export default app;
export { vault };
