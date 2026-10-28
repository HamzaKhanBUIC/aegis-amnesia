import crypto from 'crypto';
import type { Server } from 'http';
import type { AddressInfo } from 'net';
import express, { Request, Response, NextFunction } from 'express';
import path from 'path';
import { AmnesiaVault } from './vault';
import { AmnesiaCrypto } from './crypto';

// ─── SETUP ──────────────────────────────────────────────────────────────────

const app = express();
const DEFAULT_PORT = 3747;
// Loopback only by default. Set HOST to expose the daemon on other interfaces.
const DEFAULT_HOST = '127.0.0.1';
export const MIN_TOKEN_LENGTH = 16;
const vault = new AmnesiaVault();

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

// ─── AUTH ───────────────────────────────────────────────────────────────────

/** Returns why AMNESIA_TOKEN is unusable, or null when it is set. */
export function tokenConfigError(token = process.env.AMNESIA_TOKEN): string | null {
  if (!token || token.length < MIN_TOKEN_LENGTH) {
    return `AMNESIA_TOKEN must be set to a random secret of at least ${MIN_TOKEN_LENGTH} characters ` +
      '(e.g. `openssl rand -hex 32`).';
  }
  return null;
}

function sha256(value: string): Buffer {
  return crypto.createHash('sha256').update(value, 'utf8').digest();
}

/**
 * Every /memory and /audit route requires `Authorization: Bearer <AMNESIA_TOKEN>`.
 * Fails closed: with no usable token configured, every request is rejected.
 * Both sides are hashed so the comparison is constant-time for any input length.
 */
function requireToken(req: Request, res: Response, next: NextFunction): void {
  const expected = process.env.AMNESIA_TOKEN;
  const configError = tokenConfigError(expected);
  if (configError) {
    res.status(503).json({ error: 'AUTH_NOT_CONFIGURED', message: configError });
    return;
  }

  const match = /^Bearer\s+(.+)$/i.exec(req.get('authorization') ?? '');
  if (!match || !crypto.timingSafeEqual(sha256(match[1]), sha256(expected!))) {
    res.status(401).set('WWW-Authenticate', 'Bearer').json({
      error: 'UNAUTHORIZED',
      message: 'Missing or invalid bearer token.',
    });
    return;
  }
  next();
}

app.use(['/memory', '/audit'], requireToken);
app.use(express.json({ limit: '16kb' }));

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

/**
 * Starts the daemon on PORT (default 3747) and HOST (default 127.0.0.1).
 * Throws instead of listening when AMNESIA_TOKEN is missing or too short.
 */
export function startServer(
  port = Number(process.env.PORT) || DEFAULT_PORT,
  host = process.env.HOST || DEFAULT_HOST,
): Server {
  const configError = tokenConfigError();
  if (configError) throw new Error(`Refusing to start: ${configError}`);

  const server = app.listen(port, host, (err?: Error) => {
    if (err) {
      console.error(`  Failed to listen on ${host}:${port}: ${err.message}`);
      process.exitCode = 1;
      return;
    }
    const base = `http://${host}:${(server.address() as AddressInfo).port}`;
    console.log('');
    console.log('  ╔══════════════════════════════════════════════════════╗');
    console.log('  ║      CRYPTOGRAPHIC AMNESIA — DAEMON v1.0.0           ║');
    console.log('  ║      AES-256-GCM · HMAC-SHA256 · Proof-of-Erasure    ║');
    console.log('  ╚══════════════════════════════════════════════════════╝');
    console.log('');
    console.log(`  API Server   →  ${base}`);
    console.log(`  Dashboard    →  ${base}/index.html`);
    console.log(`  Health       →  ${base}/health`);
    console.log(`  Audit Log    →  ${base}/audit/log`);
    console.log('');
    if (!['127.0.0.1', '::1', 'localhost'].includes(host)) {
      console.warn(`  WARNING: HOST=${host} exposes the daemon beyond this machine.\n`);
    }
    console.log('  Waiting for agent memory requests...\n');
  });
  return server;
}

if (require.main === module) {
  try {
    startServer();
  } catch (err) {
    console.error(`\n  ${(err as Error).message}\n`);
    process.exit(1);
  }
}

export default app;
export { vault };
