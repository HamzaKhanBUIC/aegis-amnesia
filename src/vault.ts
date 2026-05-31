import { v4 as uuidv4 } from 'uuid';
import { AmnesiaCrypto, EncryptedPayload, ShredAttestation } from './crypto';

// ─── TYPES ──────────────────────────────────────────────────────────────────

export type MemoryState = 'active' | 'shredded';

export interface VaultRecord {
  id: string;
  label: string;
  payload: EncryptedPayload;
  key: Buffer;
  createdAt: number;
  expiresAt: number;
  ttlMs: number;
  state: MemoryState;
  timeoutId?: ReturnType<typeof setTimeout>;
}

export interface VaultRecordPublic {
  id: string;
  label: string;
  state: MemoryState;
  createdAt: number;
  expiresAt: number;
  ttlMs: number;
  remainingMs: number;
}

export interface AuditEvent {
  eventId: string;
  type: 'STORED' | 'ACCESSED' | 'SHREDDED' | 'SHRED_FAILED';
  recordId: string;
  label: string;
  timestamp: string;
  attestation?: ShredAttestation;
  metadata?: Record<string, string | number | boolean>;
}

// ─── VAULT ──────────────────────────────────────────────────────────────────

/**
 * AmnesiaVault — The secure, time-bounded ephemeral memory store.
 *
 * Each record is encrypted with a unique AES-256-GCM key.
 * Keys are shredded (zeroed-out in memory) automatically when their TTL expires,
 * or immediately on demand. Every shred event produces a signed attestation.
 */
export class AmnesiaVault {
  private records: Map<string, VaultRecord> = new Map();
  private auditLog: AuditEvent[] = [];
  private readonly maxAuditLogSize = 1000;

  // ─── STORE ──────────────────────────────────────────────────────────────────

  /**
   * Encrypts and stores a context payload with a finite TTL.
   * @returns The opaque record ID
   */
  public store(label: string, plaintext: string, ttlMs: number): string {
    const id = uuidv4();
    const key = AmnesiaCrypto.generateEphemeralKey();
    const payload = AmnesiaCrypto.encrypt(plaintext, key);
    const now = Date.now();

    const timeoutId = setTimeout(() => this._ttlShred(id), ttlMs);

    const record: VaultRecord = {
      id,
      label,
      payload,
      key,
      createdAt: now,
      expiresAt: now + ttlMs,
      ttlMs,
      state: 'active',
      timeoutId,
    };

    this.records.set(id, record);
    this._audit({ type: 'STORED', recordId: id, label, metadata: { ttlMs } });
    return id;
  }

  // ─── RETRIEVE ───────────────────────────────────────────────────────────────

  /**
   * Decrypts and returns the context if the key is still alive.
   * Returns null if the record does not exist or has been shredded.
   */
  public retrieve(id: string): string | null {
    const record = this.records.get(id);
    if (!record || record.state === 'shredded') {
      return null;
    }

    try {
      const plaintext = AmnesiaCrypto.decrypt(record.payload, record.key);
      this._audit({ type: 'ACCESSED', recordId: id, label: record.label });
      return plaintext;
    } catch {
      this._audit({ type: 'SHRED_FAILED', recordId: id, label: record.label });
      return null;
    }
  }

  // ─── SHRED ──────────────────────────────────────────────────────────────────

  /**
   * Immediately and irreversibly shreds the encryption key for a record.
   * Produces a signed Proof of Erasure attestation.
   */
  public shred(id: string): ShredAttestation | null {
    const record = this.records.get(id);
    if (!record || record.state === 'shredded') return null;
    return this._executeShred(record, 'manual');
  }

  private _ttlShred(id: string): void {
    const record = this.records.get(id);
    if (!record || record.state === 'shredded') return;
    this._executeShred(record, 'ttl-expiry');
  }

  private _executeShred(record: VaultRecord, trigger: string): ShredAttestation {
    // Compute attestation BEFORE zeroing the key
    const attestation = AmnesiaCrypto.proveErasure(record.id, record.key);

    // Zero-overwrite the key in heap memory
    AmnesiaCrypto.shredKey(record.key);

    // Mark state
    record.state = 'shredded';
    if (record.timeoutId) clearTimeout(record.timeoutId);

    this._audit({
      type: 'SHREDDED',
      recordId: record.id,
      label: record.label,
      attestation,
      metadata: { trigger },
    });

    return attestation;
  }

  // ─── INSPECTION ─────────────────────────────────────────────────────────────

  /** Returns a sanitized view of all active records (no keys or ciphertext). */
  public listActive(): VaultRecordPublic[] {
    const now = Date.now();
    const results: VaultRecordPublic[] = [];
    for (const r of this.records.values()) {
      if (r.state === 'active') {
        results.push({
          id: r.id,
          label: r.label,
          state: r.state,
          createdAt: r.createdAt,
          expiresAt: r.expiresAt,
          ttlMs: r.ttlMs,
          remainingMs: Math.max(0, r.expiresAt - now),
        });
      }
    }
    return results;
  }

  /** Returns the immutable audit log. */
  public getAuditLog(): AuditEvent[] {
    return [...this.auditLog];
  }

  /** Returns vault statistics. */
  public getStats() {
    let active = 0;
    let shredded = 0;
    for (const r of this.records.values()) {
      r.state === 'active' ? active++ : shredded++;
    }
    return { active, shredded, total: this.records.size, auditEvents: this.auditLog.length };
  }

  // ─── PRIVATE ────────────────────────────────────────────────────────────────

  private _audit(event: Omit<AuditEvent, 'eventId' | 'timestamp'>): void {
    const entry: AuditEvent = {
      eventId: uuidv4(),
      timestamp: new Date().toISOString(),
      ...event,
    };

    if (this.auditLog.length >= this.maxAuditLogSize) {
      this.auditLog.shift(); // Ring-buffer behavior
    }
    this.auditLog.push(entry);
  }
}
