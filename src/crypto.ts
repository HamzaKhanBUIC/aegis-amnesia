import crypto from 'crypto';

export const ALGORITHM = 'aes-256-gcm';
export const IV_LENGTH = 12;
export const AUTH_TAG_LENGTH = 16;
export const KEY_LENGTH = 32;

export interface EncryptedPayload {
  ciphertext: Buffer;
  iv: Buffer;
  authTag: Buffer;
  /** HMAC-SHA256 integrity proof over (iv || ciphertext || authTag) */
  integrityHmac: Buffer;
}

export interface ShredAttestation {
  /** Unique ID of the memory record that was shredded */
  recordId: string;
  /** SHA-256 hash of the key material at the time of shredding (computed BEFORE zeroing) */
  keyFingerprint: string;
  /** UTC ISO timestamp of when the shred occurred */
  shredAt: string;
  /** HMAC-SHA256 signature over (recordId + keyFingerprint + shredAt) using a session-level signing key */
  signature: string;
}

/**
 * The elite Cryptographic Engine for Ephemeral Memory.
 * Uses AES-256-GCM for AEAD encryption and HMAC-SHA256 for integrity attestation.
 */
export class AmnesiaCrypto {
  /** Session-level HMAC signing key for attestation. Never persisted. */
  private static readonly signingKey: Buffer = crypto.randomBytes(32);

  // ─── KEY LIFECYCLE ──────────────────────────────────────────────────────────

  /** Generates a 256-bit cryptographically-random ephemeral key. */
  static generateEphemeralKey(): Buffer {
    return crypto.randomBytes(KEY_LENGTH);
  }

  /**
   * Computes the SHA-256 fingerprint of a key for attestation purposes.
   * This is computed BEFORE the key is shredded.
   */
  static fingerprintKey(key: Buffer): string {
    return crypto.createHash('sha256').update(key).digest('hex');
  }

  /**
   * Cryptographically shreds a key by overwriting its Buffer allocation with zeros.
   * This ensures the key bytes are wiped from the Node.js heap before GC can reap them,
   * preventing memory scanning attacks.
   */
  static shredKey(key: Buffer): void {
    key.fill(0);
  }

  // ─── ENCRYPTION ─────────────────────────────────────────────────────────────

  /**
   * Encrypts a plaintext string using AES-256-GCM.
   * Appends an HMAC-SHA256 integrity proof over the full ciphertext envelope.
   */
  static encrypt(plaintext: string, key: Buffer): EncryptedPayload {
    const iv = crypto.randomBytes(IV_LENGTH);
    const cipher = crypto.createCipheriv(ALGORITHM, key, iv, {
      authTagLength: AUTH_TAG_LENGTH,
    } as any);

    const ciphertext = Buffer.concat([
      cipher.update(plaintext, 'utf8'),
      cipher.final(),
    ]);
    const authTag = cipher.getAuthTag();

    // Compute HMAC-SHA256 over the full envelope for tamper detection
    const hmac = crypto.createHmac('sha256', key);
    hmac.update(iv);
    hmac.update(ciphertext);
    hmac.update(authTag);
    const integrityHmac = hmac.digest();

    return { ciphertext, iv, authTag, integrityHmac };
  }

  // ─── DECRYPTION ─────────────────────────────────────────────────────────────

  /**
   * Decrypts an encrypted payload. Verifies HMAC integrity before decrypting.
   * Will throw if the key has been shredded (zeroed-out key produces invalid auth tag).
   */
  static decrypt(payload: EncryptedPayload, key: Buffer): string {
    // First verify HMAC integrity to detect tampering
    const hmac = crypto.createHmac('sha256', key);
    hmac.update(payload.iv);
    hmac.update(payload.ciphertext);
    hmac.update(payload.authTag);
    const expectedHmac = hmac.digest();

    if (!crypto.timingSafeEqual(payload.integrityHmac, expectedHmac)) {
      throw new Error('INTEGRITY_VIOLATION: HMAC mismatch — payload tampered or key is zeroed.');
    }

    const decipher = crypto.createDecipheriv(ALGORITHM, key, payload.iv, {
      authTagLength: AUTH_TAG_LENGTH,
    } as any);
    decipher.setAuthTag(payload.authTag);

    return Buffer.concat([
      decipher.update(payload.ciphertext),
      decipher.final(),
    ]).toString('utf8');
  }

  // ─── ATTESTATION ────────────────────────────────────────────────────────────

  /**
   * Produces a signed Proof of Erasure attestation.
   * Call this BEFORE calling shredKey() so the fingerprint can be computed.
   */
  static proveErasure(recordId: string, key: Buffer): ShredAttestation {
    const keyFingerprint = AmnesiaCrypto.fingerprintKey(key);
    const shredAt = new Date().toISOString();

    const message = `${recordId}:${keyFingerprint}:${shredAt}`;
    const signature = crypto
      .createHmac('sha256', AmnesiaCrypto.signingKey)
      .update(message)
      .digest('hex');

    return { recordId, keyFingerprint, shredAt, signature };
  }

  /**
   * Verifies a Proof of Erasure attestation against the session signing key.
   */
  static verifyErasure(attestation: ShredAttestation): boolean {
    const message = `${attestation.recordId}:${attestation.keyFingerprint}:${attestation.shredAt}`;
    const expected = crypto
      .createHmac('sha256', AmnesiaCrypto.signingKey)
      .update(message)
      .digest('hex');
    return attestation.signature === expected;
  }
}
