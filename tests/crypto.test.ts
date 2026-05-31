import { describe, it, expect } from 'vitest';
import { AmnesiaCrypto } from '../src/crypto';

describe('AmnesiaCrypto', () => {

  describe('Key Generation', () => {
    it('generates a 32-byte ephemeral key', () => {
      const key = AmnesiaCrypto.generateEphemeralKey();
      expect(key).toBeInstanceOf(Buffer);
      expect(key.length).toBe(32);
    });

    it('generates unique keys each time', () => {
      const k1 = AmnesiaCrypto.generateEphemeralKey();
      const k2 = AmnesiaCrypto.generateEphemeralKey();
      expect(k1.equals(k2)).toBe(false);
    });
  });

  describe('Encrypt / Decrypt', () => {
    it('encrypts and decrypts a plaintext string correctly', () => {
      const key = AmnesiaCrypto.generateEphemeralKey();
      const plaintext = 'SSN: 000-00-0000, API_KEY: sk-live-abc123';
      const payload = AmnesiaCrypto.encrypt(plaintext, key);
      const decrypted = AmnesiaCrypto.decrypt(payload, key);
      expect(decrypted).toBe(plaintext);
    });

    it('produces different ciphertext for the same input (unique IVs)', () => {
      const key = AmnesiaCrypto.generateEphemeralKey();
      const p1 = AmnesiaCrypto.encrypt('hello', key);
      const p2 = AmnesiaCrypto.encrypt('hello', key);
      expect(p1.ciphertext.equals(p2.ciphertext)).toBe(false);
      expect(p1.iv.equals(p2.iv)).toBe(false);
    });

    it('throws on tampered ciphertext (HMAC integrity check)', () => {
      const key = AmnesiaCrypto.generateEphemeralKey();
      const payload = AmnesiaCrypto.encrypt('secret', key);
      // Tamper with the ciphertext
      payload.ciphertext[0] ^= 0xff;
      expect(() => AmnesiaCrypto.decrypt(payload, key)).toThrow('INTEGRITY_VIOLATION');
    });
  });

  describe('Key Shredding', () => {
    it('zeros out the key buffer on shred', () => {
      const key = AmnesiaCrypto.generateEphemeralKey();
      // Confirm key is not all zeros before shred
      const wasNonZero = key.some(b => b !== 0);
      expect(wasNonZero).toBe(true);

      AmnesiaCrypto.shredKey(key);

      const isAllZero = key.every(b => b === 0);
      expect(isAllZero).toBe(true);
    });

    it('makes decryption fail after key is shredded', () => {
      const key = AmnesiaCrypto.generateEphemeralKey();
      const payload = AmnesiaCrypto.encrypt('top-secret', key);

      // Shred the key
      AmnesiaCrypto.shredKey(key);

      // Decryption must fail — zeroed key produces invalid HMAC
      expect(() => AmnesiaCrypto.decrypt(payload, key)).toThrow();
    });
  });

  describe('Proof of Erasure', () => {
    it('produces a valid, verifiable attestation before shredding', () => {
      const key = AmnesiaCrypto.generateEphemeralKey();
      const attestation = AmnesiaCrypto.proveErasure('test-record-001', key);

      expect(attestation.recordId).toBe('test-record-001');
      expect(attestation.keyFingerprint).toHaveLength(64); // SHA-256 hex
      expect(attestation.shredAt).toBeTruthy();
      expect(attestation.signature).toBeTruthy();

      const valid = AmnesiaCrypto.verifyErasure(attestation);
      expect(valid).toBe(true);
    });

    it('rejects a tampered attestation', () => {
      const key = AmnesiaCrypto.generateEphemeralKey();
      const attestation = AmnesiaCrypto.proveErasure('tamper-test', key);

      // Tamper with the timestamp
      const tampered = { ...attestation, shredAt: '1970-01-01T00:00:00.000Z' };
      expect(AmnesiaCrypto.verifyErasure(tampered)).toBe(false);
    });
  });
});
