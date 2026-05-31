import { describe, it, expect, beforeEach, vi, afterEach } from 'vitest';
import { AmnesiaVault } from '../src/vault';

describe('AmnesiaVault', () => {
  let vault: AmnesiaVault;

  beforeEach(() => {
    vault = new AmnesiaVault();
    vi.useFakeTimers();
  });

  afterEach(() => {
    vi.useRealTimers();
  });

  describe('store & retrieve', () => {
    it('stores and retrieves a plaintext payload', () => {
      const id = vault.store('api-key', 'sk-live-supersecret', 10_000);
      const result = vault.retrieve(id);
      expect(result).toBe('sk-live-supersecret');
    });

    it('returns null for a non-existent id', () => {
      expect(vault.retrieve('non-existent-id')).toBeNull();
    });

    it('generates unique IDs for each store call', () => {
      const id1 = vault.store('a', 'foo', 5000);
      const id2 = vault.store('b', 'bar', 5000);
      expect(id1).not.toBe(id2);
    });
  });

  describe('TTL-based auto-shredding', () => {
    it('auto-shreds after TTL expires', () => {
      const id = vault.store('session', 'user-session-token', 5000);

      // Before TTL
      expect(vault.retrieve(id)).toBe('user-session-token');

      // Advance time past TTL
      vi.advanceTimersByTime(5001);

      // After TTL — must be null
      expect(vault.retrieve(id)).toBeNull();
    });

    it('records a SHREDDED audit event on TTL expiry', () => {
      const id = vault.store('temp', 'data', 3000);
      vi.advanceTimersByTime(3001);

      const log = vault.getAuditLog();
      const shredEvent = log.find(e => e.type === 'SHREDDED' && e.recordId === id);
      expect(shredEvent).toBeDefined();
      expect(shredEvent?.attestation).toBeDefined();
    });
  });

  describe('forced shred', () => {
    it('shred() makes retrieve return null immediately', () => {
      const id = vault.store('secret', 'my-private-key', 60_000);
      expect(vault.retrieve(id)).not.toBeNull();

      vault.shred(id);
      expect(vault.retrieve(id)).toBeNull();
    });

    it('shred() returns a valid attestation', () => {
      const id = vault.store('secret', 'data', 60_000);
      const attestation = vault.shred(id);
      expect(attestation).not.toBeNull();
      expect(attestation?.recordId).toBe(id);
      expect(attestation?.keyFingerprint).toHaveLength(64);
    });

    it('shred() on already-shredded record returns null', () => {
      const id = vault.store('x', 'y', 60_000);
      vault.shred(id);
      const result = vault.shred(id);
      expect(result).toBeNull();
    });
  });

  describe('audit log', () => {
    it('logs STORED event on store()', () => {
      const id = vault.store('item', 'value', 5000);
      const log = vault.getAuditLog();
      expect(log.some(e => e.type === 'STORED' && e.recordId === id)).toBe(true);
    });

    it('logs ACCESSED event on retrieve()', () => {
      const id = vault.store('item', 'value', 5000);
      vault.retrieve(id);
      const log = vault.getAuditLog();
      expect(log.some(e => e.type === 'ACCESSED' && e.recordId === id)).toBe(true);
    });

    it('logs SHREDDED event on shred()', () => {
      const id = vault.store('item', 'value', 5000);
      vault.shred(id);
      const log = vault.getAuditLog();
      expect(log.some(e => e.type === 'SHREDDED' && e.recordId === id)).toBe(true);
    });
  });

  describe('stats', () => {
    it('tracks active and shredded counts correctly', () => {
      const id1 = vault.store('a', 'val1', 60_000);
      const id2 = vault.store('b', 'val2', 60_000);

      expect(vault.getStats().active).toBe(2);
      expect(vault.getStats().shredded).toBe(0);

      vault.shred(id1);

      expect(vault.getStats().active).toBe(1);
      expect(vault.getStats().shredded).toBe(1);
    });
  });

  describe('listActive', () => {
    it('only lists active records', () => {
      const id1 = vault.store('alive', 'data', 60_000);
      const id2 = vault.store('dead', 'data', 60_000);
      vault.shred(id2);

      const active = vault.listActive();
      expect(active.map(r => r.id)).toContain(id1);
      expect(active.map(r => r.id)).not.toContain(id2);
    });

    it('computes remainingMs correctly', () => {
      const id = vault.store('timed', 'data', 10_000);
      vi.advanceTimersByTime(4000);
      const active = vault.listActive();
      const record = active.find(r => r.id === id);
      expect(record?.remainingMs).toBeLessThan(7000);
      expect(record?.remainingMs).toBeGreaterThan(5000);
    });
  });
});
