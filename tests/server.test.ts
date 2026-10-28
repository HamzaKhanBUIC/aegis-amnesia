import crypto from 'crypto';
import { once } from 'events';
import type { Server } from 'http';
import type { AddressInfo } from 'net';
import { describe, it, expect, beforeAll, afterAll, vi } from 'vitest';
import { startServer } from '../src/server';

const TOKEN = crypto.randomBytes(32).toString('hex');
const WRONG_TOKEN = crypto.randomBytes(32).toString('hex');

describe('HTTP daemon', () => {
  let server: Server;
  let base: string;
  const savedHost = process.env.HOST;

  beforeAll(async () => {
    vi.spyOn(console, 'log').mockImplementation(() => {});
    vi.spyOn(console, 'warn').mockImplementation(() => {});
    vi.stubEnv('AMNESIA_TOKEN', TOKEN);
    delete process.env.HOST;

    server = startServer(0);
    await once(server, 'listening');
    base = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
  });

  afterAll(async () => {
    server.close();
    await once(server, 'close');
    vi.unstubAllEnvs();
    vi.restoreAllMocks();
    if (savedHost !== undefined) process.env.HOST = savedHost;
  });

  const auth = (token: string) => ({ Authorization: `Bearer ${token}` });

  const store = (headers: Record<string, string> = {}) =>
    fetch(`${base}/memory/store`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', ...headers },
      body: JSON.stringify({ label: 'api-key', plaintext: 'secret-value', ttlMs: 10_000 }),
    });

  describe('binding', () => {
    it('binds to 127.0.0.1 when HOST is not set', () => {
      expect((server.address() as AddressInfo).address).toBe('127.0.0.1');
    });
  });

  describe('startup without a token', () => {
    it('refuses to start when AMNESIA_TOKEN is unset', () => {
      vi.stubEnv('AMNESIA_TOKEN', '');
      try {
        expect(() => startServer(0)).toThrow(/AMNESIA_TOKEN/);
      } finally {
        vi.stubEnv('AMNESIA_TOKEN', TOKEN);
      }
    });

    it('refuses to start when AMNESIA_TOKEN is too short', () => {
      vi.stubEnv('AMNESIA_TOKEN', 'short');
      try {
        expect(() => startServer(0)).toThrow(/at least 16 characters/);
      } finally {
        vi.stubEnv('AMNESIA_TOKEN', TOKEN);
      }
    });
  });

  describe('token auth', () => {
    const protectedRoutes: Array<[string, string]> = [
      ['GET', '/memory'],
      ['GET', '/memory/some-id'],
      ['POST', '/memory/store'],
      ['DELETE', '/memory/some-id'],
      ['GET', '/audit/log'],
      ['GET', '/audit/stats'],
    ];

    it.each(protectedRoutes)('%s %s without a token returns 401', async (method, route) => {
      const res = await fetch(`${base}${route}`, { method });
      expect(res.status).toBe(401);
      expect(res.headers.get('www-authenticate')).toBe('Bearer');
    });

    it.each(protectedRoutes)('%s %s with a wrong token returns 401', async (method, route) => {
      const res = await fetch(`${base}${route}`, { method, headers: auth(WRONG_TOKEN) });
      expect(res.status).toBe(401);
    });

    it('rejects a non-Bearer Authorization scheme', async () => {
      const basic = Buffer.from(`user:${TOKEN}`).toString('base64');
      const res = await fetch(`${base}/memory`, { headers: { Authorization: `Basic ${basic}` } });
      expect(res.status).toBe(401);
    });

    it('does not store anything for an unauthenticated request', async () => {
      expect((await store()).status).toBe(401);
      const list = await fetch(`${base}/memory`, { headers: auth(TOKEN) });
      expect((await list.json()).records).toHaveLength(0);
    });

    it('stores, reads and shreds with the correct token', async () => {
      const created = await store(auth(TOKEN));
      expect(created.status).toBe(201);
      const { id } = await created.json();

      const read = await fetch(`${base}/memory/${id}`, { headers: auth(TOKEN) });
      expect(read.status).toBe(200);
      expect((await read.json()).plaintext).toBe('secret-value');

      const shred = await fetch(`${base}/memory/${id}`, { method: 'DELETE', headers: auth(TOKEN) });
      expect(shred.status).toBe(200);
    });

    it('rejects every request when the token is unset at runtime (fails closed)', async () => {
      vi.stubEnv('AMNESIA_TOKEN', '');
      try {
        const res = await fetch(`${base}/memory`, { headers: auth('') });
        expect(res.status).toBe(503);
      } finally {
        vi.stubEnv('AMNESIA_TOKEN', TOKEN);
      }
    });

    it('keeps /health public', async () => {
      const res = await fetch(`${base}/health`);
      expect(res.status).toBe(200);
    });
  });

  describe('CORS', () => {
    it('sends no Access-Control-Allow-Origin header to other origins', async () => {
      const res = await fetch(`${base}/memory`, {
        headers: { ...auth(TOKEN), Origin: 'https://evil.example' },
      });
      expect(res.status).toBe(200);
      expect(res.headers.get('access-control-allow-origin')).toBeNull();
    });

    it('does not answer CORS preflight requests', async () => {
      const res = await fetch(`${base}/memory/store`, {
        method: 'OPTIONS',
        headers: {
          Origin: 'https://evil.example',
          'Access-Control-Request-Method': 'POST',
          'Access-Control-Request-Headers': 'authorization,content-type',
        },
      });
      expect(res.headers.get('access-control-allow-origin')).toBeNull();
    });
  });

  describe('request body limit', () => {
    it('rejects bodies over 16 kb with 413', async () => {
      const res = await fetch(`${base}/memory/store`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', ...auth(TOKEN) },
        body: JSON.stringify({ label: 'big', plaintext: 'a'.repeat(20_000), ttlMs: 1000 }),
      });
      expect(res.status).toBe(413);
    });
  });
});
