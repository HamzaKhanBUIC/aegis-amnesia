# Cryptographic Amnesia 🧠💥

> **Ephemeral Self-Destructing Agent Memory with Mathematical Forgetting Guarantees**

[![License: MIT](https://img.shields.io/badge/License-MIT-purple.svg)](LICENSE)
[![Node.js](https://img.shields.io/badge/Node.js-v20+-green.svg)](https://nodejs.org)
[![AES-256-GCM](https://img.shields.io/badge/Encryption-AES--256--GCM-cyan.svg)](#)
[![Proof of Erasure](https://img.shields.io/badge/Attestation-HMAC--SHA256-blue.svg)](#)

---

## What Is This?

As autonomous AI agents process increasingly sensitive data — PII, API keys, financial records, corporate IP — traditional "delete" is **fundamentally insecure**. Deleted bytes linger in RAM, swap files, and OS buffers.

**Cryptographic Amnesia** solves this with a radical guarantee:

> Memory is encrypted with an ephemeral AES-256-GCM key. "Forgetting" means destroying the key — mathematically rendering the ciphertext permanently irretrievable, even with physical access to the machine.

---

## ⚡ Why Aegis-Amnesia is Different (The Paradigm Shift)

The AI industry is currently obsessed with giving agents **Infinite Memory** (RAG, long-term vector stores, conversation histories). But in enterprise, medical, and defense contexts, infinite memory is a massive liability. If a LangGraph agent is compromised, its entire memory store is exposed.

Aegis-Amnesia flips the script by introducing **Cryptographic Self-Destructing Memory**:
1. **Mathematical Deletion**: When standard apps delete data (`DELETE FROM memory`), the physical bytes remain on the SSD until overwritten. Aegis-Amnesia encrypts the data and only holds the key in volatile RAM. When the task is done, the key is wiped from RAM (`Buffer.fill(0)`). The data on the SSD is instantly and mathematically destroyed.
2. **Zero-Trust Agent Context**: Agents can now safely process API keys and PII. If an attacker dumps the database post-task, they only find AES-256 ciphertext.
3. **Proof of Erasure**: In enterprise compliance (GDPR, HIPAA), you must prove data was deleted. Aegis-Amnesia generates a cryptographic HMAC signature verifying the exact millisecond the key was shredded.

**This is not just a database wrapper; it is the ultimate data sovereignty tool for the agentic era.**

---

## Core Architecture

```
┌─────────────────────────────────────────────────────────┐
│                   AGENT / APPLICATION                   │
│                                                         │
│  vault.store("api-key", sensitiveData, ttl: 10s)        │
│  ↓                                                      │
│  ┌──────────────────────────────────────────────────┐   │
│  │              AMNESIA VAULT                       │   │
│  │                                                  │   │
│  │  AES-256-GCM encrypt → store ciphertext in RAM  │   │
│  │  Start TTL countdown ...                         │   │
│  │                                                  │   │
│  │  On expiry: HMAC-SHA256 attest → shredKey()     │   │
│  │             (Buffer.fill(0) overwrites in heap)  │   │
│  └──────────────────────────────────────────────────┘   │
│                                                         │
│  vault.retrieve(id) → null  ← Key is GONE              │
└─────────────────────────────────────────────────────────┘
```

### Three Core Components

| Component | File | Role |
|---|---|---|
| `AmnesiaCrypto` | `src/crypto.ts` | AES-256-GCM engine, HMAC integrity, Proof-of-Erasure |
| `AmnesiaVault` | `src/vault.ts` | Ephemeral store, TTL decay, audit log |
| HTTP Daemon | `src/server.ts` | REST API + static dashboard server |

---

## Cryptographic Guarantees

- **AES-256-GCM** — Authenticated encryption with 256-bit keys and 128-bit auth tags
- **HMAC-SHA256 Integrity** — Every payload includes an HMAC over `iv || ciphertext || authTag`
- **Memory Shredding** — `Buffer.fill(0)` zeroes the key in the Node.js heap before GC can reap it
- **Unique IVs** — Each encryption uses a fresh `crypto.randomBytes(12)` IV, preventing IV reuse attacks
- **Proof of Erasure** — Every shred event produces a signed `HMAC-SHA256` attestation: `recordId:keyFingerprint:shredAt`

---

## Quick Start

```bash
# Install
npm install

# Run the API daemon + dashboard
npm run dev

# Open dashboard
start http://localhost:3747
```

---

## REST API

### Store a Memory
```http
POST /memory/store
Content-Type: application/json

{
  "label": "user-api-key",
  "plaintext": "sk-live-abc123",
  "ttlMs": 10000
}
```

### Retrieve a Memory (JIT Decrypt)
```http
GET /memory/:id
```

### Force-Shred a Memory
```http
DELETE /memory/:id
```
Returns a signed **Proof of Erasure**:
```json
{
  "proofOfErasure": {
    "recordId": "uuid...",
    "keyFingerprint": "sha256-of-key...",
    "shredAt": "2026-05-31T00:00:00.000Z",
    "signature": "hmac-sha256..."
  },
  "attestationValid": true
}
```

### Audit Log
```http
GET /audit/log
```

---

## Run Tests

```bash
npm test
```

---

## License

MIT © Hamza Imran
