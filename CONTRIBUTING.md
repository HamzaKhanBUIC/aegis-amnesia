# Contributing to Cryptographic Amnesia

Thank you for your interest in contributing to **Aegis-Amnesia**! This project aims to bring enterprise-grade data sovereignty and zero-trust memory management to the Agentic AI space.

We welcome all contributions: architectural improvements, bug fixes, integration SDKs for other frameworks (like AutoGen or CrewAI), and documentation enhancements.

## 🧠 Core Philosophy
1. **Security First**: Cryptography is hard. Any PR modifying `src/crypto.ts` or the memory shredding logic will require rigorous review and proof that keys cannot leak.
2. **Mathematical Guarantees**: We do not rely on OS-level file deletion. We rely on AES-256 and RAM zeroization (`Buffer.fill(0)`).
3. **Auditability**: Every shredding event must generate a mathematically verifiable HMAC-SHA256 Proof of Erasure.

---

## 🛠️ How to Contribute

### 1. Fork & Clone
Start by forking the repository to your own GitHub account, then clone it locally:
```bash
git clone https://github.com/YOUR_USERNAME/aegis-amnesia.git
cd aegis-amnesia
```

### 2. Create a Branch
Use a descriptive name for your branch:
```bash
git checkout -b feature/langgraph-native-interceptor
# or
git checkout -b fix/hmac-validation-edgecase
```

### 3. Setup Your Environment
```bash
npm install
npm run build
```

### 4. Running Tests
Our CI requires 100% pass rates for cryptographic tests. Ensure you run the test suite before submitting a PR:
```bash
npm test
```

### 5. Open a Pull Request (PR)
Go to the original Aegis-Amnesia repository and open a Pull Request. Provide a clear description of what you changed, why you changed it, and confirm that all tests pass.

---

## 🐞 Reporting Security Vulnerabilities
If you discover a cryptographic flaw, a key-leakage vulnerability, or an issue with the Proof of Erasure mechanism, **DO NOT open a public issue**. Please reach out to the maintainers directly via secure channels.

For non-security bugs, feel free to open a standard GitHub Issue with reproduction steps.

---
*Thank you for helping us secure the future of Agentic AI.*
