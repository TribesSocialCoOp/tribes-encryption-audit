# Tribes.app Encryption Audit

**Red-team attack test and source code for the Tribes.app client-side encryption layer.**

This repository contains:

1. **The attack script** — connects to a PostgreSQL database with full read access and runs 30+ attack vectors against real encrypted posts, attempting to recover plaintext without any private keys.
2. **The encryption source code** — the actual production files that implement E2E encryption in Tribes.app.

This is not the full Tribes.app codebase. It's the subset that matters for verifying our encryption claims.

---

## Why This Exists

Tribes.app uses client-side E2E encryption for private tribes, journal posts, and bond messages. We claim that our servers store only ciphertext and cannot read your private data.

Instead of asking you to take our word for it, we:

1. Posted known plaintext through the real app UI
2. Gave ourselves full database access
3. Tried every attack we could think of to recover the plaintext
4. Published the script and the results

**Result: 30 attacks, 0 plaintext recovered.**

Read the full writeup: **We Red-Teamed Our Own Encryption** *(link will be added once published)*

---

## Repository Structure

```
├── attack-test.ts            # The red-team attack script (30 attack vectors)
├── schema-and-seed.sql       # Schema + real encrypted blobs (extracted from our dev DB)
├── src/
│   ├── tribe-encryption.ts   # AES-256-GCM group key encryption (private tribes)
│   ├── journal-encryption.ts # AES-256-GCM personal key encryption (journal)
│   ├── post-encryption.ts    # Sender-key model for pairwise bond encryption
│   ├── identity-keys.ts      # RSA-OAEP 4096-bit key wrapping (tribe key distribution)
│   ├── encoding.ts           # Base64 encoding helpers
│   └── prf-vault.ts          # PRF-based key vault encryption (passkey + hardware auth)
└── README.md
```

---

## Encryption Architecture

### Three Encryption Models

| Model | Context | Algorithm | Key Storage |
|-------|---------|-----------|-------------|
| **Personal** | Journal entries | AES-256-GCM (per-user symmetric key) | IndexedDB |
| **Pairwise** | Bond messages (Inner Circle, My People) | ECDH P-256 → HKDF → AES-256-GCM | IndexedDB |
| **Group** | Private tribe posts | AES-256-GCM (shared symmetric key, RSA-OAEP wrapped distribution) | IndexedDB |

### What the Server Stores

- ✅ Ciphertext (opaque binary blobs)
- ✅ IVs (random, unique per post)
- ✅ RSA-wrapped tribe key copies (useless without recipient's RSA private key)
- ✅ ECDH public keys (useless without the corresponding private key)

### What the Server Does NOT Store

- ❌ Any plaintext post content
- ❌ Any raw symmetric keys
- ❌ Any RSA or ECDH private keys
- ❌ Any vault passphrases

---

## Running the Attack Script

You don't need the Tribes app. You just need PostgreSQL and Node.

### Prerequisites

- Node.js 20+
- PostgreSQL (local or Docker)

### Setup

```bash
# 1. Create a test database and load the schema + real encrypted blobs
createdb tribes_audit
psql tribes_audit < schema-and-seed.sql

# 2. Install the pg driver
npm install pg

# 3. Run the attack
DATABASE_URL="postgresql://localhost/tribes_audit" npx tsx attack-test.ts
```

The seed file contains the actual database schema extracted from our dev environment and three real AES-256-GCM encrypted posts created through the browser UI. The original plaintext is listed in the comments. Try to recover it.

### Expected Output

```
╔═══════════════════════════════════════════════════╗
║  TRIBES.APP ENCRYPTION EMPIRICAL ATTACK TEST      ║
║  Threat model: Full DB access, NO private keys    ║
║  Data: Real posts from browser E2E flow           ║
╚═══════════════════════════════════════════════════╝

═══ PHASE 2: RUNNING ATTACK VECTORS ════════════

  🔒 SECURE | Plaintext in content column → Only placeholder "🔒 Encrypted post" — no leak
  🔒 SECURE | Known plaintext in ciphertext → "ALPHA-BRAVO-7749" NOT found — properly encrypted
  🔒 SECURE | 1000 random AES-256 keys → All 1000 keys rejected by GCM auth tag
  ...

═══════════════════════════════════════════════════
  RESULTS SUMMARY
═══════════════════════════════════════════════════

  Total attacks:  30
  🔒 Held:        30
  🔓 Broken:      0

  ✅ ALL ATTACKS FAILED.
```

---

## Attack Vectors Covered

1. Plaintext leakage in DB text columns
2. Ciphertext entropy / randomness analysis
3. Ciphertext-as-text readability test
4. Known plaintext byte search (8 identifiable phrases)
5. IV uniqueness and length validation
6. 1,000 random AES-256 key brute force attempts
7. GCM authentication tag tampering
8. Cross-post XOR ciphertext correlation
9. Tribe key unwrap with wrong RSA-4096 key
10. RSA public key factorization feasibility
11. RSA public key as decryption key (one-way trapdoor test)
12. Vault backup PBKDF2 brute force estimation
13. Full SQL `ILIKE` text search for known plaintext

---

## Browser Encryption: Honest Threat Model

We are transparent about what browser-based encryption does and does not protect against:

### ✅ Protects Against

- **Database breach** — ciphertext only, no plaintext recoverable
- **Malicious server operator** — server never sees keys or plaintext
- **Bulk surveillance** — encrypted data is computationally infeasible to decrypt at scale
- **Data subpoena** — we can only hand over ciphertext we can't read

### ⚠️ Does NOT Protect Against

- **Compromised device** — physical access to the device with an active session
- **Malicious browser extension** - an extension with broad permissions can read page data (mitigated by PRF Vault encrypting keys at rest)
- **Browser zero-day** - a remote code execution vulnerability in the browser engine
- **Malicious code push** - if we shipped JavaScript that exfiltrated keys (mitigated by source hash verification below)

These limitations apply equally to Signal Desktop, ProtonMail, 1Password in the browser, and every other application that performs cryptography in the browser environment.

---

## Verifying Deployed Code

Every production deploy automatically hashes the crypto source files and publishes the result to [`crypto-integrity.json`](crypto-integrity.json) in this repo.

### Verify source file integrity

```bash
# 1. Get the published hashes
curl -s https://raw.githubusercontent.com/TribesSocialCoOp/tribes-encryption-audit/main/crypto-integrity.json

# 2. Hash any source file in this repo and compare
shasum -a 256 src/tribe-encryption.ts
```

The source files in this repo are identical to the ones used in production builds. If the hashes match, the code running on tribes.app is the code you see here.

---

## License

MIT License. See [LICENSE](LICENSE) for details.

This is the actual production encryption code from Tribes.app, open-sourced for transparency and independent verification.

---

*Questions? Open an issue or reach out at security@tribes.app.*
