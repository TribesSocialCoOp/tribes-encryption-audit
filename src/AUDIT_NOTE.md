// NOTE: This file is extracted from the Tribes.app codebase for audit purposes.
// Some imports reference internal modules (e.g., @/lib/crypto/key-store) that are
// not included in this repository. The encryption/decryption functions below are
// self-contained — they use only the Web Crypto API and the ./encoding helpers.
//
// The key management functions (getOrCreateJournalKey) interact with IndexedDB
// via the key-store module, which is part of the full application but not relevant
// to verifying the cryptographic operations themselves.

