# Security Policy

Report suspected vulnerabilities privately to **security@really.me**. Do not
open a public issue. For encrypted disclosure, request our current PGP key
before sending details.

Include the affected version and platform, a minimal reproducer, and the
security impact. Do not send production secrets, private keys, access tokens,
or personal data.

Reports may concern any Rust crate, C/JNI adapter, Swift, Kotlin/JVM, Android,
or TypeScript/WASM package in this repository. Platform support is listed in
the [supported JOSE surface](README.md#supported-jose-surface).

## Signature identity

ES256 verification accepts valid high-S P-256 signatures. Different compact
JWS or JWT strings can therefore authenticate the same claims. Use validated
claims and issuer-controlled identifiers for deduplication, revocation, and
cache keys instead of treating raw token bytes as a unique identity.
ES256K verification rejects high-S signatures.

## JWE sender authentication

JWE decryption authenticates the protected header and ciphertext under the
content-encryption key; it does not identify the sender. With `dir`, anyone
holding that key can create a message. With `ECDH-ES`, anyone holding the
recipient's public key can create one.

Require an independently verified signature or a key-distribution protocol
that establishes the sender's identity before trusting decrypted claims.
Binding `kid`, `typ`, `cty`, `apu`, or `apv` constrains the protocol context but
does not establish sender identity.

## Compression

Compression is disabled by default. Opting in enables raw DEFLATE (`DEF`)
before encryption. Decryption verifies the AES-GCM tag before any inflate work
and limits decompressed plaintext to 1 MiB.

Do not combine secrets with attacker-controlled data in compressed plaintext
when ciphertext length is observable: this can create a compression side
channel. Leave compression disabled when strict memory erasure is required;
codec workspaces and allocator copies may retain plaintext.

## WASM deployment

Install a trusted WASM provider before using the TypeScript facade. Pin and
review the module, bundler configuration, and host Web Crypto randomness source;
a substituted module can fabricate results. ECDH-ES P-384 and P-521 are
unsupported in WASM and return `providerUnsupported`.
