// SPDX-FileCopyrightText: 2026 ReallyMe LLC
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Compact JWS, JWT, and JWE helpers.
//!
//! `reallyme-jose` owns JOSE byte-format mechanics for compact JWS, JWT, and
//! JWE. Cryptographic operations are routed through `reallyme-crypto`; this
//! crate adds JOSE header policy, compact serialization, algorithm/key binding,
//! temporal JWT policy, and JWE content-encryption handling.
//!
//! # Example
//!
//! ```
//! use reallyme_jose::jwt::{decode_unsigned_jwt, encode_unsigned_jwt};
//!
//! let claims = serde_json::json!({
//!     "iss": "did:me:issuer",
//!     "sub": "alice",
//! });
//! let compact = encode_unsigned_jwt(&claims)?;
//! let decoded: serde_json::Value = decode_unsigned_jwt(&compact)?;
//!
//! assert_eq!(decoded.get("sub"), Some(&serde_json::json!("alice")));
//! # Ok::<(), reallyme_jose::jwt::JwtError>(())
//! ```
//!
//! Unsigned JWT decoding is a parser for profiles that explicitly allow
//! `alg = "none"`; it does not authenticate the sender. Use the signed JWT
//! verification APIs for verifier-grade paths.

#[cfg(not(any(feature = "native", feature = "wasm")))]
compile_error!("reallyme-jose requires a supported runtime lane: enable feature `native` for native Rust cryptography or `wasm` for the WebAssembly lane with package-owned cryptography.");

/// Crypto algorithm selector used by JOSE/JWT public APIs.
///
/// Consumers should import this re-export instead of depending directly on
/// `reallyme-crypto`; that keeps the algorithm type identical to the one used
/// by `reallyme-jose`.
#[cfg(any(feature = "native", feature = "wasm"))]
pub use reallyme_crypto::{core::Algorithm, csprng::SecureRandom, jwk::Jwk, signer::Signer};

/// JSON value type used by claim maps and protected-header values.
#[cfg(any(feature = "native", feature = "wasm"))]
pub use serde_json::Value as JsonValue;

/// Zeroizing owner used for decrypted plaintext and derived CEK bytes.
#[cfg(any(feature = "native", feature = "wasm"))]
pub use zeroize::Zeroizing;

#[cfg(any(feature = "native", feature = "wasm"))]
mod measure_encoding;
#[cfg(test)]
mod measure_encoding_tests;
#[cfg(any(feature = "native", feature = "wasm"))]
mod operation_contract;
#[cfg(any(feature = "native", feature = "wasm"))]
mod reject_duplicate_json_members;

#[cfg(any(feature = "native", feature = "wasm"))]
pub mod jwe;
#[cfg(any(feature = "native", feature = "wasm"))]
pub mod jws;
#[cfg(any(feature = "native", feature = "wasm"))]
pub mod jwt;
#[cfg(all(any(feature = "native", feature = "wasm"), feature = "wire"))]
pub mod wire;
