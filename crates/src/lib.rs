// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

//! JOSE, JWT, and JWS helpers.
//!
//! `reallyme-jose` owns JOSE byte-format mechanics for compact JWS, JWT, and
//! JWE. Cryptographic operations are routed through `reallyme-crypto`; this
//! crate adds JOSE header policy, compact serialization, algorithm/key binding,
//! temporal JWT policy, and JWE content-encryption handling.

#[cfg(not(any(feature = "native", feature = "wasm")))]
compile_error!("reallyme-jose requires a supported runtime lane: enable feature `native` for audited Rust crypto or `wasm` for the WebAssembly host-provider lane.");

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
pub mod jwe;
#[cfg(any(feature = "native", feature = "wasm"))]
pub mod jws;
#[cfg(any(feature = "native", feature = "wasm"))]
pub mod jwt;
