#![allow(
    missing_docs,
    clippy::arithmetic_side_effects,
    clippy::as_conversions,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::missing_const_for_fn,
    clippy::unwrap_used
)]
// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Compact JWE decrypt tests.

use serde::Deserialize;
use serde_json::{json, Value};

use reallyme_codec::base64url::{base64url_to_bytes, bytes_to_base64url};
use reallyme_crypto::core::{CryptoError, RngFailureKind, RngOutputKind};
use reallyme_jose::jwe::{
    decrypt_compact_jwe_bytes, decrypt_compact_jwe_json, derive_ecdh_es_content_encryption_key,
    encrypt_compact_jwe_bytes, CompactJweEncryptRequest, CompactJwePolicy,
    CompactJweProtectedHeader, DirectJweKeyEncryptor, DirectJweKeyResolver,
    JweContentEncryptionAlgorithm, JweContentEncryptionKeyResolver, JweError,
    JweKeyManagementAlgorithm, P256EcdhEsJweKeyEncryptor, P256EcdhEsJweKeyResolver,
    PreparedJweEncryptionKey, MAX_COMPACT_JWE_BYTES,
};
#[cfg(feature = "native")]
use reallyme_jose::jwe::{P384EcdhEsJweKeyResolver, P521EcdhEsJweKeyResolver};

#[derive(Debug, Deserialize, PartialEq, Eq)]
struct DirectPostPayload {
    vp_token: String,
    state: String,
}

#[derive(Debug, Deserialize)]
struct JweVectorSuite {
    cases: Vec<JweVectorCase>,
}

#[derive(Debug, Deserialize)]
struct JweVectorCase {
    id: String,
    alg: String,
    enc: String,
    cek_hex: Option<String>,
    recipient_private_key_hex: Option<String>,
    protected_header: Value,
    compact: String,
    expected_plaintext_json: Option<Value>,
    expected_error: Option<String>,
    derived_cek_hex: Option<String>,
}

include!("jwe_tests/cases.rs");
include!("jwe_tests/support_and_boundaries.rs");
