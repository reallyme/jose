// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

//! JSON Web Encryption helpers.

mod decrypt;
mod derive_key;
mod encrypt;
mod error;
mod parse_compact;
mod validate_header;

pub use decrypt::{
    decrypt_compact_jwe_bytes, decrypt_compact_jwe_json, DirectJweKeyResolver,
    JweContentEncryptionKeyResolver,
};
pub use derive_key::derive_ecdh_es_content_encryption_key;
pub use encrypt::{
    encrypt_compact_jwe_bytes, encrypt_compact_jwe_json, CompactJweEncryptRequest,
    DirectJweKeyEncryptor, JweContentEncryptionKeyEncryptor, P256EcdhEsJweKeyEncryptor,
    P256EcdhEsJweKeyResolver, PreparedJweEncryptionKey,
};
#[cfg(feature = "native")]
pub use encrypt::{
    P384EcdhEsJweKeyEncryptor, P384EcdhEsJweKeyResolver, P521EcdhEsJweKeyEncryptor,
    P521EcdhEsJweKeyResolver,
};
pub use error::JweError;
pub use parse_compact::MAX_COMPACT_JWE_BYTES;
pub use validate_header::{
    CompactJwePolicy, CompactJweProtectedHeader, JweContentEncryptionAlgorithm,
    JweKeyManagementAlgorithm,
};
