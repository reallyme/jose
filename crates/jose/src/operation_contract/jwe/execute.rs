// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

//! Canonical JWE execution entrypoints.

use zeroize::Zeroizing;

use crate::jwe::{
    decrypt::decrypt_compact_jwe_bytes_core, encrypt::encrypt_compact_jwe_bytes_core,
    CompactJweEncryptRequest, CompactJwePolicy, JweContentEncryptionKeyEncryptor,
    JweContentEncryptionKeyResolver, JweError,
};
use crate::SecureRandom;

/// Encrypts a compact JWE through the selected key-management provider.
pub(crate) fn encrypt_jwe<R: SecureRandom + ?Sized>(
    request: &CompactJweEncryptRequest<'_>,
    key_encryptor: &mut dyn JweContentEncryptionKeyEncryptor,
    rng: &mut R,
) -> Result<String, JweError> {
    encrypt_compact_jwe_bytes_core(request, key_encryptor, rng)
}

/// Decrypts a compact JWE through the selected key-management provider.
pub(crate) fn decrypt_jwe(
    compact_jwe: &str,
    policy: &CompactJwePolicy<'_>,
    key_resolver: &dyn JweContentEncryptionKeyResolver,
) -> Result<Zeroizing<Vec<u8>>, JweError> {
    decrypt_compact_jwe_bytes_core(compact_jwe, policy, key_resolver)
}
