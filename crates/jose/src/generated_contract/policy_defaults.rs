// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

// Derived from the protobuf contract. Change the schema and regenerate.

use crate::jwe::{JweContentEncryptionAlgorithm, JweKeyManagementAlgorithm};

pub(crate) const JWT_TYPE: &str = "JWT";
pub(crate) const JWT_ACCEPTED_TYPES: &[&str] = &["JWT"];
pub(crate) const JWT_ALLOW_MISSING_TYPE: bool = false;
pub(crate) const JWT_ALLOW_EMBEDDED_KEY: bool = false;
pub(crate) const TEMPORAL_REQUIRE_EXP: bool = true;
pub(crate) const TEMPORAL_REQUIRE_NBF: bool = false;
pub(crate) const TEMPORAL_REQUIRE_IAT: bool = false;
pub(crate) const OPENID_KEY_MANAGEMENT: &[JweKeyManagementAlgorithm] = &[
    JweKeyManagementAlgorithm::EcdhEs,
    JweKeyManagementAlgorithm::Direct,
];
pub(crate) const OPENID_CONTENT_ENCRYPTION: &[JweContentEncryptionAlgorithm] = &[
    JweContentEncryptionAlgorithm::A128Gcm,
    JweContentEncryptionAlgorithm::A192Gcm,
    JweContentEncryptionAlgorithm::A256Gcm,
];
#[cfg(test)]
#[path = "policy_defaults_tests.rs"]
mod tests;
