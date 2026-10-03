// SPDX-FileCopyrightText: 2026 ReallyMe LLC
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use super::CompactJwePolicy;

// Bound identifiers and party information can be private, so Debug exposes
// only whether a constraint is set rather than the value it contains.
impl core::fmt::Debug for CompactJwePolicy<'_> {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("CompactJwePolicy")
            .field(
                "allowed_key_management_algorithms",
                &self.allowed_key_management_algorithms,
            )
            .field(
                "allowed_content_encryption_algorithms",
                &self.allowed_content_encryption_algorithms,
            )
            .field("require_kid", &self.require_kid)
            .field("expected_kid", &self.expected_kid.map(|_| "<redacted>"))
            .field("expected_typ", &self.expected_typ.map(|_| "<redacted>"))
            .field("expected_cty", &self.expected_cty.map(|_| "<redacted>"))
            .field("expected_apu", &self.expected_apu.map(|_| "<redacted>"))
            .field("expected_apv", &self.expected_apv.map(|_| "<redacted>"))
            .finish()
    }
}
