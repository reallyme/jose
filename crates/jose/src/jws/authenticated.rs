// SPDX-FileCopyrightText: 2026 ReallyMe LLC
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Authenticated compact-JWS output ownership.

use zeroize::Zeroizing;

/// Protected header and payload bytes released only after JWS verification.
pub struct AuthenticatedCompactJws {
    protected_header: Zeroizing<Vec<u8>>,
    payload: Zeroizing<Vec<u8>>,
}

impl AuthenticatedCompactJws {
    pub(crate) const fn new(
        protected_header: Zeroizing<Vec<u8>>,
        payload: Zeroizing<Vec<u8>>,
    ) -> Self {
        Self {
            protected_header,
            payload,
        }
    }

    /// Borrows the authenticated decoded JWS Protected Header JSON bytes.
    #[must_use]
    pub fn protected_header(&self) -> &[u8] {
        self.protected_header.as_slice()
    }

    /// Borrows the authenticated decoded JWS Payload bytes.
    #[must_use]
    pub fn payload(&self) -> &[u8] {
        self.payload.as_slice()
    }

    /// Transfers ownership of both authenticated buffers.
    #[must_use]
    pub fn into_parts(self) -> (Zeroizing<Vec<u8>>, Zeroizing<Vec<u8>>) {
        (self.protected_header, self.payload)
    }

    /// Transfers the authenticated payload and zeroizes the protected header.
    #[must_use]
    pub fn into_payload(self) -> Zeroizing<Vec<u8>> {
        self.payload
    }
}
