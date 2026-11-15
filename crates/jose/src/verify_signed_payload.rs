// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

pub(crate) fn verify_signed_payload<Header, Payload, Error>(
    caller_key: &[u8],
    authorize_header: impl FnOnce(&[u8]) -> Result<Header, Error>,
    verify_signature: impl FnOnce(&[u8], &Header) -> Result<(), Error>,
    release_payload: impl FnOnce(Header) -> Result<Payload, Error>,
) -> Result<Payload, Error> {
    // Header authorization can reject the caller's key, but only the
    // caller-supplied bytes enter the signature verifier.
    let header = authorize_header(caller_key)?;
    verify_signature(caller_key, &header)?;
    release_payload(header)
}

#[cfg(kani)]
#[path = "verify_signed_payload_proofs.rs"]
mod proofs;
