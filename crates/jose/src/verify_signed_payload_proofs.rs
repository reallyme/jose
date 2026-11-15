// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use core::cell::Cell;

use super::verify_signed_payload;

#[derive(Debug, Eq, PartialEq)]
enum Failure {
    Header,
    Signature,
    Payload,
}

#[kani::proof]
fn signed_payload_requires_authorized_header_and_verified_signature_with_caller_key() {
    let caller_byte = kani::any::<u8>();
    let caller_key = [caller_byte];
    let embedded_key = kani::any::<u8>();
    let header_allowed = kani::any::<bool>();
    let signature_valid = kani::any::<bool>();
    let payload_decodable = kani::any::<bool>();
    let payload = kani::any::<u8>();
    let authorized = Cell::new(false);
    let verified = Cell::new(false);
    let released = Cell::new(false);

    let result = verify_signed_payload(
        &caller_key,
        |key| {
            kani::assert(key == caller_key, "header policy checks the caller's key");
            if header_allowed {
                authorized.set(true);
                Ok(embedded_key)
            } else {
                Err(Failure::Header)
            }
        },
        |key, header| {
            kani::assert(
                authorized.get(),
                "signature verification requires an authorized header",
            );
            kani::assert(
                core::ptr::eq(key, caller_key.as_slice()),
                "signature verification receives the original caller key slice",
            );
            kani::assert(
                *header == embedded_key,
                "authorized header metadata is preserved",
            );
            if signature_valid {
                verified.set(true);
                Ok(())
            } else {
                Err(Failure::Signature)
            }
        },
        |header| {
            kani::assert(
                verified.get(),
                "payload decoding follows successful verification",
            );
            kani::assert(
                header == embedded_key,
                "release receives the authorized header",
            );
            released.set(true);
            if payload_decodable {
                Ok(payload)
            } else {
                Err(Failure::Payload)
            }
        },
    );
    let expected = match (header_allowed, signature_valid, payload_decodable) {
        (false, _, _) => Err(Failure::Header),
        (true, false, _) => Err(Failure::Signature),
        (true, true, false) => Err(Failure::Payload),
        (true, true, true) => Ok(payload),
    };
    kani::assert(
        result == expected,
        "only authenticated and decodable payloads are returned",
    );
    kani::assert(
        released.get() == (header_allowed && signature_valid),
        "release runs only after both checks",
    );
    kani::cover!(
        matches!(result, Err(Failure::Header)),
        "header rejected before verification"
    );
    kani::cover!(
        matches!(result, Err(Failure::Signature)),
        "signature rejected before release"
    );
    kani::cover!(
        matches!(result, Err(Failure::Payload)),
        "decode fails after authentication"
    );
    kani::cover!(
        result.is_ok() && embedded_key != caller_byte,
        "different embedded key cannot replace caller key"
    );
}
