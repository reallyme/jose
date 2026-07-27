#![allow(missing_docs, clippy::expect_used, clippy::unwrap_used)]
// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

use super::support::{base_claims_json, gen_ed25519};
use reallyme_jose::jwt::{decode_verify_jwt_signature_only, encode_signed_jwt};

#[test]
fn ed25519_signed_jwt_roundtrip() {
    let k = gen_ed25519();
    let claims = base_claims_json();

    let jwt = encode_signed_jwt(&claims, &k.jwk, &k.private).unwrap();

    let decoded: serde_json::Value =
        decode_verify_jwt_signature_only(&jwt, &k.jwk, &k.public).unwrap();

    assert_eq!(decoded["iss"], "did:me:test");
}
