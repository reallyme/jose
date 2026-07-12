#![allow(missing_docs, clippy::expect_used, clippy::unwrap_used, clippy::panic)]
// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

//! Deterministic generator for the portable JWS/JWT conformance vector files.
//!
//! This is a maintenance tool, not a CI test. It is `#[ignore]`d so it never runs
//! in the normal suite; run it explicitly to regenerate the checked-in vectors:
//!
//! ```text
//! cargo test -p reallyme-jose --features conformance-vectors --test gen_vectors -- --ignored --nocapture
//! ```
//!
//! Signing is deterministic (RFC 6979 ECDSA, RFC 8032 EdDSA), so the emitted
//! compact strings are byte-stable across runs and portable to SDK test suites.

#![cfg(feature = "conformance-vectors")]

use serde_json::{json, Map, Value};

use reallyme_codec::base64url::bytes_to_base64url;
use reallyme_crypto::jwk::{
    ed25519_public_key_to_jwk, p256_public_key_to_jwk, secp256k1_public_key_to_jwk, JwkOptions,
};

use reallyme_jose::jws::suites::eddsa::sign_eddsa_jws;
use reallyme_jose::jws::suites::es256::sign_es256_jws;
use reallyme_jose::jwt::{encode_signed_jwt, encode_unsigned_jwt};
use reallyme_jose::Jwk;

const JWS_PAYLOAD: &str = "reallyme-conformance-cid";

fn hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(char::from_digit((byte >> 4) as u32, 16).unwrap());
        out.push(char::from_digit((byte & 0x0f) as u32, 16).unwrap());
    }
    out
}

fn p256_scalar() -> [u8; 32] {
    let mut scalar = [0u8; 32];
    scalar[31] = 0x11;
    scalar
}

fn secp256k1_scalar() -> [u8; 32] {
    let mut scalar = [0u8; 32];
    scalar[31] = 0x13;
    scalar
}

fn ed25519_seed() -> [u8; 32] {
    [0x09u8; 32]
}

struct Material {
    public: Vec<u8>,
    private: Vec<u8>,
    jwk: Jwk,
}

fn p256_material() -> Material {
    let (public, private) =
        reallyme_crypto::p256::generate_p256_keypair_from_secret_key(&p256_scalar()).unwrap();
    let jwk = p256_public_key_to_jwk(
        &public,
        JwkOptions {
            alg: true,
            use_sig: true,
            use_enc: false,
            kid: Some("k-p256".into()),
        },
    )
    .unwrap();
    Material {
        public,
        private: private.to_vec(),
        jwk: Jwk::Ec(jwk),
    }
}

fn secp256k1_material() -> Material {
    let (public, private) =
        reallyme_crypto::secp256k1::generate_secp256k1_keypair_from_secret_key(&secp256k1_scalar())
            .unwrap();
    let jwk = secp256k1_public_key_to_jwk(
        &public,
        JwkOptions {
            alg: true,
            use_sig: true,
            use_enc: false,
            kid: Some("k-k1".into()),
        },
    )
    .unwrap();
    Material {
        public,
        private: private.to_vec(),
        jwk: Jwk::Ec(jwk),
    }
}

fn ed25519_material() -> Material {
    let (public, private) =
        reallyme_crypto::ed25519::generate_ed25519_keypair_from_seed(&ed25519_seed());
    let jwk = ed25519_public_key_to_jwk(
        &public,
        JwkOptions {
            alg: true,
            use_sig: true,
            use_enc: false,
            kid: Some("k-ed".into()),
        },
    )
    .unwrap();
    Material {
        public,
        private: private.to_vec(),
        jwk: Jwk::Okp(jwk.into()),
    }
}

/// Base64url-encode a raw JSON header string, preserving byte layout (used for
/// duplicate-member and unsafe-parameter headers that `serde_json` cannot emit).
fn header_segment(raw_json: &str) -> String {
    bytes_to_base64url(raw_json.as_bytes())
}

fn replace_segment(compact: &str, index: usize, replacement: &str) -> String {
    let mut parts: Vec<String> = compact.split('.').map(str::to_owned).collect();
    parts[index] = replacement.to_owned();
    parts.join(".")
}

/// Flip the first character of a segment to a different valid base64url symbol so
/// the segment stays well-formed base64url but decodes to different bytes.
fn tamper_segment(compact: &str, index: usize) -> String {
    let parts: Vec<&str> = compact.split('.').collect();
    let segment = parts[index];
    let first = segment.chars().next().unwrap();
    let flipped = if first == 'A' { 'B' } else { 'A' };
    let mut new_segment = String::new();
    new_segment.push(flipped);
    new_segment.push_str(&segment[first.len_utf8()..]);
    replace_segment(compact, index, &new_segment)
}

fn case(map: Vec<(&str, Value)>) -> Value {
    let mut object = Map::new();
    for (key, value) in map {
        object.insert(key.to_owned(), value);
    }
    Value::Object(object)
}

fn write_suite(path: &str, suite: &str, cases: Vec<Value>) {
    let doc = json!({
        "schema": "reallyme.identity.conformance.vectors.v1",
        "suite": suite,
        "cases": cases,
    });
    let mut text = serde_json::to_string_pretty(&doc).unwrap();
    text.push('\n');
    std::fs::write(path, text).unwrap();
}

fn jws_compact_cases() -> Vec<Value> {
    let p256 = p256_material();
    let ed = ed25519_material();

    let es256_valid = sign_es256_jws(&p256.private, JWS_PAYLOAD).unwrap();
    let eddsa_valid = sign_eddsa_jws(&ed.private, JWS_PAYLOAD).unwrap();

    // A second, unrelated P-256 key for wrong-key negatives.
    let mut other_scalar = [0u8; 32];
    other_scalar[31] = 0x22;
    let (other_p256_public, _other_p256_private) =
        reallyme_crypto::p256::generate_p256_keypair_from_secret_key(&other_scalar).unwrap();

    let payload_seg = es256_valid.split('.').nth(1).unwrap().to_owned();
    let signature_seg = es256_valid.split('.').nth(2).unwrap().to_owned();

    let header_alg = |raw: &str| header_segment(raw);

    let mut cases = vec![
        case(vec![
            ("id", json!("reallyme-jws/es256-valid")),
            ("source", json!("RFC7515")),
            ("format", json!("jws-compact")),
            ("alg", json!("ES256")),
            ("payload_utf8", json!(JWS_PAYLOAD)),
            ("public_key_hex", json!(hex(&p256.public))),
            ("private_key_hex", json!(hex(&p256.private))),
            ("compact", json!(es256_valid)),
            ("expected_valid", json!(true)),
        ]),
        case(vec![
            ("id", json!("reallyme-jws/eddsa-valid")),
            ("source", json!("RFC8037")),
            ("format", json!("jws-compact")),
            ("alg", json!("EdDSA")),
            ("payload_utf8", json!(JWS_PAYLOAD)),
            ("public_key_hex", json!(hex(&ed.public))),
            ("private_key_hex", json!(hex(&ed.private))),
            ("compact", json!(eddsa_valid)),
            ("expected_valid", json!(true)),
        ]),
        // RFC 8037 Appendix A.4 Ed25519 known-answer interop vector.
        case(vec![
            ("id", json!("rfc8037-a4/eddsa-known-answer")),
            ("source", json!("RFC8037 Appendix A.4")),
            ("format", json!("jws-compact")),
            ("alg", json!("EdDSA")),
            ("payload_utf8", json!("Example of Ed25519 signing")),
            (
                "public_key_hex",
                json!(hex(
                    &reallyme_codec::base64url::base64url_to_bytes(
                        "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"
                    )
                    .unwrap()
                )),
            ),
            (
                "compact",
                json!("eyJhbGciOiJFZERTQSJ9.RXhhbXBsZSBvZiBFZDI1NTE5IHNpZ25pbmc.hgyY0il_MGCjP0JzlnLWG1PPOt7-09PGcvMg3AIbQR6dWbhijcNR4ki4iylGjg5BhVsPt9g7sVvpAr_MuM0KAg"),
            ),
            ("expected_valid", json!(true)),
        ]),
    ];

    // RFC 7515 Appendix A.3 ES256 known-answer interop vector.
    let a3_x = reallyme_codec::base64url::base64url_to_bytes(
        "f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU",
    )
    .unwrap();
    let a3_y = reallyme_codec::base64url::base64url_to_bytes(
        "x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0",
    )
    .unwrap();
    let mut a3_sec1 = Vec::with_capacity(65);
    a3_sec1.push(0x04);
    a3_sec1.extend_from_slice(&a3_x);
    a3_sec1.extend_from_slice(&a3_y);
    cases.push(case(vec![
        ("id", json!("rfc7515-a3/es256-known-answer")),
        ("source", json!("RFC7515 Appendix A.3")),
        ("format", json!("jws-compact")),
        ("alg", json!("ES256")),
        (
            "payload_utf8",
            json!("{\"iss\":\"joe\",\r\n \"exp\":1300819380,\r\n \"http://example.com/is_root\":true}"),
        ),
        ("public_key_hex", json!(hex(&a3_sec1))),
        (
            "compact",
            json!("eyJhbGciOiJFUzI1NiJ9.eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ.DtEhU3ljbEg8L38VWAfUAqOyKAM6-Xx-F4GawxaepmXFCgfTjDxw5djxLa8ISlSApmWQxfKTUJqPP3-Kg6NU1Q"),
        ),
        ("expected_valid", json!(true)),
    ]));

    // ES256 structural / attack negatives derived from the valid ES256 token.
    let es256_negatives: Vec<(&str, String, &str)> = vec![
        (
            "reallyme-jws/es256-tampered-payload",
            tamper_segment(&es256_valid, 1),
            "InvalidSignature",
        ),
        (
            "reallyme-jws/es256-tampered-signature",
            tamper_segment(&es256_valid, 2),
            "InvalidSignature",
        ),
        (
            "reallyme-jws/es256-signature-stripped",
            format!(
                "{}.{}.",
                es256_valid.split('.').next().unwrap(),
                payload_seg
            ),
            "InvalidSignature",
        ),
        (
            "reallyme-jws/es256-signature-too-short",
            replace_segment(&es256_valid, 2, &bytes_to_base64url(&[0u8; 63])),
            "InvalidSignature",
        ),
        (
            "reallyme-jws/es256-signature-too-long",
            replace_segment(&es256_valid, 2, &bytes_to_base64url(&[0u8; 65])),
            "InvalidSignature",
        ),
        (
            "reallyme-jws/es256-non-base64url-signature",
            replace_segment(&es256_valid, 2, "not*base64url"),
            "BadSignatureBase64",
        ),
        (
            "reallyme-jws/es256-alg-none-header",
            replace_segment(&es256_valid, 0, &header_alg(r#"{"alg":"none"}"#)),
            "HeaderMismatch",
        ),
        (
            "reallyme-jws/es256-alg-es256k-header",
            replace_segment(&es256_valid, 0, &header_alg(r#"{"alg":"ES256K"}"#)),
            "HeaderMismatch",
        ),
        (
            "reallyme-jws/es256-duplicate-alg-header",
            replace_segment(
                &es256_valid,
                0,
                &header_alg(r#"{"alg":"ES256","alg":"ES256"}"#),
            ),
            "HeaderMismatch",
        ),
        (
            "reallyme-jws/es256-crit-header",
            replace_segment(
                &es256_valid,
                0,
                &header_alg(r#"{"alg":"ES256","crit":["b64"]}"#),
            ),
            "HeaderMismatch",
        ),
        (
            "reallyme-jws/es256-b64-header",
            replace_segment(
                &es256_valid,
                0,
                &header_alg(r#"{"alg":"ES256","b64":false}"#),
            ),
            "HeaderMismatch",
        ),
        (
            "reallyme-jws/es256-jku-header",
            replace_segment(
                &es256_valid,
                0,
                &header_alg(r#"{"alg":"ES256","jku":"https://example.test/jwks"}"#),
            ),
            "HeaderMismatch",
        ),
        (
            "reallyme-jws/es256-jwk-header",
            replace_segment(
                &es256_valid,
                0,
                &header_alg(r#"{"alg":"ES256","jwk":{"kty":"EC"}}"#),
            ),
            "HeaderMismatch",
        ),
        (
            "reallyme-jws/es256-x5u-header",
            replace_segment(
                &es256_valid,
                0,
                &header_alg(r#"{"alg":"ES256","x5u":"https://example.test/cert"}"#),
            ),
            "HeaderMismatch",
        ),
        (
            "reallyme-jws/es256-x5c-header",
            replace_segment(
                &es256_valid,
                0,
                &header_alg(r#"{"alg":"ES256","x5c":["MIIB"]}"#),
            ),
            "HeaderMismatch",
        ),
        (
            "reallyme-jws/es256-two-parts",
            format!("{}.{}", es256_valid.split('.').next().unwrap(), payload_seg),
            "InvalidCompactEncoding",
        ),
        (
            "reallyme-jws/es256-four-parts",
            format!("{es256_valid}.{signature_seg}"),
            "InvalidCompactEncoding",
        ),
        (
            "reallyme-jws/eddsa-token-to-es256-verify",
            eddsa_valid.clone(),
            "HeaderMismatch",
        ),
    ];

    for (id, compact, err) in es256_negatives {
        cases.push(case(vec![
            ("id", json!(id)),
            ("source", json!("RFC7515")),
            ("format", json!("jws-compact")),
            ("alg", json!("ES256")),
            ("public_key_hex", json!(hex(&p256.public))),
            ("compact", json!(compact)),
            ("expected_error", json!(err)),
        ]));
    }

    // Wrong-key negative: valid token, unrelated public key.
    cases.push(case(vec![
        ("id", json!("reallyme-jws/es256-wrong-public-key")),
        ("source", json!("RFC7515")),
        ("format", json!("jws-compact")),
        ("alg", json!("ES256")),
        ("public_key_hex", json!(hex(&other_p256_public))),
        ("compact", json!(es256_valid)),
        ("expected_error", json!("InvalidSignature")),
    ]));

    // EdDSA negatives.
    let eddsa_negatives: Vec<(&str, String, &str)> = vec![
        (
            "reallyme-jws/eddsa-tampered-payload",
            tamper_segment(&eddsa_valid, 1),
            "InvalidSignature",
        ),
        (
            "reallyme-jws/eddsa-signature-stripped",
            format!(
                "{}.{}.",
                eddsa_valid.split('.').next().unwrap(),
                eddsa_valid.split('.').nth(1).unwrap()
            ),
            "InvalidSignature",
        ),
        (
            "reallyme-jws/es256-token-to-eddsa-verify",
            es256_valid.clone(),
            "HeaderMismatch",
        ),
    ];
    for (id, compact, err) in eddsa_negatives {
        cases.push(case(vec![
            ("id", json!(id)),
            ("source", json!("RFC8037")),
            ("format", json!("jws-compact")),
            ("alg", json!("EdDSA")),
            ("public_key_hex", json!(hex(&ed.public))),
            ("compact", json!(compact)),
            ("expected_error", json!(err)),
        ]));
    }

    cases
}

fn signed_jwt_cases() -> Vec<Value> {
    let p256 = p256_material();
    let k1 = secp256k1_material();
    let ed = ed25519_material();

    let claims = json!({
        "iss": "did:me:issuer",
        "sub": "alice",
        "aud": "did:me:verifier",
    });
    let claims_array_aud = json!({
        "iss": "did:me:issuer",
        "sub": "alice",
        "aud": ["did:me:verifier", "did:me:other"],
    });

    let es256_valid = encode_signed_jwt(&claims, &p256.jwk, &p256.private).unwrap();
    let es256k_valid = encode_signed_jwt(&claims, &k1.jwk, &k1.private).unwrap();
    let eddsa_valid = encode_signed_jwt(&claims, &ed.jwk, &ed.private).unwrap();
    let es256_array_aud = encode_signed_jwt(&claims_array_aud, &p256.jwk, &p256.private).unwrap();

    let jwk_value = |jwk: &Jwk| serde_json::to_value(jwk).unwrap();

    let mut cases = vec![
        case(vec![
            ("id", json!("reallyme-jwt/es256-valid")),
            ("source", json!("RFC7519")),
            ("format", json!("signed-jwt")),
            ("alg", json!("ES256")),
            ("verification_jwk", jwk_value(&p256.jwk)),
            ("public_key_hex", json!(hex(&p256.public))),
            ("private_key_hex", json!(hex(&p256.private))),
            ("compact", json!(es256_valid)),
            ("expected_claims_json", claims.clone()),
        ]),
        case(vec![
            ("id", json!("reallyme-jwt/es256k-valid")),
            ("source", json!("RFC7519")),
            ("format", json!("signed-jwt")),
            ("alg", json!("ES256K")),
            ("verification_jwk", jwk_value(&k1.jwk)),
            ("public_key_hex", json!(hex(&k1.public))),
            ("private_key_hex", json!(hex(&k1.private))),
            ("compact", json!(es256k_valid)),
            ("expected_claims_json", claims.clone()),
        ]),
        case(vec![
            ("id", json!("reallyme-jwt/eddsa-valid")),
            ("source", json!("RFC7519")),
            ("format", json!("signed-jwt")),
            ("alg", json!("EdDSA")),
            ("verification_jwk", jwk_value(&ed.jwk)),
            ("public_key_hex", json!(hex(&ed.public))),
            ("private_key_hex", json!(hex(&ed.private))),
            ("compact", json!(eddsa_valid)),
            ("expected_claims_json", claims.clone()),
        ]),
        case(vec![
            ("id", json!("reallyme-jwt/es256-array-audience")),
            ("source", json!("RFC7519 Section 4.1.3")),
            ("format", json!("signed-jwt")),
            ("alg", json!("ES256")),
            ("verification_jwk", jwk_value(&p256.jwk)),
            ("public_key_hex", json!(hex(&p256.public))),
            ("compact", json!(es256_array_aud)),
            ("expected_claims_json", claims_array_aud.clone()),
        ]),
    ];

    // Header/alg attack negatives derived from the valid ES256 JWT.
    let payload_seg = es256_valid.split('.').nth(1).unwrap().to_owned();
    let signature_seg = es256_valid.split('.').nth(2).unwrap().to_owned();
    let swap_header = |raw: &str| replace_segment(&es256_valid, 0, &header_segment(raw));

    let es256_header_negatives: Vec<(&str, String, &str)> = vec![
        (
            "reallyme-jwt/alg-none-signed-path",
            swap_header(r#"{"alg":"none","typ":"JWT"}"#),
            "InvalidHeader",
        ),
        (
            "reallyme-jwt/alg-none-capitalized",
            swap_header(r#"{"alg":"None","typ":"JWT"}"#),
            "UnsupportedAlgorithm",
        ),
        (
            "reallyme-jwt/alg-none-uppercase",
            swap_header(r#"{"alg":"NONE","typ":"JWT"}"#),
            "UnsupportedAlgorithm",
        ),
        (
            "reallyme-jwt/alg-hs256-unsupported",
            swap_header(r#"{"alg":"HS256","typ":"JWT"}"#),
            "UnsupportedAlgorithm",
        ),
        (
            "reallyme-jwt/duplicate-alg-header",
            swap_header(r#"{"alg":"ES256","alg":"ES256","typ":"JWT"}"#),
            "InvalidHeader",
        ),
        (
            "reallyme-jwt/crit-header",
            swap_header(r#"{"alg":"ES256","typ":"JWT","crit":["b64"]}"#),
            "InvalidHeader",
        ),
        (
            "reallyme-jwt/b64-header",
            swap_header(r#"{"alg":"ES256","typ":"JWT","b64":false}"#),
            "InvalidHeader",
        ),
        (
            "reallyme-jwt/jku-header",
            swap_header(r#"{"alg":"ES256","typ":"JWT","jku":"https://example.test/jwks"}"#),
            "InvalidHeader",
        ),
        (
            "reallyme-jwt/x5u-header",
            swap_header(r#"{"alg":"ES256","typ":"JWT","x5u":"https://example.test/cert"}"#),
            "InvalidHeader",
        ),
        (
            "reallyme-jwt/embedded-jwk-header",
            swap_header(r#"{"alg":"ES256","typ":"JWT","jwk":{"kty":"EC"}}"#),
            "InvalidHeader",
        ),
        (
            "reallyme-jwt/embedded-x5c-header",
            swap_header(r#"{"alg":"ES256","typ":"JWT","x5c":["MIIB"]}"#),
            "InvalidHeader",
        ),
        (
            "reallyme-jwt/typ-not-jwt",
            swap_header(r#"{"alg":"ES256","typ":"at+jwt"}"#),
            "InvalidHeader",
        ),
        (
            "reallyme-jwt/tampered-payload",
            tamper_segment(&es256_valid, 1),
            "InvalidSignature",
        ),
        (
            "reallyme-jwt/tampered-signature",
            tamper_segment(&es256_valid, 2),
            "InvalidSignature",
        ),
        (
            "reallyme-jwt/signature-stripped",
            format!(
                "{}.{}.",
                es256_valid.split('.').next().unwrap(),
                payload_seg
            ),
            "InvalidSignature",
        ),
        (
            "reallyme-jwt/two-parts",
            format!("{}.{}", es256_valid.split('.').next().unwrap(), payload_seg),
            "InvalidJwtFormat",
        ),
        (
            "reallyme-jwt/four-parts",
            format!("{es256_valid}.{signature_seg}"),
            "InvalidJwtFormat",
        ),
    ];
    for (id, compact, err) in es256_header_negatives {
        cases.push(case(vec![
            ("id", json!(id)),
            ("source", json!("RFC8725")),
            ("format", json!("signed-jwt")),
            ("alg", json!("ES256")),
            ("verification_jwk", jwk_value(&p256.jwk)),
            ("public_key_hex", json!(hex(&p256.public))),
            ("compact", json!(compact)),
            ("expected_error", json!(err)),
        ]));
    }

    // Algorithm/key binding: valid ES256 token, EdDSA verification key.
    cases.push(case(vec![
        ("id", json!("reallyme-jwt/alg-key-mismatch")),
        ("source", json!("RFC8725 Section 3.1")),
        ("format", json!("signed-jwt")),
        ("alg", json!("ES256")),
        ("verification_jwk", jwk_value(&ed.jwk)),
        ("public_key_hex", json!(hex(&ed.public))),
        ("compact", json!(es256_valid.clone())),
        ("expected_error", json!("AlgorithmMismatch")),
    ]));

    // Wrong-key negative.
    let mut other_scalar = [0u8; 32];
    other_scalar[31] = 0x22;
    let (other_public, _other_private) =
        reallyme_crypto::p256::generate_p256_keypair_from_secret_key(&other_scalar).unwrap();
    let other_jwk = Jwk::Ec(
        p256_public_key_to_jwk(
            &other_public,
            JwkOptions {
                alg: true,
                use_sig: true,
                use_enc: false,
                kid: Some("k-p256-other".into()),
            },
        )
        .unwrap(),
    );
    cases.push(case(vec![
        ("id", json!("reallyme-jwt/wrong-public-key")),
        ("source", json!("RFC7519")),
        ("format", json!("signed-jwt")),
        ("alg", json!("ES256")),
        ("verification_jwk", jwk_value(&other_jwk)),
        ("public_key_hex", json!(hex(&other_public))),
        ("compact", json!(es256_valid.clone())),
        ("expected_error", json!("InvalidSignature")),
    ]));

    // Temporal vectors. now_unix present => decode with strict temporal policy.
    let now: u64 = 1_700_000_000;
    let temporal_claims = |extra: Value| {
        let mut object = claims.as_object().unwrap().clone();
        if let Value::Object(map) = extra {
            for (key, value) in map {
                object.insert(key, value);
            }
        }
        Value::Object(object)
    };

    let temporal_valid = temporal_claims(json!({
        "iat": now - 100,
        "nbf": now - 100,
        "exp": now + 1_000,
    }));
    let temporal_valid_jwt = encode_signed_jwt(&temporal_valid, &p256.jwk, &p256.private).unwrap();
    cases.push(case(vec![
        ("id", json!("reallyme-jwt/temporal-valid")),
        ("source", json!("RFC7519 Section 4.1")),
        ("format", json!("signed-jwt")),
        ("alg", json!("ES256")),
        ("verification_jwk", jwk_value(&p256.jwk)),
        ("public_key_hex", json!(hex(&p256.public))),
        ("compact", json!(temporal_valid_jwt)),
        ("now_unix", json!(now)),
        ("temporal_policy", json!("strict")),
        ("expected_claims_json", temporal_valid.clone()),
    ]));

    let temporal_negatives: Vec<(&str, Value, &str)> = vec![
        (
            "reallyme-jwt/temporal-expired",
            temporal_claims(json!({ "iat": now - 10_000, "exp": now - 5_000 })),
            "Expired",
        ),
        (
            "reallyme-jwt/temporal-not-yet-valid",
            temporal_claims(json!({ "iat": now - 100, "nbf": now + 5_000, "exp": now + 10_000 })),
            "NotYetValid",
        ),
        (
            "reallyme-jwt/temporal-issued-in-future",
            temporal_claims(json!({ "iat": now + 5_000, "exp": now + 10_000 })),
            "IssuedAtInFuture",
        ),
        (
            "reallyme-jwt/temporal-missing-exp-strict",
            temporal_claims(json!({ "iat": now - 100 })),
            "MissingRequiredTemporalClaim:Exp",
        ),
        (
            "reallyme-jwt/temporal-exp-string",
            temporal_claims(json!({ "iat": now - 100, "exp": "soon" })),
            "InvalidTemporalClaimValue:Exp",
        ),
        (
            "reallyme-jwt/temporal-exp-zero",
            temporal_claims(json!({ "iat": now - 100, "exp": 0 })),
            "InvalidTemporalClaimValue:Exp",
        ),
    ];
    for (id, claim_set, err) in temporal_negatives {
        let compact = encode_signed_jwt(&claim_set, &p256.jwk, &p256.private).unwrap();
        cases.push(case(vec![
            ("id", json!(id)),
            ("source", json!("RFC7519 Section 4.1")),
            ("format", json!("signed-jwt")),
            ("alg", json!("ES256")),
            ("verification_jwk", jwk_value(&p256.jwk)),
            ("public_key_hex", json!(hex(&p256.public))),
            ("compact", json!(compact)),
            ("now_unix", json!(now)),
            ("temporal_policy", json!("strict")),
            ("expected_error", json!(err)),
        ]));
    }

    // Within-skew acceptance: exp just past but inside the 60s strict skew.
    let within_skew = temporal_claims(json!({ "iat": now - 100, "exp": now - 30 }));
    let within_skew_jwt = encode_signed_jwt(&within_skew, &p256.jwk, &p256.private).unwrap();
    cases.push(case(vec![
        ("id", json!("reallyme-jwt/temporal-expired-within-skew")),
        ("source", json!("RFC7519 Section 4.1.4")),
        ("format", json!("signed-jwt")),
        ("alg", json!("ES256")),
        ("verification_jwk", jwk_value(&p256.jwk)),
        ("public_key_hex", json!(hex(&p256.public))),
        ("compact", json!(within_skew_jwt)),
        ("now_unix", json!(now)),
        ("temporal_policy", json!("strict")),
        ("expected_claims_json", within_skew.clone()),
    ]));

    cases
}

fn unsigned_jwt_cases() -> Vec<Value> {
    let claims = json!({ "iss": "did:me:issuer", "sub": "alice" });
    let valid = encode_unsigned_jwt(&claims).unwrap();

    let p256 = p256_material();
    let signed = encode_signed_jwt(&claims, &p256.jwk, &p256.private).unwrap();

    let header_seg = valid.split('.').next().unwrap().to_owned();
    let payload_seg = valid.split('.').nth(1).unwrap().to_owned();

    vec![
        case(vec![
            ("id", json!("reallyme-jwt/unsigned-valid")),
            ("source", json!("RFC7519")),
            ("format", json!("unsigned-jwt")),
            ("compact", json!(valid)),
            ("expected_claims_json", claims.clone()),
        ]),
        case(vec![
            ("id", json!("reallyme-jwt/unsigned-alg-not-none")),
            ("source", json!("RFC8725")),
            ("format", json!("unsigned-jwt")),
            (
                "compact",
                json!(replace_segment(
                    &valid,
                    0,
                    &header_segment(r#"{"alg":"ES256","typ":"JWT"}"#)
                )),
            ),
            ("expected_error", json!("InvalidJwtFormat")),
        ]),
        case(vec![
            ("id", json!("reallyme-jwt/unsigned-typ-not-jwt")),
            ("source", json!("RFC8725")),
            ("format", json!("unsigned-jwt")),
            (
                "compact",
                json!(replace_segment(
                    &valid,
                    0,
                    &header_segment(r#"{"alg":"none","typ":"at+jwt"}"#)
                )),
            ),
            ("expected_error", json!("InvalidJwtFormat")),
        ]),
        case(vec![
            ("id", json!("reallyme-jwt/unsigned-non-empty-signature")),
            ("source", json!("RFC7519")),
            ("format", json!("unsigned-jwt")),
            ("compact", json!(format!("{header_seg}.{payload_seg}.AAAA"))),
            ("expected_error", json!("InvalidJwtFormat")),
        ]),
        case(vec![
            ("id", json!("reallyme-jwt/unsigned-two-parts")),
            ("source", json!("RFC7519")),
            ("format", json!("unsigned-jwt")),
            ("compact", json!(format!("{header_seg}.{payload_seg}"))),
            ("expected_error", json!("InvalidJwtFormat")),
        ]),
        case(vec![
            ("id", json!("reallyme-jwt/signed-token-to-unsigned-decoder")),
            ("source", json!("RFC8725 Section 3.12")),
            ("format", json!("unsigned-jwt")),
            ("compact", json!(signed)),
            ("expected_error", json!("InvalidJwtFormat")),
        ]),
    ]
}

#[test]
#[ignore = "maintenance tool: regenerates checked-in conformance vectors"]
fn regenerate_conformance_vectors() {
    write_suite(
        "../conformance/vectors/jws-compact.json",
        "jws-compact",
        jws_compact_cases(),
    );
    write_suite(
        "../conformance/vectors/signed-jwt.json",
        "signed-jwt",
        signed_jwt_cases(),
    );
    write_suite(
        "../conformance/vectors/unsigned-jwt.json",
        "unsigned-jwt",
        unsigned_jwt_cases(),
    );
}
