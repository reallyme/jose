#![allow(missing_docs, clippy::expect_used, clippy::unwrap_used)]
// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

use reallyme_jose::jwt::{AnyClaims, NumericDate, RegisteredClaims, StringOrURI};

#[test]
fn registered_claims_roundtrip() {
    let claims = RegisteredClaims {
        iss: Some(StringOrURI("https://issuer.example".into())),
        sub: Some(StringOrURI("did:example:123".into())),
        aud: None,
        exp: Some(NumericDate::new(1_700_000_000)),
        nbf: None,
        iat: None,
        jti: None,
    };

    let json = serde_json::to_string(&claims).unwrap();
    let decoded: RegisteredClaims = serde_json::from_str(&json).unwrap();

    assert_eq!(claims, decoded);
}

#[test]
fn registered_claims_accept_single_string_audience() {
    let decoded: RegisteredClaims =
        serde_json::from_str(r#"{"iss":"https://issuer.example","aud":"wallet"}"#).unwrap();

    assert_eq!(decoded.aud, Some(vec![StringOrURI("wallet".to_owned())]));
}

#[test]
fn registered_claims_accept_array_audience() {
    let decoded: RegisteredClaims =
        serde_json::from_str(r#"{"aud":["wallet","verifier"]}"#).unwrap();

    assert_eq!(
        decoded.aud,
        Some(vec![
            StringOrURI("wallet".to_owned()),
            StringOrURI("verifier".to_owned())
        ])
    );
}

#[test]
fn registered_claims_serialize_single_audience_as_string() {
    let claims = RegisteredClaims {
        iss: None,
        sub: None,
        aud: Some(vec![StringOrURI("wallet".to_owned())]),
        exp: None,
        nbf: None,
        iat: None,
        jti: None,
    };

    let json = serde_json::to_value(&claims).unwrap();

    assert_eq!(json["aud"], serde_json::json!("wallet"));
}

#[test]
fn any_claims_roundtrip() {
    let mut claims = AnyClaims::default();
    claims.insert("foo".into(), serde_json::json!(42));

    let json = serde_json::to_string(&claims).unwrap();
    let decoded: AnyClaims = serde_json::from_str(&json).unwrap();

    assert_eq!(claims, decoded);
}
