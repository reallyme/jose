// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use reallyme_codec::base64url::bytes_to_base64url;
use serde_json::{json, Value};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use super::encode_required_members::encode;
use super::{
    thumbprint_sha256, thumbprint_sha256_from_json, JwkThumbprintErrorReason, JwkThumbprintMembers,
    MAX_JWK_THUMBPRINT_MEMBER_BYTES,
};

const RFC7638_MODULUS: &str = concat!(
    "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAt",
    "VT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn6",
    "4tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FD",
    "W2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n9",
    "1CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINH",
    "aQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw"
);

#[test]
fn published_rsa_and_okp_vectors() -> Result<(), JwkThumbprintErrorReason> {
    // RFC 7638 section 3.1 and RFC 8037 appendix A.3 publish these digests.
    let cases = [
        (
            JwkThumbprintMembers::Rsa {
                e: "AQAB",
                n: RFC7638_MODULUS,
            },
            "NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs",
        ),
        (
            JwkThumbprintMembers::Okp {
                crv: "Ed25519",
                x: "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo",
            },
            "kPrK_qmxVWaYVA9wwBF6Iuo3vVzz7TxHCTwXBygrS4k",
        ),
    ];
    for (members, expected) in cases {
        let digest = thumbprint_sha256(&members)?;
        assert_eq!(bytes_to_base64url(digest.as_ref()), expected);
    }
    Ok(())
}

#[test]
fn every_key_type_has_exact_required_member_order() -> Result<(), JwkThumbprintErrorReason> {
    let cases = [
        (
            JwkThumbprintMembers::Ec {
                crv: "P-256",
                x: "x",
                y: "y",
            },
            r#"{"crv":"P-256","kty":"EC","x":"x","y":"y"}"#,
        ),
        (
            JwkThumbprintMembers::Okp {
                crv: "Ed25519",
                x: "x",
            },
            r#"{"crv":"Ed25519","kty":"OKP","x":"x"}"#,
        ),
        (
            JwkThumbprintMembers::Rsa { n: "n", e: "e" },
            r#"{"e":"e","kty":"RSA","n":"n"}"#,
        ),
        (
            JwkThumbprintMembers::Oct { k: "k" },
            r#"{"k":"k","kty":"oct"}"#,
        ),
    ];
    for (members, expected) in cases {
        assert_eq!(encode(&members)?.as_slice(), expected.as_bytes());
        assert_eq!(
            thumbprint_sha256(&members)?.as_ref(),
            reallyme_crypto::sha2::digest(expected.as_bytes()).as_bytes()
        );
    }
    Ok(())
}

#[test]
fn json_adapter_ignores_extra_fields_and_input_member_order(
) -> Result<(), Box<dyn std::error::Error>> {
    let reordered: Value = serde_json::from_str(
        r#"{"y":"y","ignored":{"nested":[null,true]},"d":"private","alg":null,"x":"x","kty":"EC","crv":"P-256"}"#,
    )?;
    let required = json!({"crv":"P-256", "kty":"EC", "x":"x", "y":"y"});
    assert_eq!(
        thumbprint_sha256_from_json(&reordered)?,
        thumbprint_sha256_from_json(&required)?
    );

    for jwk in valid_json_keys() {
        let mut extended = jwk.clone();
        if let Value::Object(fields) = &mut extended {
            fields.insert("kid".into(), Value::String("x".repeat(8193)));
            fields.insert("d".into(), json!({"invalid": [1,2,3]}));
            fields.insert("other".into(), json!({"kty":"incorrect", "k":null}));
        }
        assert_eq!(
            thumbprint_sha256_from_json(&jwk)?,
            thumbprint_sha256_from_json(&extended)?
        );
    }
    Ok(())
}

#[test]
fn escapes_json_syntax_controls_and_preserves_unicode() -> Result<(), Box<dyn std::error::Error>> {
    let value = "\"\\\u{0}\u{8}\t\n\u{c}\r\u{1f}/é雪😀\u{2028}\u{2029}";
    let members = JwkThumbprintMembers::Oct { k: value };
    let encoded = encode(&members)?;
    let expected =
        "{\"k\":\"\\\"\\\\\\u0000\\b\\t\\n\\f\\r\\u001f/é雪😀\u{2028}\u{2029}\",\"kty\":\"oct\"}";
    assert_eq!(encoded.as_slice(), expected.as_bytes());
    assert_eq!(
        serde_json::from_slice::<Value>(&encoded)?,
        json!({"k":value, "kty":"oct"})
    );
    assert_eq!(
        thumbprint_sha256(&members)?,
        thumbprint_sha256_from_json(&json!({"k":value, "kty":"oct"}))?
    );

    let controls: String = ('\u{0}'..='\u{1f}').collect();
    let encoded = encode(&JwkThumbprintMembers::Oct { k: &controls })?;
    assert_eq!(
        serde_json::from_slice::<Value>(&encoded)?,
        json!({"k":controls, "kty":"oct"})
    );
    assert_ne!(
        thumbprint_sha256(&JwkThumbprintMembers::Oct { k: "é" })?,
        thumbprint_sha256(&JwkThumbprintMembers::Oct { k: "e\u{301}" })?
    );
    Ok(())
}

fn valid_json_keys() -> [Value; 4] {
    [
        json!({"kty":"EC","crv":"P-256","x":"x","y":"y"}),
        json!({"kty":"OKP","crv":"Ed25519","x":"x"}),
        json!({"kty":"RSA","e":"AQAB","n":"n"}),
        json!({"kty":"oct","k":"k"}),
    ]
}

#[test]
fn rejects_each_missing_empty_mistyped_and_oversized_json_member() {
    for jwk in valid_json_keys() {
        if let Value::Object(fields) = jwk {
            for name in fields.keys() {
                let mut missing = fields.clone();
                missing.remove(name);
                assert_eq!(
                    thumbprint_sha256_from_json(&Value::Object(missing)),
                    Err(JwkThumbprintErrorReason::MissingMember)
                );
                let invalid = [
                    (
                        Value::String(String::new()),
                        JwkThumbprintErrorReason::MissingMember,
                    ),
                    (Value::Null, JwkThumbprintErrorReason::InvalidMemberType),
                    (json!(false), JwkThumbprintErrorReason::InvalidMemberType),
                    (json!(1), JwkThumbprintErrorReason::InvalidMemberType),
                    (json!([]), JwkThumbprintErrorReason::InvalidMemberType),
                    (json!({}), JwkThumbprintErrorReason::InvalidMemberType),
                    (
                        Value::String("x".repeat(8193)),
                        JwkThumbprintErrorReason::MemberTooLarge,
                    ),
                ];
                for (value, reason) in invalid {
                    let mut changed = fields.clone();
                    changed.insert(name.clone(), value);
                    assert_eq!(
                        thumbprint_sha256_from_json(&Value::Object(changed)),
                        Err(reason)
                    );
                }
            }
        }
    }
}

#[test]
fn rejects_non_objects_and_unsupported_key_types() {
    for jwk in [json!(null), json!([]), json!("oct"), json!(true), json!(42)] {
        assert_eq!(
            thumbprint_sha256_from_json(&jwk),
            Err(JwkThumbprintErrorReason::InvalidJsonObject)
        );
    }
    for kty in ["ec", "okp", "rsa", "OCT", "unknown"] {
        assert_eq!(
            thumbprint_sha256_from_json(&json!({"kty":kty})),
            Err(JwkThumbprintErrorReason::UnsupportedKeyType)
        );
    }
}

fn with_each_member(value: &str) -> [JwkThumbprintMembers<'_>; 8] {
    [
        JwkThumbprintMembers::Ec {
            crv: value,
            x: "x",
            y: "y",
        },
        JwkThumbprintMembers::Ec {
            crv: "P-256",
            x: value,
            y: "y",
        },
        JwkThumbprintMembers::Ec {
            crv: "P-256",
            x: "x",
            y: value,
        },
        JwkThumbprintMembers::Okp { crv: value, x: "x" },
        JwkThumbprintMembers::Okp {
            crv: "Ed25519",
            x: value,
        },
        JwkThumbprintMembers::Rsa { e: value, n: "n" },
        JwkThumbprintMembers::Rsa {
            e: "AQAB",
            n: value,
        },
        JwkThumbprintMembers::Oct { k: value },
    ]
}

#[test]
fn typed_members_enforce_empty_and_byte_limits_for_every_field(
) -> Result<(), JwkThumbprintErrorReason> {
    assert_eq!(MAX_JWK_THUMBPRINT_MEMBER_BYTES, 8192);
    for members in with_each_member("") {
        assert_eq!(
            thumbprint_sha256(&members),
            Err(JwkThumbprintErrorReason::MissingMember)
        );
    }
    // Both ASCII and multibyte input limits apply before JSON escaping.
    for value in ["x".repeat(8192), "é".repeat(4096), "\u{0}".repeat(8192)] {
        for members in with_each_member(&value) {
            let _digest = thumbprint_sha256(&members)?;
        }
        let _digest = thumbprint_sha256(&JwkThumbprintMembers::Ec {
            crv: &value,
            x: &value,
            y: &value,
        })?;
    }
    for value in ["x".repeat(8193), "é".repeat(4097), "\u{0}".repeat(8193)] {
        for members in with_each_member(&value) {
            assert_eq!(
                thumbprint_sha256(&members),
                Err(JwkThumbprintErrorReason::MemberTooLarge)
            );
        }
    }
    Ok(())
}

#[test]
fn output_and_canonical_secret_storage_support_zeroization() -> Result<(), JwkThumbprintErrorReason>
{
    fn requires_zeroize_on_drop<T: ZeroizeOnDrop>(_: &T) {}
    let secret = Zeroizing::new(String::from("symmetric-key"));
    let members = JwkThumbprintMembers::Oct { k: &secret };
    let mut canonical = encode(&members)?;
    let mut digest: Zeroizing<[u8; 32]> = thumbprint_sha256(&members)?;
    requires_zeroize_on_drop(&canonical);
    requires_zeroize_on_drop(&digest);
    assert!(digest.iter().any(|byte| *byte != 0));
    digest.zeroize();
    canonical.zeroize();
    assert_eq!(*digest, [0; 32]);
    assert!(canonical.is_empty());
    // Borrowing must never wipe the caller's storage as a side effect.
    assert_eq!(secret.as_str(), "symmetric-key");
    Ok(())
}
