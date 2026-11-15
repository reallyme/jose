// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Presence, replacement, and malformed-input coverage for hardened generated owners.

#![cfg(feature = "generated")]

use buffa::{DecodeOptions, Message};
use reallyme_jose_proto::generated::proto::reallyme::jose::v1::{
    JoseJweEncryptRequest, JoseJwtAudience, JoseJwtHeaderEncodeOptions, JoseJwtRegisteredClaims,
    JoseJwtSignWithProviderRequest,
};

#[test]
fn optional_bytes_and_strings_preserve_empty_on_wire_and_json(
) -> Result<(), Box<dyn std::error::Error>> {
    let absent = JoseJweEncryptRequest::default();
    assert!(absent.encode_to_vec().is_empty());
    let present = JoseJweEncryptRequest::default()
        .with_kid("")
        .with_apu(Vec::new());
    assert_eq!(present.encode_to_vec(), [0x2a, 0, 0x32, 0]);
    let decoded = JoseJweEncryptRequest::decode_from_slice(&present.encode_to_vec())?;
    assert_eq!(decoded.kid.as_deref(), Some(""));
    assert_eq!(decoded.apu.as_deref(), Some([].as_slice()));
    assert_eq!(
        serde_json::to_value(&present)?,
        serde_json::json!({"kid":"", "apu":""})
    );
    for document in [r#"{}"#, r#"{"kid":null,"apu":null}"#] {
        let request: JoseJweEncryptRequest = serde_json::from_str(document)?;
        assert!(request.kid.is_none());
        assert!(request.apu.is_none());
    }
    let request: JoseJweEncryptRequest = serde_json::from_str(r#"{"kid":"","apu":""}"#)?;
    assert_eq!(request, present);
    Ok(())
}

#[test]
fn optional_numeric_scalars_keep_zero_presence() -> Result<(), Box<dyn std::error::Error>> {
    let mut claims = JoseJwtRegisteredClaims::default();
    claims.exp = Some(0);
    claims.iat = Some(i64::MIN);
    let decoded = JoseJwtRegisteredClaims::decode_from_slice(&claims.encode_to_vec())?;
    assert_eq!(decoded, claims);
    assert_eq!(
        serde_json::from_slice::<JoseJwtRegisteredClaims>(&serde_json::to_vec(&claims)?)?,
        claims
    );
    let request: JoseJwtSignWithProviderRequest = serde_json::from_str(r#"{"signerHandle":"0"}"#)?;
    assert_eq!(request.signer_handle, Some(0));
    assert!(
        serde_json::from_str::<JoseJwtSignWithProviderRequest>(r#"{"signerHandle":"-1"}"#).is_err()
    );
    Ok(())
}

#[test]
fn merge_replaces_sensitive_fields_and_clear_removes_presence(
) -> Result<(), Box<dyn std::error::Error>> {
    // Singular protobuf fields use the final occurrence, including explicit empty.
    let mut message = JoseJweEncryptRequest::default()
        .with_apu(vec![0xa5; 4096])
        .with_kid("secret");
    let merge = DecodeOptions::new()
        .reject_unknown_fields()
        .clear_on_merge_error();
    merge.merge_from_slice(&mut message, &[0x32, 0, 0x2a, 0])?;
    assert_eq!(message.kid.as_deref(), Some(""));
    assert_eq!(message.apu.as_deref(), Some([].as_slice()));
    message.clear();
    assert!(message.kid.is_none());
    assert!(message.apu.is_none());
    assert!(message.encode_to_vec().is_empty());
    let mut options = JoseJwtHeaderEncodeOptions::default().with_typ("secret");
    assert!(matches!(
        merge.merge_from_slice(&mut options, &[0x0a, 1, 0xff]),
        Err(buffa::DecodeError::InvalidUtf8)
    ));
    assert!(options.typ.is_none());

    let mut oversized = JoseJwtHeaderEncodeOptions::default().with_typ("secret");
    let result = merge
        .with_max_message_size(1)
        .merge_from_slice(&mut oversized, &[0x0a, 0]);
    assert!(matches!(result, Err(buffa::DecodeError::MessageTooLarge)));
    assert!(oversized.typ.is_none());
    Ok(())
}

#[test]
fn json_failures_reject_unknown_fields_alias_duplicates_and_partial_values() {
    for document in [
        r#"{"kid":"secret","apu":"QUJD!!!!"}"#,
        r#"{"apu":"QUJD","unknown":true}"#,
        r#"{"kid":"first","kid":"second"}"#,
        r#"{"apu":123}"#,
        r#"{"hasKid":true}"#,
    ] {
        assert!(serde_json::from_str::<JoseJweEncryptRequest>(document).is_err());
    }
    assert!(serde_json::from_str::<JoseJwtAudience>(r#"{"values":["secret",1]}"#).is_err());
    // Null may stand for an absent collection, but it is not a repeated
    // string element under the native ProtoJSON policy.
    assert!(serde_json::from_str::<JoseJwtAudience>(r#"{"values":[null]}"#).is_err());
    assert!(
        serde_json::from_str::<JoseJwtAudience>(r#"{"values":null}"#)
            .is_ok_and(|value| value.values.is_empty())
    );
    assert!(serde_json::from_str::<JoseJwtSignWithProviderRequest>(
        r#"{"signerHandle":"1","signer_handle":"2"}"#
    )
    .is_err());
}
