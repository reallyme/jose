// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

//! Contract tests for the generated canonical JOSE operation response.

#![cfg(feature = "generated")]
#![allow(missing_docs)]

use buffa::{EnumValue, Enumeration, Message};
use reallyme_jose_proto::generated::proto::reallyme::jose::v1::{
    __buffa::oneof::{
        jose_jwe_decrypt_response::Outcome as JweDecryptOutcome,
        jose_jws_verify_response::Outcome as JwsVerifyOutcome, jose_operation_response::Response,
    },
    JoseJweDecryptResponse, JoseJwePlaintextResult, JoseJwsVerifyResponse,
    JoseOperationContractVersion, JoseOperationResponse, JoseVerifyResult,
};

#[test]
fn canonical_response_version_and_field_numbers_are_stable() -> Result<(), buffa::DecodeError> {
    assert_eq!(
        JoseOperationContractVersion::JOSE_OPERATION_CONTRACT_VERSION_UNSPECIFIED.to_i32(),
        0
    );
    assert_eq!(
        JoseOperationContractVersion::JOSE_OPERATION_CONTRACT_VERSION_V1.to_i32(),
        1
    );
    assert!(JoseOperationContractVersion::from_i32(2).is_none());

    let response = JoseOperationResponse {
        contract_version: EnumValue::from(
            JoseOperationContractVersion::JOSE_OPERATION_CONTRACT_VERSION_V1,
        ),
        response: Some(Response::JwsVerify(Box::new(JoseJwsVerifyResponse {
            outcome: Some(JwsVerifyOutcome::Result(Box::new(JoseVerifyResult {
                __buffa_unknown_fields: Default::default(),
            }))),
            __buffa_unknown_fields: Default::default(),
        }))),
        __buffa_unknown_fields: Default::default(),
    };
    let expected = [0x50, 0x01, 0xca, 0x3e, 0x02, 0x0a, 0x00];
    assert_eq!(response.encode_to_vec(), expected);
    assert_eq!(
        JoseOperationResponse::decode_from_slice(&expected)?,
        response
    );
    Ok(())
}

#[test]
fn canonical_response_proto_json_round_trips_with_generated_oneofs(
) -> Result<(), Box<dyn std::error::Error>> {
    let response = JoseOperationResponse {
        contract_version: EnumValue::from(
            JoseOperationContractVersion::JOSE_OPERATION_CONTRACT_VERSION_V1,
        ),
        response: Some(Response::JwsVerify(Box::new(JoseJwsVerifyResponse {
            outcome: Some(JwsVerifyOutcome::Result(Box::new(JoseVerifyResult {
                __buffa_unknown_fields: Default::default(),
            }))),
            __buffa_unknown_fields: Default::default(),
        }))),
        __buffa_unknown_fields: Default::default(),
    };

    let json = serde_json::to_vec(&response)?;
    let decoded: JoseOperationResponse = serde_json::from_slice(&json)?;
    assert_eq!(decoded, response);
    Ok(())
}

#[test]
fn canonical_response_debug_redacts_nested_plaintext() {
    let response = JoseOperationResponse {
        contract_version: EnumValue::from(
            JoseOperationContractVersion::JOSE_OPERATION_CONTRACT_VERSION_V1,
        ),
        response: Some(Response::JweDecrypt(Box::new(JoseJweDecryptResponse {
            outcome: Some(JweDecryptOutcome::Result(Box::new(
                JoseJwePlaintextResult {
                    plaintext: vec![0x30, 0x82, 0x04, 0x0d],
                    __buffa_unknown_fields: Default::default(),
                },
            ))),
            __buffa_unknown_fields: Default::default(),
        }))),
        __buffa_unknown_fields: Default::default(),
    };

    let debug = format!("{response:?}");
    assert!(debug.contains("<redacted>"), "{debug}");
    assert!(!debug.contains("130"), "{debug}");
    assert!(!debug.contains("[48"), "{debug}");
}

#[test]
fn canonical_response_proto_json_rejects_unknown_and_conflicting_oneof_fields() {
    let unknown = br#"{"contractVersion":"JOSE_OPERATION_CONTRACT_VERSION_V1","unknown":{}}"#;
    assert!(serde_json::from_slice::<JoseOperationResponse>(unknown).is_err());

    let conflicting = br#"{
        "contractVersion":"JOSE_OPERATION_CONTRACT_VERSION_V1",
        "jwsVerify":{"result":{}},
        "jweDecrypt":{"result":{"plaintext":""}}
    }"#;
    assert!(serde_json::from_slice::<JoseOperationResponse>(conflicting).is_err());
}
