// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

#[test]
fn jwk_thumbprint_routes_and_generated_borrowing_cover_every_family(
) -> Result<(), Box<dyn std::error::Error>> {
    use reallyme_jose::api::contract::{
        self, __buffa::oneof::jose_jwk_thumbprint_sha256response::Outcome,
    };
    use reallyme_jose::jwk::{thumbprint_sha256, JwkThumbprintMembers};

    let requests = [
        r#"{"jwkThumbprintSha256":{"ec":{"crv":"P-256","x":"x","y":"y"}}}"#,
        r#"{"jwkThumbprintSha256":{"okp":{"crv":"Ed25519","x":"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"}}}"#,
        r#"{"jwkThumbprintSha256":{"rsa":{"e":"AQAB","n":"n"}}}"#,
        r#"{"jwkThumbprintSha256":{"oct":{"k":"secret"}}}"#,
    ];
    for json in requests {
        let request: JoseOperationRequest = reallyme_jose::wire::decode_json(json.as_bytes())?;
        let Some(RequestOperation::JwkThumbprintSha256(key)) = request.operation.as_ref() else {
            panic!("fixture omitted thumbprint operation");
        };
        let members = JwkThumbprintMembers::try_from(key.as_ref())?;
        let expected = thumbprint_sha256(&members)?;
        let response = assert_canonical_route_parity(
            &request,
            JoseOperationKind::JwkThumbprintSha256,
            [1; 12],
        )?;
        assert!(
            matches!(response.response.as_ref(), Some(Response::JwkThumbprintSha256(value))
            if matches!(value.outcome.as_ref(), Some(Outcome::Result(result)) if result.digest.as_slice() == expected.as_ref()))
        );
    }

    let missing = contract::JoseJwkThumbprintSha256Request::default();
    assert!(matches!(
        JwkThumbprintMembers::try_from(&missing),
        Err(reallyme_jose::jwk::JwkThumbprintErrorReason::MissingMember)
    ));
    Ok(())
}

#[test]
fn jwk_thumbprint_errors_remain_operation_scoped_and_digest_length_is_validated(
) -> Result<(), Box<dyn std::error::Error>> {
    use reallyme_jose::api::contract::{
        self, __buffa::oneof::jose_jwk_thumbprint_sha256response::Outcome,
    };
    use reallyme_jose::wire::{decode_json, execute_operation_request};

    for json in [
        r#"{"jwkThumbprintSha256":{}}"#,
        r#"{"jwkThumbprintSha256":{"ec":{"crv":"P-256","x":"x"}}}"#,
        r#"{"jwkThumbprintSha256":{"okp":{"x":"x"}}}"#,
        r#"{"jwkThumbprintSha256":{"rsa":{"n":"n"}}}"#,
        r#"{"jwkThumbprintSha256":{"oct":{"k":""}}}"#,
    ] {
        let request: JoseOperationRequest = decode_json(json.as_bytes())?;
        let response = assert_canonical_route_parity(
            &request,
            JoseOperationKind::JwkThumbprintSha256,
            [1; 12],
        )?;
        assert!(
            matches!(response.response.as_ref(), Some(Response::JwkThumbprintSha256(value))
            if matches!(value.outcome.as_ref(), Some(Outcome::Error(error))
                if matches!(error.error.as_ref(), Some(ErrorBranch::Primitive(failure)) if failure.reason == JoseErrorReason::JwkThumbprintMissingMember)))
        );
    }
    let oversized = "x".repeat(8193);
    let mut key = contract::JoseJwkThumbprintSha256Request::default();
    key.key = Some(
        contract::__buffa::oneof::jose_jwk_thumbprint_sha256request::Key::Oct(Box::new(
            contract::JoseJwkThumbprintOctMembers {
                k: oversized.into(),
            },
        )),
    );
    let response = execute_operation_request(
        operation(RequestOperation::JwkThumbprintSha256(Box::new(key))),
        &mut FixedRandom::new([1; 12]),
    );
    assert!(
        matches!(response.response.as_ref(), Some(Response::JwkThumbprintSha256(value))
        if matches!(value.outcome.as_ref(), Some(Outcome::Error(error))
            if matches!(error.error.as_ref(), Some(ErrorBranch::Primitive(failure)) if failure.reason == JoseErrorReason::JwkThumbprintMemberTooLarge)))
    );

    for length in [0, 31, 32, 33] {
        let response = JoseOperationResponse {
            contract_version: JoseOperationContractVersion::V2.into(),
            response: Some(Response::JwkThumbprintSha256(Box::new(
                contract::JoseJwkThumbprintSha256Response {
                    outcome: Some(Outcome::Result(Box::new(
                        contract::JoseJwkThumbprintSha256Result {
                            digest: vec![1; length].into(),
                        },
                    ))),
                },
            ))),
        };
        let bytes = encode_protobuf(&response);
        assert_eq!(
            decode_operation_response_v1(&bytes, JoseOperationKind::JwkThumbprintSha256).is_ok(),
            length == 32
        );
        assert!(decode_operation_response_v1(&bytes, JoseOperationKind::JwtSign).is_err());
    }
    Ok(())
}
