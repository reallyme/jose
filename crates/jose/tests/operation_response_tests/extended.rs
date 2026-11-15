// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

#[test]
fn generated_signature_primitives_preserve_native_bytes_and_errors(
) -> Result<(), Box<dyn std::error::Error>> {
    use contract::__buffa::oneof::{
        jose_signature_sign_response::Outcome as Sign,
        jose_signature_verify_response::Outcome as Verify,
    };
    use reallyme_jose::api::contract;
    use reallyme_jose::jws::suites::es256::sign_p256_jose_prehash;
    let (public, private) = generate_p256_keypair_from_secret_key(&[23; 32])?;
    let message = b"exact signature input";
    let expected = sign_p256_jose_prehash(&private, message)?;
    let mut sign = contract::JoseSignatureSignRequest::default();
    sign.algorithm = contract::JoseSignatureAlgorithm::Es256.into();
    sign.private_key = private.to_vec().into();
    sign.signing_input = message.to_vec().into();
    let response = assert_canonical_route_parity(
        &operation(RequestOperation::SignatureSign(Box::new(sign))),
        JoseOperationKind::SignatureSign,
        [1; 12],
    )?;
    assert!(
        matches!(response.response.as_ref(), Some(Response::SignatureSign(value)) if matches!(value.outcome.as_ref(), Some(Sign::Result(result)) if result.signature == expected))
    );
    let mut verify = contract::JoseSignatureVerifyRequest::default();
    verify.algorithm = contract::JoseSignatureAlgorithm::Es256.into();
    verify.public_key = public.into();
    verify.signing_input = message.to_vec().into();
    verify.signature = expected.to_vec().into();
    let response = assert_canonical_route_parity(
        &operation(RequestOperation::SignatureVerify(Box::new(verify.clone()))),
        JoseOperationKind::SignatureVerify,
        [1; 12],
    )?;
    assert!(
        matches!(response.response.as_ref(), Some(Response::SignatureVerify(value)) if matches!(value.outcome.as_ref(), Some(Verify::Result(_))))
    );
    verify.signing_input = [verify.signing_input.as_slice(), &[0]].concat().into();
    let response = assert_canonical_route_parity(
        &operation(RequestOperation::SignatureVerify(Box::new(verify))),
        JoseOperationKind::SignatureVerify,
        [1; 12],
    )?;
    assert_response_error(
        response,
        Some(JoseOperationKind::SignatureVerify),
        JoseWireErrorBranch::Primitive,
        JoseErrorReason::JwsInvalidSignature,
    );
    for invalid in [
        0,
        -1,
        99,
        i32::MAX,
        contract::JoseSignatureAlgorithm::Eddsa.to_i32(),
    ] {
        let mut request = contract::JoseSignatureSignRequest::default();
        request.algorithm = invalid.into();
        let response = assert_canonical_route_parity(
            &operation(RequestOperation::SignatureSign(Box::new(request))),
            JoseOperationKind::SignatureSign,
            [1; 12],
        )?;
        assert_response_error(
            response,
            Some(JoseOperationKind::SignatureSign),
            JoseWireErrorBranch::Provider,
            JoseErrorReason::ProviderUnsupported,
        );
    }
    Ok(())
}

#[test]
fn generated_derivation_matches_native_and_rejects_invalid_secrets(
) -> Result<(), Box<dyn std::error::Error>> {
    use contract::__buffa::oneof::jose_jwe_derive_key_response::Outcome;
    use reallyme_jose::api::contract;
    use reallyme_jose::jwe::{derive_ecdh_es_content_encryption_key, CompactJweProtectedHeader};
    let native: CompactJweProtectedHeader =
        serde_json::from_str(r#"{"alg":"dir","enc":"A256GCM"}"#)?;
    let expected = derive_ecdh_es_content_encryption_key(&[5; 32], &native)?;
    let mut request = contract::JoseJweDeriveKeyRequest::default();
    request.shared_secret = vec![5; 32].into();
    let mut header = contract::JoseJweProtectedHeader::default();
    header.algorithm = contract::JoseJweHeaderAlgorithm::Direct.into();
    header.content_encryption_algorithm =
        contract::JoseJweContentEncryptionAlgorithm::A256gcm.into();
    request.header = header.into();
    let response = assert_canonical_route_parity(
        &operation(RequestOperation::JweDeriveKey(Box::new(request.clone()))),
        JoseOperationKind::JweDeriveKey,
        [1; 12],
    )?;
    assert!(
        matches!(response.response.as_ref(), Some(Response::JweDeriveKey(value)) if matches!(value.outcome.as_ref(), Some(Outcome::Result(value)) if value.value == *expected))
    );
    zeroize::Zeroize::zeroize(&mut request.shared_secret);
    let response = assert_canonical_route_parity(
        &operation(RequestOperation::JweDeriveKey(Box::new(request))),
        JoseOperationKind::JweDeriveKey,
        [1; 12],
    )?;
    assert_response_error(
        response,
        Some(JoseOperationKind::JweDeriveKey),
        JoseWireErrorBranch::Primitive,
        JoseErrorReason::JweInvalidSharedSecret,
    );
    Ok(())
}

#[test]
fn typed_requests_reject_nested_unknown_fields_and_excessive_input(
) -> Result<(), buffa::DecodeError> {
    use reallyme_jose::api::{contract, execute};
    // A dropping generated owner cannot carry unknown-field storage. Reject
    // unknown data while the original nested bytes are still available.
    let malformed = br#"{"jwtVerify":{"verification":{"signatureOnly":{"unknown":1}}}}"#;
    let response =
        reallyme_jose::wire::execute_operation_json_v1(malformed, &mut FixedRandom::new([1; 12]));
    let response = contract::JoseOperationResponse::decode_from_slice(&response)?;
    assert_response_error(
        response,
        None,
        JoseWireErrorBranch::Primitive,
        JoseErrorReason::CommonMalformedJson,
    );
    // Raw nested requests prove rejection before the runtime can discard an
    // unknown varint or group in the otherwise empty signature-only policy.
    let unknown_wire: [&[u8]; 2] = [
        &[0x9a, 0x7d, 7, 0x3a, 5, 0x0a, 3, 0x98, 0x06, 1],
        &[
            0x9a, 0x7d, 10, 0x3a, 8, 0x0a, 6, 0x9b, 0x06, 8, 1, 0x9c, 0x06,
        ],
    ];
    for malformed in unknown_wire {
        let bytes =
            reallyme_jose::wire::execute_operation_v1(malformed, &mut FixedRandom::new([1; 12]));
        assert_response_error(
            contract::JoseOperationResponse::decode_from_slice(&bytes)?,
            None,
            JoseWireErrorBranch::Primitive,
            JoseErrorReason::CommonMalformedProtobuf,
        );
    }
    let mut sign = contract::JoseJwsSignRequest::default();
    sign.payload = vec![0; MAX_JOSE_PROTO_MESSAGE_BYTES].into();
    assert_response_error(
        execute(operation(RequestOperation::JwsSign(Box::new(sign)))),
        None,
        JoseWireErrorBranch::Primitive,
        JoseErrorReason::CommonResourceLimitExceeded,
    );
    Ok(())
}

#[test]
fn claims_parsing_rejects_non_objects_duplicates_and_invalid_registered_values(
) -> Result<(), Box<dyn std::error::Error>> {
    use reallyme_jose::api::contract;
    for (document, reason) in [
        ("[]", JoseErrorReason::JwtInvalidClaims),
        (
            "[null,null,null,null,null,null,null]",
            JoseErrorReason::JwtInvalidClaims,
        ),
        ("null", JoseErrorReason::JwtInvalidClaims),
        (
            r#"{"iss":"first","iss":"second"}"#,
            JoseErrorReason::JwtInvalidClaims,
        ),
        (
            r#"{"custom":{"duplicate":1,"duplicate":2}}"#,
            JoseErrorReason::JwtInvalidClaims,
        ),
        (r#"{"exp":1.5}"#, JoseErrorReason::JwtSerializationFailed),
        (
            r#"{"exp":9223372036854775808}"#,
            JoseErrorReason::JwtSerializationFailed,
        ),
        (r#"{"aud":[1]}"#, JoseErrorReason::JwtSerializationFailed),
    ] {
        let mut request = contract::JoseJwtClaimsParseRequest::default();
        request.claims_json = document.as_bytes().to_vec().into();
        let response = assert_canonical_route_parity(
            &operation(RequestOperation::JwtClaimsParse(Box::new(request))),
            JoseOperationKind::JwtClaimsParse,
            [1; 12],
        )?;
        assert_response_error(
            response,
            Some(JoseOperationKind::JwtClaimsParse),
            JoseWireErrorBranch::Primitive,
            reason,
        );
    }
    Ok(())
}
