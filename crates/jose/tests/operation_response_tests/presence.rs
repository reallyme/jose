// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

#[test]
fn jwe_explicit_empty_headers_match_native_and_survive_both_encodings(
) -> Result<(), Box<dyn std::error::Error>> {
    use reallyme_jose::jwe::{
        encrypt_compact_jwe_bytes, CompactJweEncryptRequest, DirectJweKeyEncryptor,
        JweContentEncryptionAlgorithm,
    };
    let mut request = direct_jwe_encrypt_request();
    request.kid = Some(String::new().into());
    request.typ = Some(String::new().into());
    request.cty = Some(String::new().into());
    let native =
        CompactJweEncryptRequest::new(&request.plaintext, JweContentEncryptionAlgorithm::A128Gcm)
            .with_kid("")
            .with_typ("")
            .with_cty("");
    let expected = encrypt_compact_jwe_bytes(
        &native,
        &mut DirectJweKeyEncryptor::new(&request.key),
        &mut FixedRandom::new([7; 12]),
    )?;
    let response = assert_canonical_route_parity(
        &operation(RequestOperation::JweEncrypt(Box::new(request))),
        JoseOperationKind::JweEncrypt,
        [7; 12],
    )?;
    assert_eq!(decode_compact(&normalize_response(response))?, expected);

    let mut invalid = direct_jwe_encrypt_request();
    invalid.apu = Some(Vec::new().into());
    let encoded = assert_canonical_route_parity(
        &operation(RequestOperation::JweEncrypt(Box::new(invalid))),
        JoseOperationKind::JweEncrypt,
        [7; 12],
    )?;
    assert_response_error(
        encoded,
        Some(JoseOperationKind::JweEncrypt),
        JoseWireErrorBranch::Primitive,
        JoseErrorReason::JweInvalidHeader,
    );
    Ok(())
}

#[test]
fn jwt_typ_default_omission_and_explicit_values_match_native(
) -> Result<(), Box<dyn std::error::Error>> {
    use reallyme_crypto::jwk::ed25519_public_key_to_jwk;
    use reallyme_jose::api::contract;
    use reallyme_jose::jwt::{encode_signed_jwt_with_header_options, JwtHeaderEncodeOptions};
    let (public, private) = generate_keypair(Algorithm::Ed25519)?;
    let jwk = Jwk::Okp(
        ed25519_public_key_to_jwk(
            &public,
            JwkOptions {
                alg: true,
                use_sig: true,
                use_enc: false,
                kid: None,
            },
        )?
        .into(),
    );
    let claims = serde_json::json!({"sub":"recipient"});
    for (outer, typ) in [
        (false, None),
        (true, None),
        (true, Some("application/example+jwt")),
        (true, Some("")),
    ] {
        let mut request = contract::JoseJwtSignRequest::default();
        request.private_key = private.to_vec().into();
        request.jwk_json = serde_json::to_vec(&jwk)?.into();
        request.claims_json = serde_json::to_vec(&claims)?.into();
        if outer {
            let mut options = contract::JoseJwtHeaderEncodeOptions::default();
            options.typ = typ.map(Into::into);
            request.header_options = options.into();
        }
        let response = assert_canonical_route_parity(
            &operation(RequestOperation::JwtSign(Box::new(request))),
            JoseOperationKind::JwtSign,
            [1; 12],
        )?;
        if typ == Some("") {
            assert_response_error(
                response,
                Some(JoseOperationKind::JwtSign),
                JoseWireErrorBranch::Primitive,
                JoseErrorReason::JwtInvalidHeader,
            );
        } else {
            let options = if outer {
                JwtHeaderEncodeOptions::new(typ.map(str::to_owned))
            } else {
                JwtHeaderEncodeOptions::jwt()
            };
            let expected =
                encode_signed_jwt_with_header_options(&claims, &jwk, &private, &options)?;
            assert_eq!(decode_compact(&normalize_response(response))?, expected);
        }
    }
    Ok(())
}

#[test]
fn jwt_verification_oneof_rejects_conflicts_and_legacy_fields() {
    for json in [
        br#"{"jwtVerify":{"verification":{"signatureOnly":{},"claims":{}}}}"#.as_slice(),
        br#"{"jwtVerify":{"signatureOnly":true}}"#.as_slice(),
        br#"{"jwtVerify":{"temporalPolicy":{}}}"#.as_slice(),
        br#"{"jwtVerify":{"verification":{"claims":{"expectedIssuer":""}}}}"#.as_slice(),
        br#"{"jwtVerify":{"verification":{"claims":{"expectedSubject":""}}}}"#.as_slice(),
    ] {
        let response = execute_operation_json_v1(json, &mut FixedRandom::new([1; 12]));
        match decode_operation_response_v1(&response, JoseOperationKind::JwtVerify) {
            Ok(response) => assert_response_error(
                response,
                None,
                JoseWireErrorBranch::Primitive,
                JoseErrorReason::CommonMalformedJson,
            ),
            Err(error) => panic!("invalid error envelope: {error:?}"),
        }
    }
}
