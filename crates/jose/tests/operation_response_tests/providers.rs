// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

const PROVIDER_KEY: [u8; 16] = [7; 16];

struct TestProviders {
    signer: reallyme_crypto::signer::DispatchSigner,
    encryptor: reallyme_jose::jwe::DirectJweKeyEncryptor<'static>,
    resolver: reallyme_jose::jwe::DirectJweKeyResolver<'static>,
}

fn unavailable_capability() -> JoseWireError {
    match JoseWireError::try_new(
        JoseWireErrorBranch::Provider,
        JoseErrorReason::ProviderUnavailable,
    ) {
        Ok(error) => error,
        Err(_) => panic!("test provider reason belongs to the provider branch"),
    }
}

impl reallyme_jose::api::OperationProviders for TestProviders {
    fn signer(
        &self,
        handle: core::num::NonZeroU64,
    ) -> Result<&dyn reallyme_jose::Signer, JoseWireError> {
        if handle.get() == 1 {
            Ok(&self.signer)
        } else {
            Err(unavailable_capability())
        }
    }
    fn jwe_encryptor(
        &mut self,
        handle: core::num::NonZeroU64,
    ) -> Result<&mut dyn reallyme_jose::jwe::JweContentEncryptionKeyEncryptor, JoseWireError> {
        if handle.get() == 1 {
            Ok(&mut self.encryptor)
        } else {
            Err(unavailable_capability())
        }
    }
    fn jwe_resolver(
        &self,
        handle: core::num::NonZeroU64,
    ) -> Result<&dyn reallyme_jose::jwe::JweContentEncryptionKeyResolver, JoseWireError> {
        if handle.get() == 1 {
            Ok(&self.resolver)
        } else {
            Err(unavailable_capability())
        }
    }
}

#[test]
fn generated_provider_handles_preserve_signing_and_jwe_capabilities(
) -> Result<(), Box<dyn std::error::Error>> {
    use contract::__buffa::oneof::{
        jose_jwe_decrypt_with_provider_response::Outcome as Decrypt,
        jose_jwe_encrypt_with_provider_response::Outcome as Encrypt,
        jose_jwt_sign_with_provider_response::Outcome as Sign,
    };
    use reallyme_crypto::jwk::ed25519_public_key_to_jwk;
    use reallyme_jose::api::contract;
    use reallyme_jose::jwe::{DirectJweKeyEncryptor, DirectJweKeyResolver};
    use reallyme_jose::wire::execute_operation_request_with_providers;
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
    let mut providers = TestProviders {
        signer: reallyme_crypto::signer::DispatchSigner::new(Algorithm::Ed25519, private),
        encryptor: DirectJweKeyEncryptor::new(&PROVIDER_KEY),
        resolver: DirectJweKeyResolver::new(&PROVIDER_KEY),
    };
    let claims = serde_json::json!({"sub":"recipient"});
    let expected =
        reallyme_jose::jwt::encode_signed_jwt_with_signer(&claims, &jwk, &providers.signer)?;
    let mut sign = contract::JoseJwtSignWithProviderRequest::default();
    sign.claims_json = serde_json::to_vec(&claims)?.into();
    sign.jwk_json = serde_json::to_vec(&jwk)?.into();
    sign.signer_handle = Some(1);
    let response = execute_operation_request_with_providers(
        operation(RequestOperation::JwtSignWithProvider(Box::new(
            sign.clone(),
        ))),
        &mut FixedRandom::new([8; 12]),
        &mut providers,
    );
    assert!(
        matches!(response.response.as_ref(), Some(Response::JwtSignWithProvider(value)) if matches!(value.outcome.as_ref(), Some(Sign::Result(result)) if result.compact == expected))
    );
    for handle in [None, Some(0), Some(2)] {
        sign.signer_handle = handle;
        let response = execute_operation_request_with_providers(
            operation(RequestOperation::JwtSignWithProvider(Box::new(
                sign.clone(),
            ))),
            &mut FixedRandom::new([8; 12]),
            &mut providers,
        );
        let (branch, reason) = if handle == Some(2) {
            (
                JoseWireErrorBranch::Provider,
                JoseErrorReason::ProviderUnavailable,
            )
        } else {
            (
                JoseWireErrorBranch::Primitive,
                JoseErrorReason::CommonMalformedProtobuf,
            )
        };
        assert_response_error(
            response,
            Some(JoseOperationKind::JwtSignWithProvider),
            branch,
            reason,
        );
    }

    let mut parameters = direct_jwe_encrypt_request();
    zeroize::Zeroize::zeroize(&mut parameters.key);
    let mut encrypt = contract::JoseJweEncryptWithProviderRequest::default();
    encrypt.parameters = parameters.into();
    encrypt.provider_handle = Some(1);
    let response = execute_operation_request_with_providers(
        operation(RequestOperation::JweEncryptWithProvider(Box::new(
            encrypt.clone(),
        ))),
        &mut FixedRandom::new([8; 12]),
        &mut providers,
    );
    let compact = match response.response.as_ref() {
        Some(Response::JweEncryptWithProvider(value)) => match value.outcome.as_ref() {
            Some(Encrypt::Result(result)) => result.compact.clone(),
            _ => panic!("capability encryption failed"),
        },
        _ => panic!("capability encryption selected the wrong response"),
    };
    let mut direct = direct_jwe_encrypt_request();
    direct.key = PROVIDER_KEY.to_vec().into();
    let expected = assert_route_parity(
        &operation(RequestOperation::JweEncrypt(Box::new(direct))),
        JoseOperationKind::JweEncrypt,
        [8; 12],
    )?;
    assert_eq!(compact, decode_compact(&expected)?);
    let mut policy = contract::JoseJwePolicy::default();
    policy.allowed_key_management_algorithms =
        vec![contract::JoseJweHeaderAlgorithm::Direct.into()].into();
    policy.allowed_content_encryption_algorithms =
        vec![contract::JoseJweContentEncryptionAlgorithm::A128gcm.into()].into();
    let mut decrypt = contract::JoseJweDecryptWithProviderRequest::default();
    decrypt.compact = compact;
    decrypt.policy = policy.into();
    decrypt.provider_handle = Some(1);
    let response = execute_operation_request_with_providers(
        operation(RequestOperation::JweDecryptWithProvider(Box::new(
            decrypt.clone(),
        ))),
        &mut FixedRandom::new([8; 12]),
        &mut providers,
    );
    assert!(
        matches!(response.response.as_ref(), Some(Response::JweDecryptWithProvider(value)) if matches!(value.outcome.as_ref(), Some(Decrypt::Result(result)) if result.plaintext == b"wire policy plaintext"))
    );
    decrypt.provider_handle = Some(2);
    assert_response_error(
        execute_operation_request_with_providers(
            operation(RequestOperation::JweDecryptWithProvider(Box::new(decrypt))),
            &mut FixedRandom::new([8; 12]),
            &mut providers,
        ),
        Some(JoseOperationKind::JweDecryptWithProvider),
        JoseWireErrorBranch::Provider,
        JoseErrorReason::ProviderUnavailable,
    );
    encrypt.provider_handle = Some(2);
    assert_response_error(
        execute_operation_request_with_providers(
            operation(RequestOperation::JweEncryptWithProvider(Box::new(encrypt))),
            &mut FixedRandom::new([8; 12]),
            &mut providers,
        ),
        Some(JoseOperationKind::JweEncryptWithProvider),
        JoseWireErrorBranch::Provider,
        JoseErrorReason::ProviderUnavailable,
    );
    Ok(())
}

#[test]
fn generated_claims_and_contract_metadata_match_native_views(
) -> Result<(), Box<dyn std::error::Error>> {
    use contract::__buffa::oneof::{
        jose_contract_info_response::Outcome as Info,
        jose_jwt_claims_parse_response::Outcome as Claims,
        jose_signature_suite_info_response::Outcome as Suite,
    };
    use reallyme_jose::api::contract;
    let document = br#"{"iss":"issuer","sub":"subject","aud":[],"exp":-1,"nbf":0,"iat":1,"jti":"id","custom":{"value":true}}"#;
    let mut request = contract::JoseJwtClaimsParseRequest::default();
    request.claims_json = document.to_vec().into();
    let response = assert_canonical_route_parity(
        &operation(RequestOperation::JwtClaimsParse(Box::new(request))),
        JoseOperationKind::JwtClaimsParse,
        [1; 12],
    )?;
    assert!(
        matches!(response.response.as_ref(), Some(Response::JwtClaimsParse(value)) if matches!(value.outcome.as_ref(), Some(Claims::Result(result)) if result.claims_json == document && result.registered.exp == Some(-1) && result.registered.nbf == Some(0) && result.registered.aud.is_set() && result.registered.aud.values.is_empty()))
    );
    let response = assert_canonical_route_parity(
        &operation(RequestOperation::ContractInfo(Box::default())),
        JoseOperationKind::ContractInfo,
        [1; 12],
    )?;
    assert!(
        matches!(response.response.as_ref(), Some(Response::ContractInfo(value)) if matches!(value.outcome.as_ref(), Some(Info::Result(result)) if result.operation_kinds.len() == contract::JoseOperationKind::values().len().checked_sub(1).ok_or(buffa::DecodeError::UnexpectedEof)?))
    );
    for algorithm in contract::JoseSignatureAlgorithm::values()
        .iter()
        .copied()
        .filter(|value| *value != contract::JoseSignatureAlgorithm::Unspecified)
    {
        let request = contract::JoseSignatureSuiteInfoRequest {
            algorithm: algorithm.into(),
        };
        let response = assert_canonical_route_parity(
            &operation(RequestOperation::SignatureSuiteInfo(Box::new(request))),
            JoseOperationKind::SignatureSuiteInfo,
            [1; 12],
        )?;
        assert!(
            matches!(response.response.as_ref(), Some(Response::SignatureSuiteInfo(value)) if matches!(value.outcome.as_ref(), Some(Suite::Result(result)) if result.algorithm == algorithm && result.builtin_provider == (algorithm == contract::JoseSignatureAlgorithm::Es256)))
        );
    }
    Ok(())
}

#[cfg(feature = "native")]
#[test]
fn provider_encryption_cannot_override_the_selected_curve() -> Result<(), Box<dyn std::error::Error>>
{
    use reallyme_jose::api::{contract, OperationProviders};
    use reallyme_jose::jwe::{JweContentEncryptionKeyEncryptor, P384EcdhEsJweKeyEncryptor};
    struct WrongCurve<'a>(P384EcdhEsJweKeyEncryptor<'a>);
    impl OperationProviders for WrongCurve<'_> {
        fn jwe_encryptor(
            &mut self,
            _handle: core::num::NonZeroU64,
        ) -> Result<&mut dyn JweContentEncryptionKeyEncryptor, JoseWireError> {
            Ok(&mut self.0)
        }
    }
    let (public, _private) =
        reallyme_crypto::p384::generate_p384_keypair_from_secret_key(&[9; 48])?;
    let mut providers = WrongCurve(P384EcdhEsJweKeyEncryptor::new(&public));
    let mut parameters = direct_jwe_encrypt_request();
    zeroize::Zeroize::zeroize(&mut parameters.key);
    parameters.key_management_algorithm =
        contract::JoseJweKeyManagementAlgorithm::EcdhEsP256.into();
    let mut request = contract::JoseJweEncryptWithProviderRequest::default();
    request.parameters = parameters.into();
    request.provider_handle = Some(1);
    assert_response_error(
        reallyme_jose::wire::execute_operation_request_with_providers(
            operation(RequestOperation::JweEncryptWithProvider(Box::new(
                request.clone(),
            ))),
            &mut FixedRandom::new([8; 12]),
            &mut providers,
        ),
        Some(JoseOperationKind::JweEncryptWithProvider),
        JoseWireErrorBranch::Primitive,
        JoseErrorReason::JweHeaderPolicyMismatch,
    );
    request.parameters.get_or_insert_default().key = vec![7; 16].into();
    assert_response_error(
        reallyme_jose::wire::execute_operation_request_with_providers(
            operation(RequestOperation::JweEncryptWithProvider(Box::new(request))),
            &mut FixedRandom::new([8; 12]),
            &mut providers,
        ),
        Some(JoseOperationKind::JweEncryptWithProvider),
        JoseWireErrorBranch::Primitive,
        JoseErrorReason::JweInvalidKeyAgreementKey,
    );
    Ok(())
}
