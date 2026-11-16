// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Provider-backed compact JWS byte preservation and policy tests.

use core::cell::Cell;
use core::num::NonZeroU64;

use reallyme_codec::base64url::bytes_to_base64url;
use reallyme_jose::api::{
    contract::{
        jose_jws_sign_response, jose_operation_request, jose_operation_response, JoseErrorReason,
        JoseExternalJwsAlgorithm, JoseInspectedCompactJws, JoseJwsInspectRequest,
        JoseJwsSignWithProviderRequest, JoseJwsVerifyWithProviderRequest, JoseOperationRequest,
    },
    execute, execute_with_providers, OperationProviders,
};
use reallyme_jose::jws::{
    external_jws_algorithm, sign_compact_jws_with_provider, verify_compact_jws_with_provider,
};
use reallyme_jose::wire::{JoseWireError, JoseWireErrorBranch, JoseWireResult};
use zeroize::Zeroizing;

const HEADER: &[u8] = br#"{ "typ":"dpop+jwt", "jwk":{"kty":"EC"}, "alg":"ES384" }"#;
const PAYLOAD: &[u8] = br#"{"htu":"https://example.org"}"#;
const SIGNATURE: &[u8] = &[1, 2, 3];

fn signing_input() -> String {
    format!(
        "{}.{}",
        bytes_to_base64url(HEADER),
        bytes_to_base64url(PAYLOAD)
    )
}

fn sign_request() -> JoseJwsSignWithProviderRequest {
    JoseJwsSignWithProviderRequest::default()
        .with_protected_header_json(HEADER)
        .with_payload(PAYLOAD)
        .with_algorithm(JoseExternalJwsAlgorithm::Es384)
        .with_allow_embedded_jwk(true)
}

fn verify_request(compact: &str) -> JoseJwsVerifyWithProviderRequest {
    JoseJwsVerifyWithProviderRequest::default()
        .with_input(JoseJwsInspectRequest::default().with_compact(compact))
        .with_allow_embedded_jwk(true)
}

#[test]
fn exact_header_and_signing_input_survive_direct_and_wire_provider_paths() -> JoseWireResult<()> {
    let expected_input = signing_input();
    let result = sign_compact_jws_with_provider(&sign_request(), |algorithm, input| {
        assert_eq!(algorithm, JoseExternalJwsAlgorithm::Es384);
        assert_eq!(input, expected_input.as_bytes());
        Ok::<_, JoseWireError>(Zeroizing::new(SIGNATURE.to_vec()))
    })?;
    let compact = format!("{}.{}", expected_input, bytes_to_base64url(SIGNATURE));
    assert_eq!(result.compact.as_str(), compact);

    let (receipt, capability_result) =
        verify_compact_jws_with_provider(&verify_request(&compact), |algorithm, input, parsed| {
            assert_eq!(algorithm, JoseExternalJwsAlgorithm::Es384);
            assert_eq!(input, expected_input.as_bytes());
            assert_eq!(parsed.signature.as_slice(), SIGNATURE);
            Ok::<_, JoseWireError>(true)
        })?;
    assert!(capability_result);
    assert_eq!(receipt.protected_header_json.as_slice(), HEADER);
    assert_eq!(receipt.payload.as_slice(), PAYLOAD);

    let request = JoseOperationRequest::default().with_operation(
        jose_operation_request::Operation::JwsSignWithProvider(Box::new(
            sign_request().with_signer_handle(1),
        )),
    );
    let response = execute_with_providers(request, &mut TestProvider);
    assert!(matches!(
        &response.response,
        Some(jose_operation_response::Response::JwsSignWithProvider(response))
            if matches!(&response.outcome, Some(jose_jws_sign_response::Outcome::Result(value))
                if value.compact.as_str() == compact)
    ));

    let request = JoseOperationRequest::default().with_operation(
        jose_operation_request::Operation::JwsVerifyWithProvider(Box::new(
            verify_request(&compact).with_verifier_handle(2),
        )),
    );
    let response = execute_with_providers(request, &mut TestProvider);
    assert!(matches!(
        &response.response,
        Some(jose_operation_response::Response::JwsVerifyWithProvider(response))
            if matches!(&response.outcome,
                Some(reallyme_jose::api::contract::jose_jws_verify_response::Outcome::Result(value))
                if value.payload.as_slice() == PAYLOAD)
    ));
    Ok(())
}

#[test]
fn malformed_headers_and_limits_fail_before_injected_crypto() {
    let called = Cell::new(false);
    for header in [
        br#"{"alg":"ES384","x":{"v":0,"v":1}}"#.as_slice(),
        br#"{"alg":"ES384","b64":false}"#,
        br#"{"alg":"ES384","crit":["custom"]}"#,
        br#"{"alg":"ES384","jku":"https://example.org"}"#,
        br#"{"alg":"ES384","jwk":{"kty":"EC","d":"private"}}"#,
        br#"{"alg":"ES256"}"#,
        br#"{"alg":"none"}"#,
    ] {
        let result = sign_compact_jws_with_provider(
            &sign_request().with_protected_header_json(header),
            |_, _| {
                called.set(true);
                Ok::<_, JoseWireError>(Zeroizing::new(SIGNATURE.to_vec()))
            },
        );
        assert_eq!(
            result.err().map(JoseWireError::reason),
            Some(JoseErrorReason::JwsHeaderMismatch)
        );
    }

    let result =
        sign_compact_jws_with_provider(&sign_request().with_max_compact_bytes(8), |_, _| {
            called.set(true);
            Ok::<_, JoseWireError>(Zeroizing::new(SIGNATURE.to_vec()))
        });
    assert_eq!(
        result.err().map(JoseWireError::reason),
        Some(JoseErrorReason::CommonResourceLimitExceeded)
    );
    let result = sign_compact_jws_with_provider(&sign_request(), |_, _| {
        Ok::<_, JoseWireError>(Zeroizing::new(Vec::new()))
    });
    assert_eq!(
        result.err().map(JoseWireError::reason),
        Some(JoseErrorReason::JwsBadRawSignature)
    );
    assert_eq!(
        external_jws_algorithm("RS512").ok(),
        Some(JoseExternalJwsAlgorithm::Rs512)
    );

    let malformed = format!("{}.AQI=", signing_input());
    let invalid = verify_compact_jws_with_provider(&verify_request(&malformed), |_, _, _| {
        called.set(true);
        Ok::<_, JoseWireError>(())
    });
    assert_eq!(
        invalid.err().map(JoseWireError::reason),
        Some(JoseErrorReason::JwsBadSignatureBase64)
    );

    let compact = format!("{}.AQID", signing_input());
    let disabled = verify_compact_jws_with_provider(
        &verify_request(&compact).with_allow_embedded_jwk(false),
        |_, _, _| {
            called.set(true);
            Ok::<_, JoseWireError>(())
        },
    );
    assert_eq!(
        disabled.err().map(JoseWireError::reason),
        Some(JoseErrorReason::JwsHeaderMismatch)
    );
    assert!(!called.get());
}

#[test]
fn missing_provider_and_rejected_signature_produce_no_receipt() {
    let response = execute(JoseOperationRequest::default().with_operation(
        jose_operation_request::Operation::JwsSignWithProvider(Box::new(
            sign_request().with_signer_handle(1),
        )),
    ));
    assert!(
        matches!(&response.response, Some(jose_operation_response::Response::JwsSignWithProvider(response))
        if matches!(&response.outcome, Some(jose_jws_sign_response::Outcome::Error(error))
            if matches!(&error.error,
                Some(reallyme_jose::api::contract::jose_error::Error::Provider(error))
                if error.reason == JoseErrorReason::ProviderUnavailable)))
    );
    let rejection = JoseWireError::try_new(
        JoseWireErrorBranch::Primitive,
        JoseErrorReason::JwsInvalidSignature,
    );
    assert!(rejection.is_ok());
    if let Ok(rejection) = rejection {
        let compact = format!("{}.AQID", signing_input());
        let result = verify_compact_jws_with_provider(&verify_request(&compact), |_, _, _| {
            Err::<(), _>(rejection)
        });
        assert_eq!(result.err(), Some(rejection));
    }
}

struct TestProvider;

impl OperationProviders for TestProvider {
    fn sign_compact_jws(
        &self,
        handle: NonZeroU64,
        algorithm: JoseExternalJwsAlgorithm,
        input: &[u8],
    ) -> JoseWireResult<Zeroizing<Vec<u8>>> {
        assert_eq!(handle.get(), 1);
        assert_eq!(algorithm, JoseExternalJwsAlgorithm::Es384);
        assert_eq!(input, signing_input().as_bytes());
        Ok(Zeroizing::new(SIGNATURE.to_vec()))
    }

    fn verify_compact_jws(
        &self,
        handle: NonZeroU64,
        algorithm: JoseExternalJwsAlgorithm,
        signing_bytes: &[u8],
        input: &JoseInspectedCompactJws,
    ) -> JoseWireResult<()> {
        assert_eq!(handle.get(), 2);
        assert_eq!(algorithm, JoseExternalJwsAlgorithm::Es384);
        assert_eq!(signing_bytes, signing_input().as_bytes());
        assert_eq!(input.signature.as_slice(), SIGNATURE);
        Ok(())
    }
}
