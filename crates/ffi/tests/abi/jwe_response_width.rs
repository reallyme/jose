// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

#![allow(clippy::unwrap_used)]

use reallyme_crypto::{
    core::{Algorithm, CryptoError, RngFailureKind, RngOutputKind},
    dispatch::generate_keypair,
};
use reallyme_jose::wire::proto::proto::reallyme::jose::v1::{
    __buffa::oneof::{
        jose_error::Error, jose_jwe_encrypt_response::Outcome, jose_operation_request::Operation,
        jose_operation_response::Response,
    },
    JoseErrorReason, JoseJweCompressionAlgorithm, JoseJweContentEncryptionAlgorithm,
    JoseJweEncryptRequest, JoseJweKeyManagementAlgorithm, JoseOperationRequest,
    JoseOperationResponse,
};
use reallyme_jose::wire::{encode_json, execute_operation_v1};
use reallyme_jose::{SecureRandom, Zeroizing};

use super::{
    decode_operation_response_v1, encode_protobuf, execute, execute_with_lengths,
    rm_jose_execute_operation_json_v1, rm_jose_execute_operation_v1, JoseOperationKind,
};

const KEY_MODES: [(JoseJweKeyManagementAlgorithm, Option<Algorithm>); 4] = [
    (
        JoseJweKeyManagementAlgorithm::JOSE_JWE_KEY_MANAGEMENT_ALGORITHM_DIRECT,
        None,
    ),
    (
        JoseJweKeyManagementAlgorithm::JOSE_JWE_KEY_MANAGEMENT_ALGORITHM_ECDH_ES_P256,
        Some(Algorithm::P256),
    ),
    (
        JoseJweKeyManagementAlgorithm::JOSE_JWE_KEY_MANAGEMENT_ALGORITHM_ECDH_ES_P384,
        Some(Algorithm::P384),
    ),
    (
        JoseJweKeyManagementAlgorithm::JOSE_JWE_KEY_MANAGEMENT_ALGORITHM_ECDH_ES_P521,
        Some(Algorithm::P521),
    ),
];

const CONTENT_SUITES: [(JoseJweContentEncryptionAlgorithm, usize); 3] = [
    (
        JoseJweContentEncryptionAlgorithm::JOSE_JWE_CONTENT_ENCRYPTION_ALGORITHM_A128GCM,
        16,
    ),
    (
        JoseJweContentEncryptionAlgorithm::JOSE_JWE_CONTENT_ENCRYPTION_ALGORITHM_A192GCM,
        24,
    ),
    (
        JoseJweContentEncryptionAlgorithm::JOSE_JWE_CONTENT_ENCRYPTION_ALGORITHM_A256GCM,
        32,
    ),
];

const COMPRESSION: [JoseJweCompressionAlgorithm; 2] = [
    JoseJweCompressionAlgorithm::JOSE_JWE_COMPRESSION_ALGORITHM_UNSPECIFIED,
    JoseJweCompressionAlgorithm::JOSE_JWE_COMPRESSION_ALGORITHM_DEFLATE,
];

pub(super) fn exercise_randomized_jwe_matrix() {
    for (key_mode, curve) in KEY_MODES {
        let public_key = curve.map(|curve| generate_keypair(curve).unwrap().0);
        for (suite, key_len) in CONTENT_SUITES {
            let direct_key = Zeroizing::new(vec![0x42; key_len]);
            let key = public_key.as_deref().unwrap_or(direct_key.as_slice());
            for compression in COMPRESSION {
                let request = request(key_mode, suite, compression, key);
                let binary = encode_protobuf(&request);
                let json = encode_json(&request).unwrap();
                // Both exports require an independent write to fit exactly in
                // the capacity reported by their zero-capacity sizing call.
                let (first, binary_probe_len, _) =
                    execute_with_lengths(rm_jose_execute_operation_v1, &binary);
                let (second, json_probe_len, _) =
                    execute_with_lengths(rm_jose_execute_operation_json_v1, &json);
                assert_eq!(binary_probe_len, json_probe_len);

                let first = decode(&first);
                let second = decode(&second);
                let first_segments = segments(compact(&first));
                let second_segments = segments(compact(&second));
                assert_eq!(first_segments.map(str::len), second_segments.map(str::len));
                let [first_header, first_key, first_iv, ..] = first_segments;
                let [second_header, second_key, second_iv, ..] = second_segments;
                assert!(first_key.is_empty() && second_key.is_empty());
                assert_ne!(first_iv, second_iv);
                if curve.is_some() {
                    // Only the ephemeral public key can change the header.
                    assert_ne!(first_header, second_header);
                } else {
                    assert_eq!(first_header, second_header);
                }
            }
        }
    }
}

fn request(
    key_mode: JoseJweKeyManagementAlgorithm,
    suite: JoseJweContentEncryptionAlgorithm,
    compression: JoseJweCompressionAlgorithm,
    key: &[u8],
) -> JoseOperationRequest {
    let mut request = JoseOperationRequest::default();
    let mut inner = JoseJweEncryptRequest::default();
    inner.key_management_algorithm = key_mode.into();
    inner.content_encryption_algorithm = suite.into();
    inner.compression_algorithm = compression.into();
    inner.key.extend_from_slice(key);
    inner.plaintext = b"Repeated plaintext exercises the selected compression mode.".repeat(8);
    inner.kid = "quoted \"key\" \\ identifier".to_owned();
    inner.typ = "application/example".to_owned();
    if key_mode != JoseJweKeyManagementAlgorithm::JOSE_JWE_KEY_MANAGEMENT_ALGORITHM_DIRECT {
        inner.apu = vec![0, 255];
        inner.apv = vec![9, 8, 7];
    }
    request.operation = Some(Operation::JweEncrypt(Box::new(inner)));
    request
}

fn decode(bytes: &[u8]) -> JoseOperationResponse {
    decode_operation_response_v1(bytes, JoseOperationKind::JweEncrypt).unwrap()
}

fn compact(response: &JoseOperationResponse) -> &str {
    let result = match response.response.as_ref() {
        Some(Response::JweEncrypt(response)) => response.outcome.as_ref(),
        _ => None,
    };
    let compact = match result {
        Some(Outcome::Result(result)) => Some(result.compact.as_str()),
        _ => None,
    };
    assert!(compact.is_some(), "expected a successful JWE encryption");
    compact.unwrap()
}

fn segments(compact: &str) -> [&str; 5] {
    <[&str; 5]>::try_from(compact.split('.').collect::<Vec<_>>()).unwrap()
}

#[test]
fn protobuf_framing_keeps_equal_compact_widths_at_varint_boundaries() {
    use reallyme_jose::jwe::MAX_COMPACT_JWE_BYTES;
    use reallyme_jose::wire::proto::proto::reallyme::jose::v1::{
        JoseCompactResult, JoseJweEncryptResponse, JoseOperationContractVersion,
    };

    for width in [
        125,
        126,
        127,
        128,
        16_378,
        16_379,
        16_380,
        16_383,
        16_384,
        MAX_COMPACT_JWE_BYTES,
    ] {
        let encode_response = |byte: &str| {
            let mut response = JoseOperationResponse::default();
            response.contract_version =
                JoseOperationContractVersion::JOSE_OPERATION_CONTRACT_VERSION_V1.into();
            let mut operation = JoseJweEncryptResponse::default();
            operation.outcome = Some(Outcome::Result(Box::new(JoseCompactResult {
                compact: byte.repeat(width),
                __buffa_unknown_fields: Default::default(),
            })));
            response.response = Some(Response::JweEncrypt(Box::new(operation)));
            encode_protobuf(&response)
        };
        let first = encode_response("A");
        let second = encode_response("_");
        assert_ne!(first.as_slice(), second.as_slice());
        assert_eq!(first.len(), second.len());
        assert!(first.len() <= super::rm_jose_max_response_bytes());
        assert_eq!(compact(&decode(&first)).len(), width);
        assert_eq!(compact(&decode(&second)).len(), width);
    }
}

struct UnavailableEntropy;

impl SecureRandom for UnavailableEntropy {
    fn fill_secure(&mut self, _: &mut [u8], output: RngOutputKind) -> Result<(), CryptoError> {
        Err(CryptoError::Rng {
            output,
            kind: RngFailureKind::EntropyUnavailable,
        })
    }
}

#[test]
fn entropy_failure_changes_the_operation_outcome_and_encoded_size() {
    let (mode, _) = KEY_MODES.first().copied().unwrap();
    let (suite, key_len) = CONTENT_SUITES.first().copied().unwrap();
    let compression = COMPRESSION.first().copied().unwrap();
    let key = Zeroizing::new(vec![0x42; key_len]);
    let request = encode_protobuf(&request(mode, suite, compression, &key));
    let success = execute(rm_jose_execute_operation_v1, &request);
    assert!(!compact(&decode(&success)).is_empty());

    let failed = execute_operation_v1(&request, &mut UnavailableEntropy);
    let error = decode(&failed);
    assert!(
        matches!(&error.response, Some(Response::JweEncrypt(response))
        if matches!(&response.outcome, Some(Outcome::Error(error))
            if matches!(&error.error, Some(Error::Provider(provider))
                if provider.reason == JoseErrorReason::JOSE_ERROR_REASON_PROVIDER_RANDOMNESS_UNAVAILABLE)))
    );
    assert!(failed.len() < success.len());
}
