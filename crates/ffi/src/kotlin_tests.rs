// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use reallyme_crypto::core::{CryptoError, RngFailureKind, RngOutputKind};
use reallyme_crypto::csprng::{OsSecureRandom, SecureRandom};
use reallyme_jose::wire::{
    decode_operation_response_v1, execute_operation_json_v1,
    proto::proto::reallyme::jose::v1::{
        __buffa::oneof::{
            jose_error::Error, jose_jwe_encrypt_response::Outcome,
            jose_operation_response::Response,
        },
        JoseErrorReason,
    },
    JoseOperationKind,
};
use zeroize::Zeroizing;

use super::{
    finish_response, transfer_response, JoseFfiStatus, NativeProviderFailure, JOSE_ABI_VERSION,
};
use crate::operation::rm_jose_abi_version;

#[test]
fn jni_and_c_abi_versions_are_identical() {
    assert_eq!(rm_jose_abi_version(), JOSE_ABI_VERSION);
}

const JWE_REQUEST: &[u8] = br#"{
    "jweEncrypt": {
        "keyManagementAlgorithm": "JOSE_JWE_KEY_MANAGEMENT_ALGORITHM_DIRECT",
        "contentEncryptionAlgorithm": "JOSE_JWE_CONTENT_ENCRYPTION_ALGORITHM_A128GCM",
        "key": "AAAAAAAAAAAAAAAAAAAAAA==",
        "plaintext": "dGVzdA=="
    }
}"#;

struct UnavailableEntropy;

impl SecureRandom for UnavailableEntropy {
    fn fill_secure(&mut self, _: &mut [u8], output: RngOutputKind) -> Result<(), CryptoError> {
        Err(CryptoError::Rng {
            output,
            kind: RngFailureKind::EntropyUnavailable,
        })
    }
}

struct OutcomeChange {
    sizing: Zeroizing<Vec<u8>>,
    writing: Zeroizing<Vec<u8>>,
    capacities: Vec<usize>,
}

impl OutcomeChange {
    fn new(sizing_succeeds: bool) -> Self {
        let success = execute_operation_json_v1(JWE_REQUEST, &mut OsSecureRandom);
        let failure = execute_operation_json_v1(JWE_REQUEST, &mut UnavailableEntropy);
        assert!(failure.len() < success.len());
        let decoded = decode_operation_response_v1(&success, JoseOperationKind::JweEncrypt).ok();
        assert!(
            matches!(decoded.as_ref().and_then(|response| response.response.as_ref()),
            Some(Response::JweEncrypt(value)) if matches!(&value.outcome, Some(Outcome::Result(_))))
        );
        let (sizing, writing) = if sizing_succeeds {
            (success, failure)
        } else {
            (failure, success)
        };
        Self {
            sizing,
            writing,
            capacities: Vec::new(),
        }
    }

    fn execute(&mut self, output: Option<&mut [u8]>, produced: &mut usize) -> i32 {
        let Some(output) = output else {
            self.capacities.push(0);
            *produced = self.sizing.len();
            return JoseFfiStatus::OutputCapacityMismatch.code();
        };
        self.capacities.push(output.len());
        assert_eq!(*produced, 0);
        *produced = self.writing.len();
        // Dirty the allocation even on a transport failure so the test can
        // distinguish complete erasure from clearing only a claimed prefix.
        output.fill(0xa5);
        let Some(prefix) = output.get_mut(..self.writing.len()) else {
            return JoseFfiStatus::OutputCapacityMismatch.code();
        };
        prefix.copy_from_slice(&self.writing);
        JoseFfiStatus::Success.code()
    }
}

#[test]
fn shorter_write_preserves_typed_error_and_wipes_every_discarded_byte() {
    let mut sequence = OutcomeChange::new(true);
    let response = transfer_response(|output, produced| sequence.execute(output, produced));
    assert!(response.is_ok());
    let Ok(response) = response else { return };
    assert_eq!(sequence.capacities, [0, sequence.sizing.len()]);
    assert_eq!(response.as_slice(), sequence.writing.as_slice());

    let decoded = decode_operation_response_v1(&response, JoseOperationKind::JweEncrypt);
    assert!(decoded.is_ok());
    let Ok(decoded) = decoded else { return };
    assert!(
        matches!(&decoded.response, Some(Response::JweEncrypt(value))
        if matches!(&value.outcome, Some(Outcome::Error(error))
            if matches!(&error.error, Some(Error::Provider(provider))
                if provider.reason == JoseErrorReason::JOSE_ERROR_REASON_PROVIDER_RANDOMNESS_UNAVAILABLE)))
    );

    let mut live = vec![0xa5; sequence.sizing.len()];
    let mut produced = 0;
    let status = sequence.execute(Some(&mut live), &mut produced);
    assert_eq!(finish_response(&mut live, status, produced), Ok(()));
    assert_eq!(live.get(..produced), Some(sequence.writing.as_slice()));
    assert!(live
        .get(produced..)
        .is_some_and(|tail| !tail.is_empty() && tail.iter().all(|byte| *byte == 0)));
}

#[test]
fn larger_write_returns_provider_failure_and_erases_the_entire_allocation() {
    let mut sequence = OutcomeChange::new(false);
    let response = transfer_response(|output, produced| sequence.execute(output, produced));
    assert!(matches!(&response, Err(error)
        if error.exception_class() == jni::jni_str!("me/really/jose/ReallyMeJoseException$NativeProviderFailure")));
    assert_eq!(sequence.capacities, [0, sequence.sizing.len()]);

    let mut live = vec![0; sequence.sizing.len()];
    let mut produced = 0;
    let status = sequence.execute(Some(&mut live), &mut produced);
    assert!(live.iter().all(|byte| *byte == 0xa5));
    assert_eq!(
        finish_response(&mut live, status, produced),
        Err(NativeProviderFailure)
    );
    assert_eq!(live.len(), sequence.sizing.len());
    assert!(live.iter().all(|byte| *byte == 0));
}
