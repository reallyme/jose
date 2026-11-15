// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use super::{JweKeyManagementSuite, JwtAlgorithm};
use crate::jwe::{
    JweCompressionAlgorithm, JweContentEncryptionAlgorithm, JweKeyManagementAlgorithm,
};
use crate::jws::parse_header::JwsAlgorithm;
use crate::wire::proto::proto::reallyme::jose::v1::{
    JoseErrorReason, JoseJweCompressionAlgorithm, JoseJweContentEncryptionAlgorithm,
    JoseJweHeaderAlgorithm, JoseJweKeyManagementAlgorithm, JoseSignatureAlgorithm,
};
use crate::wire::JoseWireError;
use buffa::{EnumValue, Enumeration};

fn assert_selector<E, N>(cases: &[(E, N)], reason: JoseErrorReason)
where
    E: Enumeration + 'static,
    N: TryFrom<EnumValue<E>, Error = JoseWireError> + core::fmt::Debug + PartialEq,
{
    for generated in E::values().iter().filter(|value| value.to_i32() != 0) {
        assert_eq!(
            N::try_from(EnumValue::from(*generated)).is_ok(),
            cases.iter().any(|(value, _)| value == generated)
        );
    }
    for (generated, native) in cases {
        assert_eq!(
            N::try_from(EnumValue::from(*generated)).as_ref(),
            Ok(native)
        );
    }
    for invalid in [0, -1, 1, i32::MAX, i32::MIN] {
        let result = N::try_from(EnumValue::from(invalid));
        assert_eq!(result.map_err(JoseWireError::reason), Err(reason));
    }
}

#[test]
fn signature_selectors_match_the_contract_and_reject_unset_and_unknown() {
    assert_selector(
        &[
            (JoseSignatureAlgorithm::Eddsa, JwsAlgorithm::Eddsa),
            (JoseSignatureAlgorithm::Es256, JwsAlgorithm::Es256),
        ],
        JoseErrorReason::ProviderUnsupported,
    );
    assert_selector(
        &[
            (JoseSignatureAlgorithm::Eddsa, JwtAlgorithm::Eddsa),
            (JoseSignatureAlgorithm::Es256, JwtAlgorithm::Es256),
            (JoseSignatureAlgorithm::Es256k, JwtAlgorithm::Es256k),
        ],
        JoseErrorReason::ProviderUnsupported,
    );
}

#[test]
fn jwe_header_identity_stays_distinct_from_curve_specific_suites() {
    assert_selector(
        &[
            (
                JoseJweHeaderAlgorithm::Direct,
                JweKeyManagementAlgorithm::Direct,
            ),
            (
                JoseJweHeaderAlgorithm::EcdhEs,
                JweKeyManagementAlgorithm::EcdhEs,
            ),
        ],
        JoseErrorReason::ProviderUnsupported,
    );
    assert_selector(
        &[
            (
                JoseJweKeyManagementAlgorithm::Direct,
                JweKeyManagementSuite::Direct,
            ),
            (
                JoseJweKeyManagementAlgorithm::EcdhEsP256,
                JweKeyManagementSuite::P256,
            ),
            (
                JoseJweKeyManagementAlgorithm::EcdhEsP384,
                JweKeyManagementSuite::P384,
            ),
            (
                JoseJweKeyManagementAlgorithm::EcdhEsP521,
                JweKeyManagementSuite::P521,
            ),
        ],
        JoseErrorReason::ProviderUnsupported,
    );
    assert_eq!(
        JweKeyManagementSuite::Direct.header_algorithm(),
        JweKeyManagementAlgorithm::Direct
    );
    for suite in [
        JweKeyManagementSuite::P256,
        JweKeyManagementSuite::P384,
        JweKeyManagementSuite::P521,
    ] {
        assert_eq!(suite.header_algorithm(), JweKeyManagementAlgorithm::EcdhEs);
    }
}

#[test]
fn content_algorithms_match_the_contract_and_reject_unset_and_unknown() {
    assert_selector(
        &[
            (
                JoseJweContentEncryptionAlgorithm::A128gcm,
                JweContentEncryptionAlgorithm::A128Gcm,
            ),
            (
                JoseJweContentEncryptionAlgorithm::A192gcm,
                JweContentEncryptionAlgorithm::A192Gcm,
            ),
            (
                JoseJweContentEncryptionAlgorithm::A256gcm,
                JweContentEncryptionAlgorithm::A256Gcm,
            ),
        ],
        JoseErrorReason::ProviderUnsupported,
    );
    assert_selector(
        &[(
            JoseJweCompressionAlgorithm::Deflate,
            JweCompressionAlgorithm::Deflate,
        )],
        JoseErrorReason::JweUnsupportedCompressionAlgorithm,
    );
}

#[test]
fn generated_operation_and_branch_identities_have_total_native_conversions() {
    use crate::api::contract::{JoseErrorBranch, JoseOperationKind};
    use crate::wire::{JoseOperationKind as NativeKind, JoseWireErrorBranch};
    for value in JoseOperationKind::values()
        .iter()
        .copied()
        .filter(|value| *value != JoseOperationKind::Unspecified)
    {
        assert!(NativeKind::try_from(EnumValue::from(value)).is_ok());
    }
    for value in JoseErrorBranch::values()
        .iter()
        .copied()
        .filter(|value| *value != JoseErrorBranch::Unspecified)
    {
        assert!(JoseWireErrorBranch::try_from(EnumValue::from(value)).is_ok());
    }
    for invalid in [0, -1, 99, i32::MIN, i32::MAX] {
        assert_eq!(
            NativeKind::try_from(EnumValue::from(invalid)).map_err(JoseWireError::reason),
            Err(JoseErrorReason::BackendInternal)
        );
        assert_eq!(
            JoseWireErrorBranch::try_from(EnumValue::from(invalid)).map_err(JoseWireError::reason),
            Err(JoseErrorReason::BackendInternal)
        );
    }
}

#[test]
fn claim_identifiers_reject_cross_family_and_unknown_values() {
    use crate::api::contract::JoseJwtClaim;
    use crate::jwt::{JwtRegisteredClaim, JwtTemporalClaim};
    for value in JoseJwtClaim::values().iter().copied() {
        let temporal = matches!(
            value,
            JoseJwtClaim::Exp | JoseJwtClaim::Nbf | JoseJwtClaim::Iat
        );
        let registered = matches!(
            value,
            JoseJwtClaim::Issuer | JoseJwtClaim::Subject | JoseJwtClaim::Audience
        );
        assert_eq!(
            JwtTemporalClaim::try_from(EnumValue::from(value)).is_ok(),
            temporal
        );
        assert_eq!(
            JwtRegisteredClaim::try_from(EnumValue::from(value)).is_ok(),
            registered
        );
    }
    for invalid in [-1, i32::MAX, i32::MIN] {
        assert!(JwtTemporalClaim::try_from(EnumValue::from(invalid)).is_err());
        assert!(JwtRegisteredClaim::try_from(EnumValue::from(invalid)).is_err());
    }
}
