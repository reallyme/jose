// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

// Derived from the protobuf contract. Change the schema and regenerate.

use super::{Contract, ExternalJwsAlgorithm};
use buffa::Enumeration;

#[test]
fn schema_parity_and_invalid_values() {
    let cases = [
        (
            Contract::JOSE_EXTERNAL_JWS_ALGORITHM_ES256,
            ExternalJwsAlgorithm::Es256,
        ),
        (
            Contract::JOSE_EXTERNAL_JWS_ALGORITHM_ES384,
            ExternalJwsAlgorithm::Es384,
        ),
        (
            Contract::JOSE_EXTERNAL_JWS_ALGORITHM_ES512,
            ExternalJwsAlgorithm::Es512,
        ),
        (
            Contract::JOSE_EXTERNAL_JWS_ALGORITHM_ES256K,
            ExternalJwsAlgorithm::Es256k,
        ),
        (
            Contract::JOSE_EXTERNAL_JWS_ALGORITHM_EDDSA,
            ExternalJwsAlgorithm::EdDsa,
        ),
        (
            Contract::JOSE_EXTERNAL_JWS_ALGORITHM_PS256,
            ExternalJwsAlgorithm::Ps256,
        ),
        (
            Contract::JOSE_EXTERNAL_JWS_ALGORITHM_PS384,
            ExternalJwsAlgorithm::Ps384,
        ),
        (
            Contract::JOSE_EXTERNAL_JWS_ALGORITHM_PS512,
            ExternalJwsAlgorithm::Ps512,
        ),
        (
            Contract::JOSE_EXTERNAL_JWS_ALGORITHM_RS256,
            ExternalJwsAlgorithm::Rs256,
        ),
        (
            Contract::JOSE_EXTERNAL_JWS_ALGORITHM_RS384,
            ExternalJwsAlgorithm::Rs384,
        ),
        (
            Contract::JOSE_EXTERNAL_JWS_ALGORITHM_RS512,
            ExternalJwsAlgorithm::Rs512,
        ),
    ];
    for (contract, native) in cases {
        assert_eq!(
            ExternalJwsAlgorithm::try_from(buffa::EnumValue::from(contract)),
            Ok(native)
        );
        assert_eq!(Contract::from(native), contract);
    }
    for contract in Contract::values() {
        assert_eq!(
            ExternalJwsAlgorithm::try_from(buffa::EnumValue::from(*contract)).is_ok(),
            cases.iter().any(|(value, _)| value == contract)
        );
    }
    for invalid in [0, -1, i32::MIN, i32::MAX] {
        assert!(ExternalJwsAlgorithm::try_from(buffa::EnumValue::from(invalid)).is_err());
    }
}
