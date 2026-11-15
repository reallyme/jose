// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

// Derived from the protobuf contract. Change the schema and regenerate.

use super::{Contract, JwtAlgorithm};
use buffa::Enumeration;

#[test]
fn schema_parity_and_invalid_values() {
    let cases = [
        (
            Contract::JOSE_SIGNATURE_ALGORITHM_EDDSA,
            JwtAlgorithm::Eddsa,
        ),
        (
            Contract::JOSE_SIGNATURE_ALGORITHM_ES256,
            JwtAlgorithm::Es256,
        ),
        (
            Contract::JOSE_SIGNATURE_ALGORITHM_ES256K,
            JwtAlgorithm::Es256k,
        ),
    ];
    for (contract, native) in cases {
        assert_eq!(
            JwtAlgorithm::try_from(buffa::EnumValue::from(contract)),
            Ok(native)
        );
        assert_eq!(Contract::from(native), contract);
    }
    for contract in Contract::values() {
        assert_eq!(
            JwtAlgorithm::try_from(buffa::EnumValue::from(*contract)).is_ok(),
            cases.iter().any(|(value, _)| value == contract)
        );
    }
    for invalid in [0, -1, i32::MIN, i32::MAX] {
        assert!(JwtAlgorithm::try_from(buffa::EnumValue::from(invalid)).is_err());
    }
}
