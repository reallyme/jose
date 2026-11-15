// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

// Derived from the protobuf contract. Change the schema and regenerate.

use super::{Contract, JweKeyManagementSuite};
use buffa::Enumeration;

#[test]
fn schema_parity_and_invalid_values() {
    let cases = [
        (
            Contract::JOSE_JWE_KEY_MANAGEMENT_ALGORITHM_DIRECT,
            JweKeyManagementSuite::Direct,
        ),
        (
            Contract::JOSE_JWE_KEY_MANAGEMENT_ALGORITHM_ECDH_ES_P256,
            JweKeyManagementSuite::P256,
        ),
        (
            Contract::JOSE_JWE_KEY_MANAGEMENT_ALGORITHM_ECDH_ES_P384,
            JweKeyManagementSuite::P384,
        ),
        (
            Contract::JOSE_JWE_KEY_MANAGEMENT_ALGORITHM_ECDH_ES_P521,
            JweKeyManagementSuite::P521,
        ),
    ];
    for (contract, native) in cases {
        assert_eq!(
            JweKeyManagementSuite::try_from(buffa::EnumValue::from(contract)),
            Ok(native)
        );
        assert_eq!(Contract::from(native), contract);
    }
    for contract in Contract::values() {
        assert_eq!(
            JweKeyManagementSuite::try_from(buffa::EnumValue::from(*contract)).is_ok(),
            cases.iter().any(|(value, _)| value == contract)
        );
    }
    for invalid in [0, -1, i32::MIN, i32::MAX] {
        assert!(JweKeyManagementSuite::try_from(buffa::EnumValue::from(invalid)).is_err());
    }
}
