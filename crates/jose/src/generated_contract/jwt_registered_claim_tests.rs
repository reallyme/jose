// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

// Derived from the protobuf contract. Change the schema and regenerate.

use super::{Contract, JwtRegisteredClaim};
use buffa::Enumeration;

#[test]
fn schema_parity_and_invalid_values() {
    let cases = [
        (Contract::JOSE_JWT_CLAIM_ISSUER, JwtRegisteredClaim::Issuer),
        (
            Contract::JOSE_JWT_CLAIM_SUBJECT,
            JwtRegisteredClaim::Subject,
        ),
        (
            Contract::JOSE_JWT_CLAIM_AUDIENCE,
            JwtRegisteredClaim::Audience,
        ),
    ];
    for (contract, native) in cases {
        assert_eq!(
            JwtRegisteredClaim::try_from(buffa::EnumValue::from(contract)),
            Ok(native)
        );
        assert_eq!(Contract::from(native), contract);
    }
    for contract in Contract::values() {
        assert_eq!(
            JwtRegisteredClaim::try_from(buffa::EnumValue::from(*contract)).is_ok(),
            cases.iter().any(|(value, _)| value == contract)
        );
    }
    for invalid in [0, -1, i32::MIN, i32::MAX] {
        assert!(JwtRegisteredClaim::try_from(buffa::EnumValue::from(invalid)).is_err());
    }
}
