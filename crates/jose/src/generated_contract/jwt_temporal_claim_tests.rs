// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

// Derived from the protobuf contract. Change the schema and regenerate.

use super::{Contract, JwtTemporalClaim};
use buffa::Enumeration;

#[test]
fn schema_parity_and_invalid_values() {
    let cases = [
        (Contract::JOSE_JWT_CLAIM_EXP, JwtTemporalClaim::Exp),
        (Contract::JOSE_JWT_CLAIM_NBF, JwtTemporalClaim::Nbf),
        (Contract::JOSE_JWT_CLAIM_IAT, JwtTemporalClaim::Iat),
    ];
    for (contract, native) in cases {
        assert_eq!(
            JwtTemporalClaim::try_from(buffa::EnumValue::from(contract)),
            Ok(native)
        );
        assert_eq!(Contract::from(native), contract);
    }
    for contract in Contract::values() {
        assert_eq!(
            JwtTemporalClaim::try_from(buffa::EnumValue::from(*contract)).is_ok(),
            cases.iter().any(|(value, _)| value == contract)
        );
    }
    for invalid in [0, -1, i32::MIN, i32::MAX] {
        assert!(JwtTemporalClaim::try_from(buffa::EnumValue::from(invalid)).is_err());
    }
}
