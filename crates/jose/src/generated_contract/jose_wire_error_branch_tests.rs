// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

// Derived from the protobuf contract. Change the schema and regenerate.

use super::{Contract, JoseWireErrorBranch};
use buffa::Enumeration;

#[test]
fn schema_parity_and_invalid_values() {
    let cases = [
        (
            Contract::JOSE_ERROR_BRANCH_PRIMITIVE,
            JoseWireErrorBranch::Primitive,
        ),
        (
            Contract::JOSE_ERROR_BRANCH_PROVIDER,
            JoseWireErrorBranch::Provider,
        ),
        (
            Contract::JOSE_ERROR_BRANCH_BACKEND,
            JoseWireErrorBranch::Backend,
        ),
    ];
    for (contract, native) in cases {
        assert_eq!(
            JoseWireErrorBranch::try_from(buffa::EnumValue::from(contract)),
            Ok(native)
        );
        assert_eq!(Contract::from(native), contract);
    }
    for contract in Contract::values() {
        assert_eq!(
            JoseWireErrorBranch::try_from(buffa::EnumValue::from(*contract)).is_ok(),
            cases.iter().any(|(value, _)| value == contract)
        );
    }
    for invalid in [0, -1, i32::MIN, i32::MAX] {
        assert!(JoseWireErrorBranch::try_from(buffa::EnumValue::from(invalid)).is_err());
    }
}
