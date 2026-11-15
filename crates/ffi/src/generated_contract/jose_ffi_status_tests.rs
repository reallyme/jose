// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

// Derived from the protobuf contract. Change the schema and regenerate.

use super::{Contract, JoseFfiStatus};
use buffa::Enumeration;

#[test]
fn schema_parity_and_invalid_values() {
    let cases = [
        (
            Contract::JOSE_TRANSPORT_STATUS_SUCCESS,
            JoseFfiStatus::Success,
        ),
        (
            Contract::JOSE_TRANSPORT_STATUS_CALLER_ERROR,
            JoseFfiStatus::CallerError,
        ),
        (
            Contract::JOSE_TRANSPORT_STATUS_PROVIDER_ERROR,
            JoseFfiStatus::ProviderError,
        ),
        (
            Contract::JOSE_TRANSPORT_STATUS_BACKEND_ERROR,
            JoseFfiStatus::BackendError,
        ),
        (
            Contract::JOSE_TRANSPORT_STATUS_PANIC_CAUGHT,
            JoseFfiStatus::PanicCaught,
        ),
        (
            Contract::JOSE_TRANSPORT_STATUS_OUTPUT_CAPACITY_MISMATCH,
            JoseFfiStatus::OutputCapacityMismatch,
        ),
        (
            Contract::JOSE_TRANSPORT_STATUS_UNSUPPORTED_ABI,
            JoseFfiStatus::UnsupportedAbi,
        ),
    ];
    for (contract, native) in cases {
        assert_eq!(
            JoseFfiStatus::try_from(buffa::EnumValue::from(contract)),
            Ok(native)
        );
        assert_eq!(Contract::from(native), contract);
    }
    for contract in Contract::values() {
        assert_eq!(
            JoseFfiStatus::try_from(buffa::EnumValue::from(*contract)).is_ok(),
            cases.iter().any(|(value, _)| value == contract)
        );
    }
    for invalid in [0, -1, i32::MIN, i32::MAX] {
        assert!(JoseFfiStatus::try_from(buffa::EnumValue::from(invalid)).is_err());
    }
}
