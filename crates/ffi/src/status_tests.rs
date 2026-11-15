// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use super::JoseFfiStatus;
use buffa::{EnumValue, Enumeration};
use reallyme_jose::api::contract::JoseTransportStatus as Contract;

#[test]
fn schema_statuses_preserve_the_c_representation_and_reject_unknowns() {
    let cases = [
        (Contract::Success, JoseFfiStatus::Success, 0),
        (Contract::CallerError, JoseFfiStatus::CallerError, -1),
        (Contract::ProviderError, JoseFfiStatus::ProviderError, -2),
        (Contract::BackendError, JoseFfiStatus::BackendError, -3),
        (Contract::PanicCaught, JoseFfiStatus::PanicCaught, -4),
        (
            Contract::OutputCapacityMismatch,
            JoseFfiStatus::OutputCapacityMismatch,
            -5,
        ),
        (Contract::UnsupportedAbi, JoseFfiStatus::UnsupportedAbi, -6),
    ];
    for generated in Contract::values()
        .iter()
        .filter(|value| **value != Contract::Unspecified)
    {
        assert!(cases.iter().any(|(value, _, _)| value == generated));
    }
    for (generated, native, code) in cases {
        assert_eq!(
            JoseFfiStatus::try_from(EnumValue::from(generated)),
            Ok(native)
        );
        assert_eq!(native.code(), code);
    }
    for invalid in [0, -1, 17, i32::MIN, i32::MAX] {
        assert_eq!(
            JoseFfiStatus::try_from(EnumValue::from(invalid)),
            Err(JoseFfiStatus::CallerError)
        );
    }
}
