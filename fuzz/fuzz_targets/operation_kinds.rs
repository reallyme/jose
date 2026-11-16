// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use std::sync::LazyLock;

use buffa::{EnumValue, Enumeration};
use reallyme_jose::api::contract::JoseOperationKind as ContractKind;
use reallyme_jose::wire::JoseOperationKind;

pub(super) fn operation_kinds() -> &'static [JoseOperationKind] {
    // Resolve the complete selector set once so new operations are covered
    // automatically and a missing native mapping fails the harness.
    static KINDS: LazyLock<Vec<JoseOperationKind>> = LazyLock::new(|| {
        ContractKind::values()
            .iter()
            .copied()
            .filter(|kind| *kind != ContractKind::Unspecified)
            .map(
                |kind| match JoseOperationKind::try_from(EnumValue::from(kind)) {
                    Ok(operation) => operation,
                    Err(_) => std::process::abort(),
                },
            )
            .collect()
    });
    KINDS.as_slice()
}
