// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

mod admission_tests;
mod budgets_tests;
mod contract_tests;

use crate::api::contract::{
    JoseJwsTransportCharacterPolicy as Characters, JoseJwsTransportComposeBudgets,
    JoseJwsTransportFrameBudgets, JoseJwsTransportMemberPolicy, JoseJwsTransportPolicy,
};

fn policy(characters: Characters, allow_empty: bool) -> JoseJwsTransportPolicy {
    let member = JoseJwsTransportMemberPolicy::default()
        .with_characters(characters)
        .with_allow_empty(allow_empty);
    JoseJwsTransportPolicy::default()
        .with_protected_header(member.clone())
        .with_payload(member.clone())
        .with_signature(member)
}

fn frame_budget(limit: u64) -> JoseJwsTransportFrameBudgets {
    JoseJwsTransportFrameBudgets::default().with_max_input_bytes(limit)
}

fn compose_budgets(input: u64, output: u64) -> JoseJwsTransportComposeBudgets {
    JoseJwsTransportComposeBudgets::default()
        .with_max_input_bytes(input)
        .with_max_output_bytes(output)
}
