// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

#![allow(clippy::arithmetic_side_effects)]

use super::{compose_budgets, frame_budget, policy, Characters};
use crate::api::contract::{
    JoseJwsInspectRequest, JoseJwsTransportComposeBudgets, JoseJwsTransportFrameBudgets,
};
use crate::jws::transport::{
    compose_compact_jws_unauthenticated as compose, frame_compact_jws_unauthenticated as frame,
    ComposeCompactJwsRequest, FrameCompactJwsRequest, JwsTransportErrorReason as Error,
};

#[test]
fn two_mebibyte_framing_does_not_change_strict_inspection() -> Result<(), Error> {
    const LIMIT: usize = 2 * 1024 * 1024;
    let input = format!("h.{}.s", "p".repeat(LIMIT - 4));
    let selected = policy(Characters::Base64urlAlphabet, false);
    let budgets = frame_budget(2_097_152);
    let view = frame(&FrameCompactJwsRequest {
        compact: &input,
        policy: &selected,
        budgets: &budgets,
    })?;
    assert_eq!(view.payload().len(), LIMIT - 4);
    assert_eq!(
        frame(&FrameCompactJwsRequest {
            compact: &input,
            policy: &selected,
            budgets: &frame_budget(2_097_151)
        })
        .err(),
        Some(Error::InputTooLarge)
    );
    assert_eq!(crate::jws::MAX_COMPACT_JWS_BYTES, 1_048_576);
    assert_eq!(
        crate::jws::inspect_compact_jws(
            &JoseJwsInspectRequest::default()
                .with_compact(input)
                .with_max_compact_bytes(2_097_152)
        )
        .err()
        .map(|e| e.reason()),
        Some(crate::api::contract::JoseErrorReason::CommonResourceLimitExceeded)
    );
    Ok(())
}

#[test]
fn three_mebibyte_composition_honors_independent_input_and_output_budgets() -> Result<(), Error> {
    const LIMIT: usize = 3 * 1024 * 1024;
    let payload = "p".repeat(LIMIT - 4);
    let selected = policy(Characters::Ascii, false);
    let budgets = compose_budgets(3_145_726, 3_145_728);
    let request = ComposeCompactJwsRequest {
        protected_header: "h",
        payload: &payload,
        signature: "s",
        policy: &selected,
        budgets: &budgets,
    };
    let result = compose(&request)?;
    assert_eq!(result.as_str().len(), LIMIT);
    assert!(result.as_str().starts_with("h.pp"));
    assert!(result.as_str().ends_with("pp.s"));
    assert_eq!(
        compose(&ComposeCompactJwsRequest {
            budgets: &compose_budgets(3_145_725, 3_145_728),
            ..request
        })
        .err(),
        Some(Error::InputTooLarge)
    );
    assert_eq!(
        compose(&ComposeCompactJwsRequest {
            budgets: &compose_budgets(3_145_726, 3_145_727),
            ..request
        })
        .err(),
        Some(Error::OutputTooLarge)
    );
    Ok(())
}

#[test]
fn byte_budgets_count_utf8_and_inserted_separators_exactly() -> Result<(), Error> {
    let selected = policy(Characters::OpaqueUtf8, true);
    let budgets = compose_budgets(3, 5);
    let request = ComposeCompactJwsRequest {
        protected_header: "é",
        payload: "",
        signature: "s",
        policy: &selected,
        budgets: &budgets,
    };
    assert_eq!(compose(&request)?.as_str(), "é..s");
    assert_eq!(
        compose(&ComposeCompactJwsRequest {
            budgets: &compose_budgets(2, 5),
            ..request
        })
        .err(),
        Some(Error::InputTooLarge)
    );
    assert_eq!(
        compose(&ComposeCompactJwsRequest {
            budgets: &compose_budgets(3, 4),
            ..request
        })
        .err(),
        Some(Error::OutputTooLarge)
    );
    assert_eq!(
        frame(&FrameCompactJwsRequest {
            compact: "é..s",
            policy: &selected,
            budgets: &frame_budget(4)
        })
        .err(),
        Some(Error::InputTooLarge)
    );
    assert_eq!(
        compose(&ComposeCompactJwsRequest {
            protected_header: "",
            payload: "",
            signature: "",
            policy: &selected,
            budgets: &compose_budgets(0, 2)
        })?
        .as_str(),
        ".."
    );
    assert_eq!(
        compose(&ComposeCompactJwsRequest {
            protected_header: "",
            payload: "",
            signature: "",
            policy: &selected,
            budgets: &compose_budgets(0, 1)
        })
        .err(),
        Some(Error::OutputTooLarge)
    );
    Ok(())
}

#[test]
fn missing_budgets_and_checked_overflows_are_typed() {
    use crate::jws::transport::admit::{budget, composed_lengths};
    let selected = policy(Characters::Ascii, false);
    assert_eq!(
        frame(&FrameCompactJwsRequest {
            compact: "h.p.s",
            policy: &selected,
            budgets: &JoseJwsTransportFrameBudgets::default()
        })
        .err(),
        Some(Error::MissingBudget)
    );
    for budgets in [
        JoseJwsTransportComposeBudgets::default(),
        JoseJwsTransportComposeBudgets::default().with_max_input_bytes(3),
        JoseJwsTransportComposeBudgets::default().with_max_output_bytes(5),
    ] {
        assert_eq!(
            compose(&ComposeCompactJwsRequest {
                protected_header: "h",
                payload: "p",
                signature: "s",
                policy: &selected,
                budgets: &budgets
            })
            .err(),
            Some(Error::MissingBudget)
        );
    }
    for lengths in [
        (usize::MAX, 1, 0),
        (0, usize::MAX, 1),
        (usize::MAX - 1, 0, 0),
    ] {
        assert_eq!(
            composed_lengths(lengths.0, lengths.1, lengths.2),
            Err(Error::LengthOverflow)
        );
    }
    assert_eq!(composed_lengths(0, 0, 0), Ok((0, 2)));
    assert_eq!(budget(Some(u64::MAX)).is_ok(), usize::BITS == u64::BITS);
}

#[test]
fn alphabet_admission_does_not_weaken_canonical_strict_inspection() -> Result<(), Error> {
    let selected = policy(Characters::Base64urlAlphabet, false);
    for input in ["A.A.A", "Zh.Zh.Zh", "Zg.Zg.Zg"] {
        let view = frame(&FrameCompactJwsRequest {
            compact: input,
            policy: &selected,
            budgets: &frame_budget(100),
        })?;
        assert_eq!(
            view.signing_input().as_bytes(),
            input
                .as_bytes()
                .get(..view.signing_input().len())
                .ok_or(Error::InvalidFraming)?
        );
    }
    assert!(crate::jws::inspect_compact_jws(
        &JoseJwsInspectRequest::default().with_compact("Zh.Zh.Zh")
    )
    .is_err());
    assert!(crate::jws::inspect_compact_jws(
        &JoseJwsInspectRequest::default().with_compact("A.A.A")
    )
    .is_err());
    assert!(crate::jws::inspect_compact_jws(
        &JoseJwsInspectRequest::default().with_compact("Zg.Zg.Zg")
    )
    .is_ok());
    Ok(())
}
