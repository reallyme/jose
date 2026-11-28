// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use super::{compose_budgets, frame_budget, policy, Characters};
use crate::jws::transport::{
    compose_compact_jws_unauthenticated as compose, frame_compact_jws_unauthenticated as frame,
    ComposeCompactJwsRequest, FrameCompactJwsRequest, JwsTransportErrorReason as Error,
};

#[test]
fn slices_and_signing_input_borrow_original_utf8_bytes() -> Result<(), Error> {
    let input = String::from("héader.负载.sig\0nature");
    let selected = policy(Characters::OpaqueUtf8, false);
    let budget = frame_budget(100);
    let view = frame(&FrameCompactJwsRequest {
        compact: &input,
        policy: &selected,
        budgets: &budget,
    })?;
    assert_eq!(view.protected_header(), "héader");
    assert_eq!(view.payload(), "负载");
    assert_eq!(view.signature(), "sig\0nature");
    assert_eq!(view.signing_input(), "héader.负载");
    assert_eq!(view.protected_header().as_ptr(), input.as_ptr());
    assert_eq!(view.signing_input().as_ptr(), input.as_ptr());
    assert_eq!(input.find(view.payload()), Some("héader.".len()));
    assert_eq!(input.find(view.signature()), Some("héader.负载.".len()));
    assert_eq!(
        view.payload().as_ptr(),
        input
            .as_bytes()
            .get("héader.".len()..)
            .ok_or(Error::InvalidFraming)?
            .as_ptr()
    );
    assert_eq!(
        view.signature().as_ptr(),
        input
            .as_bytes()
            .get("héader.负载.".len()..)
            .ok_or(Error::InvalidFraming)?
            .as_ptr()
    );
    assert_eq!(
        format!("{view:?}"),
        "UnauthenticatedCompactJwsView([REDACTED])"
    );
    Ok(())
}

#[test]
fn borrowed_input_can_outlive_temporary_policy_and_budget_values() -> Result<(), Error> {
    let compact = String::from("h.p.s");
    let view = {
        let selected = policy(Characters::Ascii, false);
        let budgets = frame_budget(5);
        frame(&FrameCompactJwsRequest {
            compact: &compact,
            policy: &selected,
            budgets: &budgets,
        })?
    };
    assert_eq!(view.signing_input(), "h.p");
    Ok(())
}

#[test]
fn every_empty_segment_combination_has_independent_admission() {
    for header_empty in [false, true] {
        for payload_empty in [false, true] {
            for signature_empty in [false, true] {
                let input = format!(
                    "{}.{}.{}",
                    if header_empty { "" } else { "h" },
                    if payload_empty { "" } else { "p" },
                    if signature_empty { "" } else { "s" }
                );
                for allow_header in [false, true] {
                    for allow_payload in [false, true] {
                        for allow_signature in [false, true] {
                            let mut selected = policy(Characters::Ascii, false);
                            selected
                                .protected_header
                                .get_or_insert_default()
                                .allow_empty = allow_header;
                            selected.payload.get_or_insert_default().allow_empty = allow_payload;
                            selected.signature.get_or_insert_default().allow_empty =
                                allow_signature;
                            let result = frame(&FrameCompactJwsRequest {
                                compact: &input,
                                policy: &selected,
                                budgets: &frame_budget(100),
                            });
                            let admitted = (!header_empty || allow_header)
                                && (!payload_empty || allow_payload)
                                && (!signature_empty || allow_signature);
                            assert_eq!(result.is_ok(), admitted);
                            if !admitted {
                                assert_eq!(result.err(), Some(Error::EmptyMember));
                            }
                        }
                    }
                }
            }
        }
    }
}

#[test]
fn framing_always_requires_exactly_two_separators() {
    let selected = policy(Characters::OpaqueUtf8, true);
    let budget = frame_budget(100);
    for input in ["", "a", ".", "a.b", "a.b.c.d", "...", ".a.b.c", "a..b."] {
        assert_eq!(
            frame(&FrameCompactJwsRequest {
                compact: input,
                policy: &selected,
                budgets: &budget
            })
            .err(),
            Some(Error::InvalidFraming)
        );
    }
    for input in ["..", ".p.s", "h..s", "h.p."] {
        assert!(frame(&FrameCompactJwsRequest {
            compact: input,
            policy: &selected,
            budgets: &budget
        })
        .is_ok());
    }
}

#[test]
fn character_admission_is_independent_of_decoding_and_framing() {
    let cases = [
        ("Az09-_", [true, true, true, true]),
        ("A", [true, true, true, true]),
        ("Zh", [true, true, true, true]),
        ("é", [true, false, false, false]),
        ("负载", [true, false, false, false]),
        ("\u{a0}", [true, false, false, false]),
        ("\0", [true, true, true, false]),
        ("\u{7f}", [true, true, true, false]),
        ("\u{b}", [true, true, true, false]),
        (" ", [true, true, false, false]),
        ("\t", [true, true, false, false]),
        ("\n", [true, true, false, false]),
        ("\r", [true, true, false, false]),
        ("\u{c}", [true, true, false, false]),
        ("=", [true, true, true, false]),
        ("/", [true, true, true, false]),
        ("+", [true, true, true, false]),
        (".", [true, true, true, false]),
    ];
    let selectors = [
        Characters::OpaqueUtf8,
        Characters::Ascii,
        Characters::AsciiWithoutWhitespace,
        Characters::Base64urlAlphabet,
    ];
    for (text, expected) in cases {
        for (characters, admitted) in selectors.iter().zip(expected) {
            let selected = policy(*characters, false);
            for position in [0, 1, 2] {
                let header = if position == 0 { text } else { "h" };
                let payload = if position == 1 { text } else { "p" };
                let signature = if position == 2 { text } else { "s" };
                let result = compose(&ComposeCompactJwsRequest {
                    protected_header: header,
                    payload,
                    signature,
                    policy: &selected,
                    budgets: &compose_budgets(100, 102),
                });
                assert_eq!(
                    result.is_ok(),
                    admitted,
                    "selector {characters:?}, position {position}"
                );
                if !admitted {
                    assert_eq!(result.err(), Some(Error::InvalidCharacters));
                }
            }
        }
    }
}

#[test]
fn opaque_forwarding_preserves_embedded_dots_whitespace_and_unicode() -> Result<(), Error> {
    let selected = policy(Characters::OpaqueUtf8, false);
    let result = compose(&ComposeCompactJwsRequest {
        protected_header: " .hé\n",
        payload: "..负载\0 ",
        signature: " . ",
        policy: &selected,
        budgets: &compose_budgets(100, 102),
    })?;
    assert_eq!(result.as_str(), " .hé\n...负载\0 . . ");
    assert_eq!(
        format!("{result:?}"),
        "UnauthenticatedCompactJws([REDACTED])"
    );
    assert_eq!(
        frame(&FrameCompactJwsRequest {
            compact: result.as_str(),
            policy: &selected,
            budgets: &frame_budget(102)
        })
        .err(),
        Some(Error::InvalidFraming)
    );
    assert_eq!(result.into_zeroizing().as_str(), " .hé\n...负载\0 . . ");
    Ok(())
}

#[test]
fn unspecified_and_unknown_selectors_fail_even_for_empty_values() {
    for value in [0, -1, i32::MIN, i32::MAX] {
        let mut selected = policy(Characters::Ascii, true);
        selected.protected_header.get_or_insert_default().characters =
            buffa::EnumValue::from(value);
        assert_eq!(
            frame(&FrameCompactJwsRequest {
                compact: "..",
                policy: &selected,
                budgets: &frame_budget(2)
            })
            .err(),
            Some(Error::InvalidCharacterPolicy)
        );
    }
}
