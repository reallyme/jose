// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

#![allow(clippy::unwrap_used)]

use buffa::{DecodeOptions, Message};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use super::{compose_budgets, frame_budget, policy, Characters};
use crate::api::contract::{
    __buffa::oneof::{
        jose_jws_transport_compose_response::Outcome as ComposeOutcome,
        jose_jws_transport_frame_response::Outcome as FrameOutcome,
        jose_operation_request::Operation, jose_operation_response::Response,
    },
    JoseErrorReason as Reason, JoseJwsTransportComposeRequest, JoseJwsTransportFrameRequest,
    JoseJwsTransportPolicy, JoseOperationRequest,
};
use crate::jws::transport::{
    compose_compact_jws_unauthenticated, ComposeCompactJwsRequest,
    JwsTransportErrorReason as Error, UnauthenticatedCompactJws,
};

fn stack_reason(error: &crate::api::contract::JoseError) -> Reason {
    use crate::api::contract::__buffa::oneof::jose_error::Error;
    match error.error.as_ref().unwrap() {
        Error::Primitive(error) => error.reason.as_known().unwrap(),
        Error::Provider(error) => error.reason.as_known().unwrap(),
        Error::Backend(error) => error.reason.as_known().unwrap(),
    }
}

fn frame_request() -> JoseOperationRequest {
    JoseOperationRequest::default().with_operation(Operation::JwsFrameUnauthenticated(Box::new(
        JoseJwsTransportFrameRequest::default()
            .with_compact("hé.p.s")
            .with_policy(policy(Characters::OpaqueUtf8, false))
            .with_budgets(frame_budget(100)),
    )))
}

fn compose_request() -> JoseOperationRequest {
    JoseOperationRequest::default().with_operation(Operation::JwsComposeUnauthenticated(Box::new(
        JoseJwsTransportComposeRequest::default()
            .with_protected_header(" .hé\n")
            .with_payload("..负载\0 ")
            .with_signature(" . ")
            .with_policy(policy(Characters::OpaqueUtf8, false))
            .with_budgets(compose_budgets(100, 102)),
    )))
}

#[test]
#[allow(clippy::panic)]
fn canonical_envelopes_have_identical_binary_and_proto_json_execution() {
    for request in [frame_request(), compose_request()] {
        let wire = Zeroizing::new(request.encode_to_vec());
        let json = Zeroizing::new(serde_json::to_vec(&request).unwrap());
        let binary: JoseOperationRequest = DecodeOptions::new()
            .reject_unknown_fields()
            .decode_from_slice(&wire)
            .unwrap();
        let text: JoseOperationRequest = serde_json::from_slice(&json).unwrap();
        let binary_response = crate::api::execute(binary);
        let json_response = crate::api::execute(text);
        assert_eq!(binary_response, json_response);
        match binary_response.response.as_ref().unwrap() {
            Response::JwsFrameUnauthenticated(response) => match response.outcome.as_ref().unwrap()
            {
                FrameOutcome::Result(result) => {
                    assert_eq!(result.protected_header_end, 3);
                    assert_eq!(result.payload_end, 5);
                    assert_eq!(result.signature_start, 6);
                }
                FrameOutcome::Error(_) => panic!("unexpected frame failure"),
            },
            Response::JwsComposeUnauthenticated(response) => {
                match response.outcome.as_ref().unwrap() {
                    ComposeOutcome::Result(result) => {
                        assert_eq!(result.compact.as_str(), " .hé\n...负载\0 . . ")
                    }
                    ComposeOutcome::Error(_) => panic!("unexpected compose failure"),
                }
            }
            _ => panic!("unexpected response operation"),
        }
    }
}

#[test]
fn generated_requests_and_owned_outputs_are_guarded_and_redacted() {
    fn guarded<T: ZeroizeOnDrop>() {}
    guarded::<UnauthenticatedCompactJws>();
    guarded::<JoseJwsTransportComposeRequest>();
    guarded::<JoseOperationRequest>();
    let request = compose_request();
    assert!(!format!("{request:?}").contains("hé"));
    let mut response = crate::api::execute(request);
    assert!(!format!("{response:?}").contains("hé"));
    response.zeroize();
    assert!(response.response.is_none());
    let selected = policy(Characters::OpaqueUtf8, false);
    let budgets = compose_budgets(100, 102);
    let mut compact = compose_compact_jws_unauthenticated(&ComposeCompactJwsRequest {
        protected_header: "h",
        payload: "private-text",
        signature: "s",
        policy: &selected,
        budgets: &budgets,
    })
    .unwrap();
    compact.zeroize();
    assert!(compact.as_str().is_empty());
}

#[test]
fn absent_operation_policy_budget_or_member_never_implies_success() {
    let response = crate::api::execute(JoseOperationRequest::default());
    assert!(
        matches!(response.response.as_ref(), Some(Response::BoundaryError(e)) if stack_reason(e) == Reason::CommonMissingOperation)
    );
    for (request, expected) in [
        (
            JoseJwsTransportComposeRequest::default(),
            Reason::JwsTransportMissingMember,
        ),
        (
            JoseJwsTransportComposeRequest::default()
                .with_protected_header("")
                .with_payload("")
                .with_signature(""),
            Reason::JwsTransportMissingPolicy,
        ),
        (
            JoseJwsTransportComposeRequest::default()
                .with_protected_header("")
                .with_payload("")
                .with_signature("")
                .with_policy(policy(Characters::Ascii, true)),
            Reason::JwsTransportMissingBudget,
        ),
    ] {
        let request = JoseOperationRequest::default()
            .with_operation(Operation::JwsComposeUnauthenticated(Box::new(request)));
        let response = crate::api::execute(request);
        assert!(
            matches!(response.response.as_ref(), Some(Response::JwsComposeUnauthenticated(r)) if matches!(r.outcome.as_ref(), Some(ComposeOutcome::Error(e)) if stack_reason(e) == expected))
        );
    }
    let request = JoseOperationRequest::default()
        .with_operation(Operation::JwsFrameUnauthenticated(Box::default()));
    let response = crate::api::execute(request);
    assert!(
        matches!(response.response.as_ref(), Some(Response::JwsFrameUnauthenticated(r)) if matches!(r.outcome.as_ref(), Some(FrameOutcome::Error(e)) if stack_reason(e) == Reason::JwsTransportMissingPolicy))
    );
}

#[test]
fn policies_can_differ_by_member_and_missing_member_policies_fail_closed() {
    let mut selected = policy(Characters::AsciiWithoutWhitespace, false);
    selected.protected_header.get_or_insert_default().characters = Characters::OpaqueUtf8.into();
    selected.payload.get_or_insert_default().characters = Characters::Base64urlAlphabet.into();
    let budgets = compose_budgets(100, 102);
    let request = ComposeCompactJwsRequest {
        protected_header: "hé",
        payload: "Zh",
        signature: "\u{b}",
        policy: &selected,
        budgets: &budgets,
    };
    assert_eq!(
        compose_compact_jws_unauthenticated(&request)
            .unwrap()
            .as_str(),
        "hé.Zh.\u{b}"
    );
    for missing in [0, 1, 2] {
        let mut selected = selected.clone();
        match missing {
            0 => selected.protected_header = Default::default(),
            1 => selected.payload = Default::default(),
            _ => selected.signature = Default::default(),
        }
        assert_eq!(
            compose_compact_jws_unauthenticated(&ComposeCompactJwsRequest {
                policy: &selected,
                ..request
            })
            .err(),
            Some(Error::MissingPolicy)
        );
    }
    assert_eq!(
        compose_compact_jws_unauthenticated(&ComposeCompactJwsRequest {
            policy: &JoseJwsTransportPolicy::default(),
            ..request
        })
        .err(),
        Some(Error::MissingPolicy)
    );
}

#[test]
fn json_member_presence_and_unknown_fields_remain_strict() {
    let request: JoseJwsTransportComposeRequest =
        serde_json::from_str(r#"{"protectedHeader":"","payload":""}"#).unwrap();
    assert!(request.protected_header.is_some());
    assert!(request.payload.is_some());
    assert!(request.signature.is_none());
    assert!(serde_json::from_str::<JoseJwsTransportComposeRequest>(
        r#"{"protectedHeader":"h","extra":"ignored"}"#
    )
    .is_err());
    assert!(
        serde_json::from_str::<JoseJwsTransportComposeRequest>(r#"{"protectedHeader":12}"#)
            .is_err()
    );
}

#[test]
fn typed_execution_obeys_transport_budgets_above_the_legacy_wire_limit() {
    const INPUT_BYTES: usize = 3_145_726;
    let request = JoseOperationRequest::default().with_operation(
        Operation::JwsComposeUnauthenticated(Box::new(
            JoseJwsTransportComposeRequest::default()
                .with_protected_header("h")
                .with_payload("p".repeat(INPUT_BYTES.checked_sub(2).unwrap()))
                .with_signature("s")
                .with_policy(policy(Characters::Ascii, false))
                .with_budgets(compose_budgets(3_145_726, 3_145_728)),
        )),
    );
    let encoded = Zeroizing::new(request.encode_to_vec());
    assert!(crate::wire::decode_protobuf::<JoseOperationRequest>(&encoded).is_err());
    let response = crate::api::execute(request);
    assert!(
        matches!(response.response.as_ref(), Some(Response::JwsComposeUnauthenticated(value)) if matches!(value.outcome.as_ref(), Some(ComposeOutcome::Result(result)) if result.compact.len() == 3_145_728))
    );
}

#[test]
fn response_decoder_rejects_inconsistent_local_stack_reasons_and_offsets() {
    use crate::api::contract::JoseJwsTransportErrorReason as Local;
    use crate::wire::{decode_operation_response_v1, JoseOperationKind};
    let mut invalid = frame_request();
    if let Some(Operation::JwsFrameUnauthenticated(request)) = invalid.operation.as_mut() {
        request.compact = "missing-separators".into();
    }
    let correct = crate::api::execute(invalid);
    assert!(decode_operation_response_v1(
        &correct.encode_to_vec(),
        JoseOperationKind::JwsFrameUnauthenticated
    )
    .is_ok());
    for local in [
        Local::EmptyMember.into(),
        Local::Unspecified.into(),
        buffa::EnumValue::from(i32::MAX),
    ] {
        let mut response = correct.clone();
        if let Some(Response::JwsFrameUnauthenticated(value)) = response.response.as_mut() {
            value.transport_reason = local;
        }
        assert!(decode_operation_response_v1(
            &response.encode_to_vec(),
            JoseOperationKind::JwsFrameUnauthenticated
        )
        .is_err());
    }
    let mut response = crate::api::execute(frame_request());
    if let Some(Response::JwsFrameUnauthenticated(value)) = response.response.as_mut() {
        if let Some(FrameOutcome::Result(result)) = value.outcome.as_mut() {
            result.signature_start = u64::MAX;
        }
    }
    assert!(decode_operation_response_v1(
        &response.encode_to_vec(),
        JoseOperationKind::JwsFrameUnauthenticated
    )
    .is_err());
    let mut response = crate::api::execute(compose_request());
    if let Some(Response::JwsComposeUnauthenticated(value)) = response.response.as_mut() {
        value.transport_reason = Local::InvalidFraming.into();
    }
    assert!(decode_operation_response_v1(
        &response.encode_to_vec(),
        JoseOperationKind::JwsComposeUnauthenticated
    )
    .is_err());
}
