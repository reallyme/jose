// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

#[test]
fn unknown_binary_operation_tag_fails_closed_even_with_a_known_operation(
) -> Result<(), JoseWireError> {
    use buffa::types::put_len_delimited_header;

    // This future operation tag is absent from the executable oneof. Append
    // it to an otherwise valid request to check that it cannot be ignored.
    let mut unknown_selector = Vec::new();
    put_len_delimited_header(3999, 0, &mut unknown_selector);
    let known = operation(RequestOperation::JwtEncodeUnsigned(Box::new(
        JoseJwtEncodeUnsignedRequest {
            claims_json: b"{}".to_vec(),
            __buffa_unknown_fields: Default::default(),
        },
    )));
    let mut mixed = encode_protobuf(&known);
    mixed.extend_from_slice(&unknown_selector);

    let expected = JoseOperationKind::JwtEncodeUnsigned;
    let mut random = FixedRandom::new([0; 12]);
    let valid = execute_operation_v1(&encode_protobuf(&known), &mut random);
    assert!(matches!(
        decode_operation_response_v1(&valid, expected)?.response.as_ref(),
        Some(Response::JwtEncodeUnsigned(response))
            if matches!(&response.outcome, Some(JwtEncodeUnsignedOutcome::Result(_)))
    ));
    for request in [unknown_selector.as_slice(), mixed.as_slice()] {
        let response = execute_operation_v1(request, &mut random);
        assert_response_error(
            decode_operation_response_v1(&response, expected)?,
            None,
            JoseWireErrorBranch::Primitive,
            JoseErrorReason::JOSE_ERROR_REASON_COMMON_MALFORMED_PROTOBUF,
        );
    }
    Ok(())
}

#[test]
fn unknown_binary_response_selector_is_rejected() {
    use buffa::types::put_len_delimited_header;

    let expected = JoseOperationKind::JwsVerify;
    for response in [canonical(None), canonical(Some(valid_verify_response()))] {
        let mut encoded = encode_protobuf(&response);
        let mut unknown_selector = Vec::new();
        put_len_delimited_header(3999, 0, &mut unknown_selector);
        encoded.extend_from_slice(&unknown_selector);
        assert_backend_rejection(&encoded, expected);
    }
}
