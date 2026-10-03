// SPDX-FileCopyrightText: 2026 ReallyMe LLC
//
// SPDX-License-Identifier: MIT OR Apache-2.0

/// Compare JOSE `typ` and `cty` media types while applying the optional
/// `application/` shorthand. A subtype containing `/` cannot be shorthand.
pub(crate) fn match_media_type(actual: &str, expected: &str) -> bool {
    let (actual_type, actual_params) = split_parameters(actual);
    let (expected_type, expected_params) = split_parameters(expected);
    let actual_type = strip_application_prefix(actual_type);
    let expected_type = strip_application_prefix(expected_type);
    if !actual_type.eq_ignore_ascii_case(expected_type) {
        return false;
    }

    let mut actual_params = actual_params.split(';');
    let mut expected_params = expected_params.split(';');
    loop {
        match (actual_params.next(), expected_params.next()) {
            (None, None) => return true,
            (Some(actual), Some(expected)) if match_parameter(actual, expected) => {}
            _ => return false,
        }
    }
}

fn split_parameters(value: &str) -> (&str, &str) {
    value.split_once(';').unwrap_or((value, ""))
}

fn strip_application_prefix(value: &str) -> &str {
    if let Some((prefix, subtype)) = value.split_once('/') {
        if prefix.eq_ignore_ascii_case("application") && !subtype.contains('/') {
            return subtype;
        }
    }
    value
}

fn match_parameter(actual: &str, expected: &str) -> bool {
    match (
        actual.trim().split_once('='),
        expected.trim().split_once('='),
    ) {
        (Some((actual_name, actual_value)), Some((expected_name, expected_value))) => {
            actual_name
                .trim()
                .eq_ignore_ascii_case(expected_name.trim())
                && actual_value.trim() == expected_value.trim()
        }
        (None, None) => actual.trim().eq_ignore_ascii_case(expected.trim()),
        _ => false,
    }
}
