// SPDX-FileCopyrightText: 2026 ReallyMe LLC
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use super::match_media_type::match_media_type;

#[test]
fn applies_media_type_rules_without_collapsing_subtypes_or_parameter_values() {
    assert!(match_media_type("application/jwt", "JWT"));
    assert!(match_media_type("APPLICATION/JWT", "jwt"));
    assert!(match_media_type(
        "Application/JOSE;CHARSET=UTF-8",
        "jose;charset=UTF-8"
    ));
    assert!(!match_media_type("application/foo/bar", "foo/bar"));
    assert!(!match_media_type(
        "jose;charset=utf-8",
        "jose;charset=UTF-8"
    ));
    assert!(!match_media_type("text/jwt", "jwt"));
}
