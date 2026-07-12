#![allow(missing_docs, clippy::expect_used, clippy::unwrap_used)]
// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

use reallyme_jose::jwt::{NumericDate, StringOrURI};

#[test]
fn numeric_date_serializes() {
    let nd = NumericDate::new(1_700_000_000);
    let v = serde_json::to_value(nd).unwrap();
    assert!(v.is_number());
}

#[test]
fn string_or_uri_roundtrip() {
    let s = StringOrURI("did:me:test".into());
    let j = serde_json::to_string(&s).unwrap();
    let back: StringOrURI = serde_json::from_str(&j).unwrap();
    assert_eq!(s, back);
}
