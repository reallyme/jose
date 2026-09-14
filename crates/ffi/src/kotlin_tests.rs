// SPDX-FileCopyrightText: 2026 ReallyMe LLC
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use super::JOSE_ABI_VERSION;
use crate::operation::rm_jose_abi_version;

#[test]
fn jni_and_c_abi_versions_are_identical() {
    assert_eq!(rm_jose_abi_version(), JOSE_ABI_VERSION);
}
