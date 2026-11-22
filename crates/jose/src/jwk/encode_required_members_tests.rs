// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use super::CountBytes;
use std::io::{ErrorKind, Write};

#[test]
fn counting_writer_rejects_overflow_without_changing_its_count() {
    let mut counter = CountBytes(usize::MAX);
    assert!(counter
        .write(&[0])
        .is_err_and(|error| error.kind() == ErrorKind::FileTooLarge));
    assert_eq!(counter.0, usize::MAX);
}
