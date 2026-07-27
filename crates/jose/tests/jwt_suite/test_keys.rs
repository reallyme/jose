#![allow(missing_docs, clippy::expect_used, clippy::unwrap_used)]
// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

use reallyme_crypto::core::Algorithm;
use reallyme_crypto::dispatch::generate_keypair;

#[test]
fn generate_ed25519_keypair() {
    let (public, private) = generate_keypair(Algorithm::Ed25519).unwrap();

    assert!(!public.is_empty());
    assert!(!private.is_empty());
}
