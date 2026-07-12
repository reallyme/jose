#![allow(missing_docs, clippy::expect_used, clippy::unwrap_used)]
// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

#[path = "jwt_suite/support.rs"]
mod support;

#[path = "jwt_suite/claims_tests.rs"]
mod claims_tests;
#[path = "jwt_suite/datatype_tests.rs"]
mod datatype_tests;
#[path = "jwt_suite/signed_eddsa_tests.rs"]
mod signed_eddsa_tests;
#[path = "jwt_suite/signed_es256_tests.rs"]
mod signed_es256_tests;
#[path = "jwt_suite/signed_es256k_tests.rs"]
mod signed_es256k_tests;
#[path = "jwt_suite/signed_header_policy_tests.rs"]
mod signed_header_policy_tests;
#[path = "jwt_suite/signed_reject_tests.rs"]
mod signed_reject_tests;
#[path = "jwt_suite/temporal_validation_tests.rs"]
mod temporal_validation_tests;
#[path = "jwt_suite/test_keys.rs"]
mod test_keys;
#[path = "jwt_suite/unsigned_reject_tests.rs"]
mod unsigned_reject_tests;
#[path = "jwt_suite/unsigned_tests.rs"]
mod unsigned_tests;
