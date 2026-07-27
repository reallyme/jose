// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

//! JWS operation contracts.

mod sign;
mod verify;

pub(crate) use sign::{sign_jws, JwsSignAlgorithm, JwsSignError, JwsSignErrorReason, JwsSignInput};
pub(crate) use verify::{
    verify_jws, JwsVerifyAlgorithm, JwsVerifyError, JwsVerifyErrorReason, JwsVerifyInput,
};

#[cfg(test)]
mod verify_tests;
