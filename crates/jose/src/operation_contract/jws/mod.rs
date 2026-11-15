// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! JWS operation contracts.

mod sign;
mod verify;

pub(crate) use sign::{sign_jws, JwsSignError, JwsSignErrorReason, JwsSignInput};
pub(crate) use verify::{verify_jws, JwsVerifyError, JwsVerifyErrorReason, JwsVerifyInput};

#[cfg(test)]
mod verify_tests;

pub(crate) use crate::jws::parse_header::JwsAlgorithm;
