// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

//! Fuzz native signed-JWT temporal validation with authenticated claims.

#![no_main]

use libfuzzer_sys::fuzz_target;
use reallyme_jose::jwt::{
    decode_verify_jwt_with_claims_validation, encode_signed_jwt, JwtClaimsValidationPolicy,
    JwtTemporalValidationPolicy,
};
use serde_json::{Map, Number, Value};

mod support;

const PRIVATE_KEY_LEN: usize = 32;
const U64_LEN: usize = 8;
const NOW_OFFSET: usize = 0;
const CLOCK_SKEW_OFFSET: usize = NOW_OFFSET + U64_LEN;
const FUTURE_IAT_SKEW_OFFSET: usize = CLOCK_SKEW_OFFSET + U64_LEN;
const FLAGS_OFFSET: usize = FUTURE_IAT_SKEW_OFFSET + U64_LEN;
const EXP_SELECTOR_OFFSET: usize = FLAGS_OFFSET + 1;
const NBF_SELECTOR_OFFSET: usize = EXP_SELECTOR_OFFSET + 1;
const IAT_SELECTOR_OFFSET: usize = NBF_SELECTOR_OFFSET + 1;
const EXP_VALUE_OFFSET: usize = IAT_SELECTOR_OFFSET + 1;
const NBF_VALUE_OFFSET: usize = EXP_VALUE_OFFSET + U64_LEN;
const IAT_VALUE_OFFSET: usize = NBF_VALUE_OFFSET + U64_LEN;
const INPUT_LEN: usize = IAT_VALUE_OFFSET + U64_LEN;
const EXPECTED_AUDIENCE: &str = "fuzz-audience";
// Scalar one is a public test fixture whose matching generator point is in
// `support`; keeping it fixed makes every fuzz iteration deterministic.
const P256_PRIVATE_KEY_ONE: [u8; PRIVATE_KEY_LEN] = [
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 1,
];

fuzz_target!(|data: &[u8]| {
    let Some(input) = TemporalInput::parse(data) else {
        return;
    };

    let claims = input.claims();
    let jwk = support::p256_jwk();
    let Ok(jwt) = encode_signed_jwt(&claims, &jwk, &P256_PRIVATE_KEY_ONE) else {
        return;
    };
    let policy = JwtClaimsValidationPolicy::new(
        input.temporal_policy(),
        EXPECTED_AUDIENCE,
        None,
        None,
    );
    let _: Result<Value, _> = decode_verify_jwt_with_claims_validation(
        &jwt,
        &jwk,
        support::P256_PUBLIC_KEY_SEC1,
        input.now_unix,
        policy,
    );
});

struct TemporalInput {
    now_unix: u64,
    clock_skew_seconds: u64,
    future_iat_skew_seconds: u64,
    flags: u8,
    exp: Option<Value>,
    nbf: Option<Value>,
    iat: Option<Value>,
}

impl TemporalInput {
    fn parse(data: &[u8]) -> Option<Self> {
        if data.len() < INPUT_LEN {
            return None;
        }
        Some(Self {
            now_unix: read_u64(data, NOW_OFFSET)?,
            clock_skew_seconds: read_u64(data, CLOCK_SKEW_OFFSET)?,
            future_iat_skew_seconds: read_u64(data, FUTURE_IAT_SKEW_OFFSET)?,
            flags: *data.get(FLAGS_OFFSET)?,
            exp: claim_value(*data.get(EXP_SELECTOR_OFFSET)?, read_u64(data, EXP_VALUE_OFFSET)?),
            nbf: claim_value(*data.get(NBF_SELECTOR_OFFSET)?, read_u64(data, NBF_VALUE_OFFSET)?),
            iat: claim_value(*data.get(IAT_SELECTOR_OFFSET)?, read_u64(data, IAT_VALUE_OFFSET)?),
        })
    }

    fn temporal_policy(&self) -> JwtTemporalValidationPolicy {
        JwtTemporalValidationPolicy::new(
            self.flags & 1 != 0,
            self.flags & 2 != 0,
            self.flags & 4 != 0,
            self.clock_skew_seconds,
            self.future_iat_skew_seconds,
        )
    }

    fn claims(&self) -> Value {
        let mut claims = Map::new();
        claims.insert("aud".to_owned(), Value::String(EXPECTED_AUDIENCE.to_owned()));
        insert_optional_claim(&mut claims, "exp", self.exp.clone());
        insert_optional_claim(&mut claims, "nbf", self.nbf.clone());
        insert_optional_claim(&mut claims, "iat", self.iat.clone());
        Value::Object(claims)
    }
}

fn read_u64(data: &[u8], offset: usize) -> Option<u64> {
    let end = offset.checked_add(U64_LEN)?;
    let bytes = <[u8; U64_LEN]>::try_from(data.get(offset..end)?).ok()?;
    Some(u64::from_le_bytes(bytes))
}

fn claim_value(selector: u8, value: u64) -> Option<Value> {
    match selector % 8 {
        0 => None,
        1 => Some(Value::Number(Number::from(value))),
        2 => Some(Value::Number(Number::from(0))),
        3 => Some(Value::String(value.to_string())),
        4 => Some(Value::Number(Number::from(-1))),
        5 => Some(Value::Bool(selector & 8 != 0)),
        6 => Some(Value::Null),
        _ => Number::from_f64(1.5).map(Value::Number),
    }
}

fn insert_optional_claim(claims: &mut Map<String, Value>, name: &str, value: Option<Value>) {
    if let Some(value) = value {
        claims.insert(name.to_owned(), value);
    }
}
