// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

//! Hardened generated-boundary JWK JSON conversion for JWT operations.

use reallyme_crypto::jwk::{AkpJwk, EcJwk, OkpJwk};
use reallyme_jose_proto::generated::proto::reallyme::jose::v1::JoseErrorReason;
use serde_json::Value as JsonValue;
use zeroize::Zeroize;

use crate::jwt::reject_duplicate_object_members;
use crate::wire::{JoseWireError, JoseWireResult};
use crate::Jwk;

#[derive(Clone, Copy)]
pub(super) enum JwkOperation {
    Sign,
    Verify,
}

pub(super) struct SensitiveJwk(Jwk);

impl core::ops::Deref for SensitiveJwk {
    type Target = Jwk;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl Drop for SensitiveJwk {
    fn drop(&mut self) {
        zeroize_jwk(&mut self.0);
    }
}

pub(super) fn jwk_from_json(bytes: &[u8], operation: JwkOperation) -> JoseWireResult<SensitiveJwk> {
    reject_duplicate_object_members(bytes).map_err(|_| invalid_jwk_error())?;
    let value: JsonValue = serde_json::from_slice(bytes).map_err(|_| invalid_jwk_error())?;
    let mut value = WipeJsonValue::new(value);
    validate_jwk_operation(value.as_ref(), operation)?;
    jwk_from_json_value(&mut value)
}

struct WipeJsonValue(JsonValue);

impl WipeJsonValue {
    const fn new(value: JsonValue) -> Self {
        Self(value)
    }

    const fn as_ref(&self) -> &JsonValue {
        &self.0
    }

    fn as_object_mut(&mut self) -> JoseWireResult<&mut serde_json::Map<String, JsonValue>> {
        self.0.as_object_mut().ok_or(invalid_jwk_error())
    }
}

impl Drop for WipeJsonValue {
    fn drop(&mut self) {
        zeroize_json_value(self.0.take());
    }
}

struct WipeString(String);

impl WipeString {
    fn as_str(&self) -> &str {
        &self.0
    }

    fn into_string(mut self) -> String {
        core::mem::take(&mut self.0)
    }
}

impl Drop for WipeString {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

const PRIVATE_JWK_MEMBER_NAMES: &[&str] = &[
    "d",
    "p",
    "q",
    "dp",
    "dq",
    "qi",
    "oth",
    "k",
    "priv",
    "privateKey",
    "secretKey",
];

fn jwk_from_json_value(value: &mut WipeJsonValue) -> JoseWireResult<SensitiveJwk> {
    let object = value.as_object_mut()?;
    if PRIVATE_JWK_MEMBER_NAMES
        .iter()
        .any(|member| object.contains_key(*member))
    {
        return Err(invalid_jwk_error());
    }

    let kty = take_required_jwk_string(object, "kty")?;
    match kty.as_str() {
        "EC" => ec_jwk_from_object(kty, object),
        "OKP" => okp_jwk_from_object(kty, object),
        "AKP" => akp_jwk_from_object(kty, object),
        _ => Err(invalid_jwk_error()),
    }
}

fn ec_jwk_from_object(
    kty: WipeString,
    object: &mut serde_json::Map<String, JsonValue>,
) -> JoseWireResult<SensitiveJwk> {
    let crv = take_required_jwk_string(object, "crv")?;
    let x = take_required_jwk_string(object, "x")?;
    let y = take_required_jwk_string(object, "y")?;
    let alg = take_optional_jwk_string(object, "alg")?;
    let use_ = take_optional_jwk_string(object, "use")?;
    let kid = take_optional_jwk_string(object, "kid")?;
    Ok(SensitiveJwk(Jwk::Ec(EcJwk {
        kty: kty.into_string(),
        crv: crv.into_string(),
        x: x.into_string(),
        y: y.into_string(),
        alg: alg.map(WipeString::into_string),
        use_: use_.map(WipeString::into_string),
        kid: kid.map(WipeString::into_string),
    })))
}

fn okp_jwk_from_object(
    kty: WipeString,
    object: &mut serde_json::Map<String, JsonValue>,
) -> JoseWireResult<SensitiveJwk> {
    let crv = take_required_jwk_string(object, "crv")?;
    let x = take_required_jwk_string(object, "x")?;
    let alg = take_optional_jwk_string(object, "alg")?;
    let use_ = take_optional_jwk_string(object, "use")?;
    let kid = take_optional_jwk_string(object, "kid")?;
    Ok(SensitiveJwk(Jwk::Okp(OkpJwk {
        kty: kty.into_string(),
        crv: crv.into_string(),
        x: x.into_string(),
        alg: alg.map(WipeString::into_string),
        use_: use_.map(WipeString::into_string),
        kid: kid.map(WipeString::into_string),
    })))
}

fn akp_jwk_from_object(
    kty: WipeString,
    object: &mut serde_json::Map<String, JsonValue>,
) -> JoseWireResult<SensitiveJwk> {
    let alg = take_required_jwk_string(object, "alg")?;
    let public_key = take_required_jwk_string(object, "pub")?;
    let use_ = take_optional_jwk_string(object, "use")?;
    let kid = take_optional_jwk_string(object, "kid")?;
    Ok(SensitiveJwk(Jwk::Akp(AkpJwk {
        kty: kty.into_string(),
        alg: alg.into_string(),
        public_key: public_key.into_string(),
        use_: use_.map(WipeString::into_string),
        kid: kid.map(WipeString::into_string),
    })))
}

fn take_required_jwk_string(
    object: &mut serde_json::Map<String, JsonValue>,
    member: &str,
) -> JoseWireResult<WipeString> {
    let Some(value) = object.remove(member) else {
        return Err(invalid_jwk_error());
    };
    json_value_into_string(value)
}

fn take_optional_jwk_string(
    object: &mut serde_json::Map<String, JsonValue>,
    member: &str,
) -> JoseWireResult<Option<WipeString>> {
    let Some(value) = object.remove(member) else {
        return Ok(None);
    };
    json_value_into_string(value).map(Some)
}

fn json_value_into_string(value: JsonValue) -> JoseWireResult<WipeString> {
    match value {
        JsonValue::String(value) => Ok(WipeString(value)),
        other => {
            zeroize_json_value(other);
            Err(invalid_jwk_error())
        }
    }
}

const fn invalid_jwk_error() -> JoseWireError {
    JoseWireError::primitive_internal(JoseErrorReason::JOSE_ERROR_REASON_JWT_INVALID_JWK)
}

fn validate_jwk_operation(value: &JsonValue, operation: JwkOperation) -> JoseWireResult<()> {
    let object = value.as_object().ok_or(invalid_jwk_error())?;
    if object
        .get("use")
        .is_some_and(|value| value.as_str() != Some("sig"))
    {
        return Err(JoseWireError::primitive_internal(
            JoseErrorReason::JOSE_ERROR_REASON_JWT_ALGORITHM_MISMATCH,
        ));
    }
    let Some(key_ops) = object.get("key_ops") else {
        return Ok(());
    };
    let key_ops = key_ops.as_array().ok_or(invalid_jwk_error())?;
    let required = match operation {
        JwkOperation::Sign => "sign",
        JwkOperation::Verify => "verify",
    };
    if !key_ops.iter().any(|value| value.as_str() == Some(required))
        || key_ops.iter().any(|value| {
            !matches!(
                value.as_str(),
                Some(
                    "sign"
                        | "verify"
                        | "encrypt"
                        | "decrypt"
                        | "wrapKey"
                        | "unwrapKey"
                        | "deriveKey"
                        | "deriveBits"
                )
            )
        })
    {
        return Err(JoseWireError::primitive_internal(
            JoseErrorReason::JOSE_ERROR_REASON_JWT_ALGORITHM_MISMATCH,
        ));
    }
    Ok(())
}

fn zeroize_jwk(jwk: &mut Jwk) {
    match jwk {
        Jwk::Ec(value) => {
            value.kty.zeroize();
            value.crv.zeroize();
            value.x.zeroize();
            value.y.zeroize();
            value.alg.zeroize();
            value.use_.zeroize();
            value.kid.zeroize();
        }
        Jwk::Okp(value) => {
            value.kty.zeroize();
            value.crv.zeroize();
            value.x.zeroize();
            value.alg.zeroize();
            value.use_.zeroize();
            value.kid.zeroize();
        }
        Jwk::Akp(value) => {
            value.kty.zeroize();
            value.alg.zeroize();
            value.public_key.zeroize();
            value.use_.zeroize();
            value.kid.zeroize();
        }
    }
}

fn zeroize_json_value(value: JsonValue) {
    match value {
        JsonValue::String(mut value) => value.zeroize(),
        JsonValue::Array(values) => values.into_iter().for_each(zeroize_json_value),
        JsonValue::Object(values) => values.into_iter().for_each(|(mut key, value)| {
            key.zeroize();
            zeroize_json_value(value);
        }),
        JsonValue::Null | JsonValue::Bool(_) | JsonValue::Number(_) => {}
    }
}
