// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use reallyme_codec::base64url::{base64url_to_bytes, bytes_to_base64url};
use zeroize::Zeroizing;

use crate::api::contract::{
    JoseCompactResult, JoseErrorReason as Reason, JoseExternalJwsAlgorithm,
    JoseInspectedCompactJws, JoseJwsInspectRequest, JoseJwsSignWithProviderRequest,
    JoseJwsVerifyWithProviderRequest, JoseVerifyResult,
};
use crate::generated_contract::ExternalJwsAlgorithm;
use crate::measure_encoding::base64url_len;
use crate::wire::{JoseWireError, JoseWireResult};

use super::{
    parse_compact::{
        build_sig_structure, parse_compact_jws, CompactJwsParts, MAX_COMPACT_JWS_BYTES,
    },
    parse_header::forbidden_protected_member,
};

/// Selects an exact JOSE signature registration for an external provider.
///
/// # Errors
/// Rejects registrations outside the asymmetric external-provider contract.
pub fn external_jws_algorithm(name: &str) -> JoseWireResult<JoseExternalJwsAlgorithm> {
    ExternalJwsAlgorithm::from_jose_name(name)
        .map(Into::into)
        .ok_or_else(|| primitive(Reason::JwsHeaderMismatch))
}

/// Signs attached compact JWS using the supplied protected-header bytes verbatim.
///
/// The provider is responsible for using the selected algorithm and returning
/// the JOSE wire signature bytes. No keys are selected from the header.
/// The request's provider handle is used only by the operation dispatcher.
///
/// # Errors
/// Rejects invalid headers, algorithm mismatches and compact size violations.
/// Propagates the injected signer's error.
pub fn sign_compact_jws_with_provider<E: From<JoseWireError>>(
    request: &JoseJwsSignWithProviderRequest,
    signer: impl FnOnce(JoseExternalJwsAlgorithm, &[u8]) -> Result<Zeroizing<Vec<u8>>, E>,
) -> Result<JoseCompactResult, E> {
    let limit = compact_limit(request.max_compact_bytes)?;
    let header = request.protected_header_json.as_slice();
    let payload = request.payload.as_slice();
    let encoded_prefix = base64url_len(header.len())
        .and_then(|len| len.checked_add(base64url_len(payload.len())?))
        .and_then(|len| len.checked_add(1))
        .ok_or_else(length_overflow)?;
    check_signed_length(encoded_prefix, 1, limit)?;
    if payload.is_empty() {
        return Err(invalid_compact().into());
    }
    let expected = ExternalJwsAlgorithm::try_from(request.algorithm)?;
    if validate_header(header, request.allow_embedded_jwk)? != expected {
        return Err(primitive(Reason::JwsHeaderMismatch).into());
    }

    let protected = Zeroizing::new(bytes_to_base64url(header));
    let attached = Zeroizing::new(bytes_to_base64url(payload));
    let signing_input = build_sig_structure(&protected, &attached, length_overflow())?;
    let signature = signer(expected.into(), &signing_input)?;
    if signature.is_empty() {
        return Err(primitive(Reason::JwsBadRawSignature).into());
    }
    let len = check_signed_length(signing_input.len(), signature.len(), limit)?;
    let signature = Zeroizing::new(bytes_to_base64url(&signature));
    let mut compact = Zeroizing::new(String::with_capacity(len));
    compact.push_str(&protected);
    compact.push('.');
    compact.push_str(&attached);
    compact.push('.');
    compact.push_str(&signature);
    Ok(JoseCompactResult::default().with_compact(core::mem::take(&mut *compact)))
}

/// Borrows the exact JWS signing input and encoded signature from compact framing.
///
/// # Errors
/// Rejects invalid compact framing or a compact token above the JOSE limit.
pub fn compact_jws_signing_parts(compact: &str) -> JoseWireResult<[&str; 2]> {
    let parts = parse_compact_jws(compact, invalid_compact())?;
    if parts.protected_header.is_empty() || parts.payload.is_empty() || parts.signature.is_empty() {
        return Err(invalid_compact());
    }
    let end = signing_input_end(&parts)?;
    let signing_input = compact.get(..end).ok_or_else(invalid_compact)?;
    Ok([signing_input, parts.signature])
}

/// Inspects an attached compact JWS without authenticating the data.
///
/// # Errors
/// Rejects malformed framing, empty segments, noncanonical base64url and
/// compact inputs exceeding the selected limit.
pub fn inspect_compact_jws(
    request: &JoseJwsInspectRequest,
) -> JoseWireResult<JoseInspectedCompactJws> {
    let compact = request.compact.as_str();
    if compact.len() > compact_limit(request.max_compact_bytes)? {
        return Err(limit_exceeded());
    }
    let parts = parse_compact_jws(compact, invalid_compact())?;
    let mut header = decode_segment(parts.protected_header, Reason::JwsBadHeaderBase64)?;
    let mut payload = decode_segment(parts.payload, Reason::JwsBadPayloadBase64)?;
    let mut signature = decode_segment(parts.signature, Reason::JwsBadSignatureBase64)?;
    Ok(JoseInspectedCompactJws::default()
        .with_protected_header_json(core::mem::take(&mut *header))
        .with_payload(core::mem::take(&mut *payload))
        .with_signature(core::mem::take(&mut *signature))
        .with_signing_input_len(
            u32::try_from(signing_input_end(&parts)?).map_err(|_| length_overflow())?,
        ))
}

/// Authenticates an attached compact JWS using an injected verifier.
///
/// The callback receives the protected algorithm and exact received signing
/// input. It must bind that algorithm and the verification key under its own
/// trust policy. The returned content is released only after it succeeds.
/// The request's provider handle is used only by the operation dispatcher.
///
/// # Errors
/// Rejects invalid compact inputs and unsupported protected-header semantics.
/// Propagates the injected verifier's error without producing a receipt.
pub fn verify_compact_jws_with_provider<E: From<JoseWireError>, T>(
    request: &JoseJwsVerifyWithProviderRequest,
    verifier: impl FnOnce(JoseExternalJwsAlgorithm, &[u8], &JoseInspectedCompactJws) -> Result<T, E>,
) -> Result<(JoseVerifyResult, T), E> {
    let input = request.input.as_option().ok_or_else(invalid_compact)?;
    let mut parsed = inspect_compact_jws(input)?;
    let algorithm = validate_header(&parsed.protected_header_json, request.allow_embedded_jwk)?;
    let signing_input_len =
        usize::try_from(parsed.signing_input_len).map_err(|_| length_overflow())?;
    let signing_input = input
        .compact
        .as_str()
        .as_bytes()
        .get(..signing_input_len)
        .ok_or_else(invalid_compact)?;
    let outcome = verifier(algorithm.into(), signing_input, &parsed)?;
    let authenticated = JoseVerifyResult::default()
        .with_protected_header_json(core::mem::take(&mut parsed.protected_header_json))
        .with_payload(core::mem::take(&mut parsed.payload));
    Ok((authenticated, outcome))
}

fn signing_input_end(parts: &CompactJwsParts<'_>) -> JoseWireResult<usize> {
    parts
        .protected_header
        .len()
        .checked_add(1)
        .and_then(|prefix| prefix.checked_add(parts.payload.len()))
        .ok_or_else(length_overflow)
}

fn validate_header(
    header: &[u8],
    allow_embedded_jwk: bool,
) -> JoseWireResult<ExternalJwsAlgorithm> {
    let mismatch = || primitive(Reason::JwsHeaderMismatch);
    crate::reject_duplicate_json_members::reject_duplicate_json_members(header)
        .map_err(|_| mismatch())?;
    let parsed = crate::jwt::strict_json::parse_sensitive_json(header).map_err(|_| mismatch())?;
    let fields = parsed.as_object().ok_or_else(mismatch)?;
    if fields
        .keys()
        .any(|name| forbidden_protected_member(name) && !(name == "jwk" && allow_embedded_jwk))
    {
        return Err(mismatch());
    }
    if let Some(jwk) = fields.get("jwk") {
        let jwk = jwk.as_object().ok_or_else(mismatch)?;
        if ["d", "k", "p", "q", "dp", "dq", "qi", "oth"]
            .iter()
            .any(|field| jwk.contains_key(*field))
        {
            return Err(mismatch());
        }
    }
    fields
        .get("alg")
        .and_then(serde_json::Value::as_str)
        .and_then(ExternalJwsAlgorithm::from_jose_name)
        .ok_or_else(mismatch)
}

fn decode_segment(encoded: &str, reason: Reason) -> JoseWireResult<Zeroizing<Vec<u8>>> {
    let bytes = Zeroizing::new(base64url_to_bytes(encoded).map_err(|_| primitive(reason))?);
    if bytes.is_empty() || Zeroizing::new(bytes_to_base64url(&bytes)).as_str() != encoded {
        return Err(primitive(reason));
    }
    Ok(bytes)
}

fn compact_limit(request_limit: Option<u32>) -> JoseWireResult<usize> {
    let limit = request_limit
        .map(usize::try_from)
        .transpose()
        .map_err(|_| limit_exceeded())?
        .unwrap_or(MAX_COMPACT_JWS_BYTES);
    if limit == 0 {
        return Err(limit_exceeded());
    }
    Ok(limit.min(MAX_COMPACT_JWS_BYTES))
}

fn check_signed_length(prefix: usize, signature: usize, limit: usize) -> JoseWireResult<usize> {
    let len = prefix
        .checked_add(1)
        .and_then(|len| len.checked_add(base64url_len(signature)?))
        .ok_or_else(length_overflow)?;
    if len > limit {
        return Err(limit_exceeded());
    }
    Ok(len)
}

const fn primitive(reason: Reason) -> JoseWireError {
    JoseWireError::primitive_internal(reason)
}

const fn invalid_compact() -> JoseWireError {
    primitive(Reason::CommonInvalidCompact)
}

const fn length_overflow() -> JoseWireError {
    primitive(Reason::CommonLengthOverflow)
}

const fn limit_exceeded() -> JoseWireError {
    primitive(Reason::CommonResourceLimitExceeded)
}
