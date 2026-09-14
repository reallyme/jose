// SPDX-FileCopyrightText: 2026 ReallyMe LLC
//
// SPDX-License-Identifier: MIT OR Apache-2.0

fn audit_jws_case(case: &JwsCase) -> AuditResult<()> {
    let compact = match parse_jws(&case.compact) {
        Ok(compact) => compact,
        Err(error) => {
            if case.expected_error.as_deref() == Some("InvalidCompactEncoding") {
                return Ok(());
            }
            return Err(error);
        }
    };
    let public_key = decode_hex(&case.public_key_hex)?;
    let protected = decode_json_segment(&compact.protected)?;
    let signing_input = jws_signing_input(&compact.protected, &compact.payload);
    let signature = match decode_base64url(&compact.signature) {
        Ok(signature) => signature,
        Err(error) => {
            if case.expected_error.as_deref() == Some("BadSignatureBase64") {
                return Ok(());
            }
            return Err(error);
        }
    };
    let payload = decode_base64url(&compact.payload)?;
    let signature_ok = verify_signature(
        SignatureAlgorithm::parse(&case.alg)?,
        &public_key,
        signing_input.as_bytes(),
        &signature,
    )?;

    match (case.expected_valid, case.expected_error.as_deref()) {
        (Some(true), None) => {
            audit_alg_header(&protected, &case.alg)?;
            ensure(signature_ok, AuditReason::SignatureDidNotVerify)?;
            if let Some(expected_payload) = &case.payload_utf8 {
                ensure(
                    payload == expected_payload.as_bytes(),
                    AuditReason::ClaimsMismatch,
                )?;
            }
            ensure(
                signature.len() == SignatureAlgorithm::parse(&case.alg)?.signature_len(),
                AuditReason::SignatureLength,
            )
        }
        (_, Some(expected_error)) => {
            if expected_error != "HeaderMismatch" {
                audit_alg_header(&protected, &case.alg)?;
            }
            audit_jws_negative(
                expected_error,
                &protected,
                has_duplicate_member(&compact.protected, "alg")?,
                Some(case.alg.as_str()),
                signature_ok,
            )
        }
        _ => Err(general(AuditReason::MissingField)),
    }
}
fn audit_signed_jwt_case(case: &SignedJwtCase) -> AuditResult<()> {
    let compact = match parse_jws(&case.compact) {
        Ok(compact) => compact,
        Err(error) => {
            if case.expected_error.as_deref() == Some("InvalidJwtFormat") {
                return Ok(());
            }
            return Err(error);
        }
    };
    let protected = decode_json_segment(&compact.protected)?;
    audit_jwk_binding(case, &protected)?;
    if case.expected_error.as_deref() == Some("AlgorithmMismatch") {
        return Ok(());
    }

    let signature = decode_base64url(&compact.signature)?;
    let public_key = decode_hex(&case.public_key_hex)?;
    let signing_input = jws_signing_input(&compact.protected, &compact.payload);
    let signature_ok = verify_signature(
        SignatureAlgorithm::parse(&case.alg)?,
        &public_key,
        signing_input.as_bytes(),
        &signature,
    )?;

    match (
        case.expected_claims_json.as_ref(),
        case.expected_error.as_deref(),
    ) {
        (Some(expected_claims), None) => {
            let payload = decode_json_segment(&compact.payload)?;
            ensure(signature_ok, AuditReason::SignatureDidNotVerify)?;
            ensure(&payload == expected_claims, AuditReason::ClaimsMismatch)
        }
        (None, Some(expected_error)) => audit_signed_jwt_negative(
            expected_error,
            &protected,
            has_duplicate_member(&compact.protected, "alg")?,
            Some(case.alg.as_str()),
            signature_ok,
        ),
        _ => Err(general(AuditReason::MissingField)),
    }
}

fn audit_unsigned_jwt_case(case: &UnsignedJwtCase) -> AuditResult<()> {
    let compact = match parse_jws(&case.compact) {
        Ok(compact) => compact,
        Err(error) => {
            if case.expected_error.as_deref() == Some("InvalidJwtFormat") {
                return Ok(());
            }
            return Err(error);
        }
    };
    let protected = decode_json_segment(&compact.protected)?;
    let payload = decode_json_segment(&compact.payload)?;

    match (
        case.expected_claims_json.as_ref(),
        case.expected_error.as_deref(),
    ) {
        (Some(expected_claims), None) => {
            ensure(
                protected.get("alg").and_then(Value::as_str) == Some("none"),
                AuditReason::HeaderMismatch,
            )?;
            ensure(
                compact.signature.is_empty(),
                AuditReason::NegativeCompactShape,
            )?;
            ensure(&payload == expected_claims, AuditReason::ClaimsMismatch)
        }
        (None, Some("InvalidJwtFormat")) => {
            let invalid_alg = protected.get("alg").and_then(Value::as_str) != Some("none");
            let invalid_typ = protected
                .get("typ")
                .and_then(Value::as_str)
                .is_some_and(|typ| typ != "JWT");
            let non_empty_signature = !compact.signature.is_empty();
            ensure(
                invalid_alg || invalid_typ || non_empty_signature,
                AuditReason::NegativeCompactShape,
            )
        }
        (None, Some(_)) => Err(general(AuditReason::UnsupportedExpectedError)),
        _ => Err(general(AuditReason::MissingField)),
    }
}

fn audit_jwe_case(case: &JweCase) -> AuditResult<()> {
    let compact = match parse_jwe(&case.compact) {
        Ok(compact) => compact,
        Err(error) => {
            if case.expected_error.as_deref() == Some("InvalidCompact") {
                return Ok(());
            }
            return Err(error);
        }
    };
    let protected = decode_json_segment(&compact.protected)?;
    ensure(
        protected == case.protected_header,
        AuditReason::HeaderMismatch,
    )?;

    match (
        case.expected_plaintext_json.as_ref(),
        case.expected_error.as_deref(),
    ) {
        (Some(expected_plaintext), None) => {
            if case.alg == "dir" {
                let plaintext = decrypt_direct_jwe(case, &compact)?;
                let decoded: Value = serde_json::from_slice(&plaintext)
                    .map_err(|_| general(AuditReason::PayloadJson))?;
                ensure(
                    &decoded == expected_plaintext,
                    AuditReason::JwePlaintextMismatch,
                )
            } else if case.alg == "ECDH-ES" {
                audit_ecdh_es_positive(case, &compact, &protected)
            } else {
                Err(general(AuditReason::UnsupportedAlgorithm))
            }
        }
        (None, Some(expected_error)) => {
            audit_jwe_negative(case, &compact, &protected, expected_error)
        }
        _ => Err(general(AuditReason::MissingField)),
    }
}

fn audit_ecdh_es_positive(
    case: &JweCase,
    compact: &CompactJwe,
    protected: &Value,
) -> AuditResult<()> {
    ensure(
        compact.encrypted_key.is_empty(),
        AuditReason::DirectEncryptedKey,
    )?;
    ensure(
        protected.get("epk").is_some(),
        AuditReason::NegativeHeaderShape,
    )?;
    let iv = decode_base64url(&compact.iv)?;
    let tag = decode_base64url(&compact.tag)?;
    ensure(iv.len() == 12, AuditReason::InvalidIvLength)?;
    ensure(tag.len() == 16, AuditReason::InvalidTagLength)?;
    let derived_cek_hex = case
        .derived_cek_hex
        .as_deref()
        .ok_or_else(|| general(AuditReason::MissingField))?;
    let derived_cek = decode_hex(derived_cek_hex)?;
    ensure(
        valid_cek_len(&case.enc, derived_cek.len()),
        AuditReason::InvalidCekLength,
    )?;
    let plaintext = decrypt_jwe_with_cek(case, compact, &derived_cek)?;
    assert_expected_plaintext(case, &plaintext)
}

fn assert_expected_plaintext(case: &JweCase, plaintext: &[u8]) -> AuditResult<()> {
    let expected_plaintext = case
        .expected_plaintext_json
        .as_ref()
        .ok_or_else(|| general(AuditReason::MissingField))?;
    let decoded: Value =
        serde_json::from_slice(plaintext).map_err(|_| general(AuditReason::PayloadJson))?;
    ensure(
        &decoded == expected_plaintext,
        AuditReason::JwePlaintextMismatch,
    )
}

fn audit_alg_header(protected: &Value, expected_alg: &str) -> AuditResult<()> {
    ensure(
        protected.get("alg").and_then(Value::as_str) == Some(expected_alg),
        AuditReason::HeaderMismatch,
    )
}

fn audit_jwk_binding(case: &SignedJwtCase, protected: &Value) -> AuditResult<()> {
    let jwk_alg = case
        .verification_jwk
        .get("alg")
        .and_then(Value::as_str)
        .ok_or_else(|| general(AuditReason::MissingField))?;
    let header_alg = protected
        .get("alg")
        .and_then(Value::as_str)
        .ok_or_else(|| general(AuditReason::HeaderMismatch))?;
    if case.expected_error.as_deref() == Some("AlgorithmMismatch") {
        ensure(
            header_alg != jwk_alg,
            AuditReason::UnsupportedAlgorithmVectorInvalid,
        )
    } else if case.expected_error.as_deref() == Some("KeyIdMismatch") {
        let header_kid = protected
            .get("kid")
            .and_then(Value::as_str)
            .ok_or_else(|| general(AuditReason::HeaderMismatch))?;
        let jwk_kid = case
            .verification_jwk
            .get("kid")
            .and_then(Value::as_str)
            .ok_or_else(|| general(AuditReason::MissingField))?;
        ensure(header_kid != jwk_kid, AuditReason::HeaderMismatch)
    } else {
        Ok(())
    }
}

fn audit_jws_negative(
    expected_error: &str,
    protected: &Value,
    has_duplicate_header: bool,
    expected_alg: Option<&str>,
    signature_ok: bool,
) -> AuditResult<()> {
    match expected_error {
        "InvalidSignature" => ensure(!signature_ok, AuditReason::InvalidSignatureVerified),
        "HeaderMismatch" => {
            audit_unsafe_or_mismatched_header(protected, has_duplicate_header, expected_alg)
        }
        "BadSignatureBase64" | "InvalidCompactEncoding" => Ok(()),
        _ => Err(general(AuditReason::UnsupportedExpectedError)),
    }
}

fn audit_signed_jwt_negative(
    expected_error: &str,
    protected: &Value,
    has_duplicate_header: bool,
    expected_alg: Option<&str>,
    signature_ok: bool,
) -> AuditResult<()> {
    match expected_error {
        "InvalidSignature" => ensure(!signature_ok, AuditReason::InvalidSignatureVerified),
        "InvalidHeader" => {
            audit_unsafe_or_mismatched_header(protected, has_duplicate_header, expected_alg)
        }
        "UnsupportedAlgorithm" => audit_unsupported_algorithm_header(protected),
        "AlgorithmMismatch" => Ok(()),
        "KeyIdMismatch" | "PublicKeyMismatch" | "InvalidPublicKey" => Ok(()),
        "Expired"
        | "NotYetValid"
        | "IssuedAtInFuture"
        | "MissingRequiredTemporalClaim:Exp"
        | "InvalidTemporalClaimValue:Exp" => {
            ensure(signature_ok, AuditReason::SignatureDidNotVerify)
        }
        "InvalidJwtFormat" => Ok(()),
        _ => Err(general(AuditReason::UnsupportedExpectedError)),
    }
}

fn audit_unsafe_or_mismatched_header(
    protected: &Value,
    has_duplicate_header: bool,
    expected_alg: Option<&str>,
) -> AuditResult<()> {
    let alg = protected.get("alg").and_then(Value::as_str);
    let typ = protected.get("typ").and_then(Value::as_str);
    let alg_mismatch = expected_alg.is_some_and(|expected| alg != Some(expected));
    let has_unsafe = ["crit", "b64", "jku", "jwk", "x5u", "x5c", "zip"]
        .iter()
        .any(|name| protected.get(*name).is_some());
    ensure(
        has_unsafe
            || has_duplicate_header
            || alg_mismatch
            || alg.is_none()
            || matches!(alg, Some("none" | "ES256K" | "EdDSA"))
            || typ.is_some_and(|value| value != "JWT"),
        AuditReason::NegativeHeaderShape,
    )
}

fn has_duplicate_member(protected_segment: &str, name: &str) -> AuditResult<bool> {
    let bytes = decode_base64url(protected_segment)?;
    let header = std::str::from_utf8(&bytes).map_err(|_| general(AuditReason::HeaderJson))?;
    let needle = format!("\"{name}\"");
    Ok(header.matches(&needle).count() > 1)
}

fn audit_unsupported_algorithm_header(protected: &Value) -> AuditResult<()> {
    let alg = protected
        .get("alg")
        .and_then(Value::as_str)
        .ok_or_else(|| general(AuditReason::HeaderMismatch))?;
    ensure(
        !matches!(alg, "ES256" | "ES256K" | "EdDSA" | "none"),
        AuditReason::UnsupportedAlgorithmVectorInvalid,
    )
}

fn audit_jwe_negative(
    case: &JweCase,
    compact: &CompactJwe,
    protected: &Value,
    expected_error: &str,
) -> AuditResult<()> {
    match expected_error {
        "Decrypt" => {
            let plaintext = decrypt_direct_jwe(case, compact);
            ensure(plaintext.is_err(), AuditReason::JweDecrypt)
        }
        "UnsupportedKeyManagementAlgorithm" => ensure(
            !matches!(case.alg.as_str(), "dir" | "ECDH-ES"),
            AuditReason::UnsupportedAlgorithmVectorInvalid,
        ),
        "UnsupportedContentEncryptionAlgorithm" => ensure(
            !matches!(case.enc.as_str(), "A128GCM" | "A192GCM" | "A256GCM"),
            AuditReason::UnsupportedContentEncryptionAlgorithm,
        ),
        "MissingRequiredHeaderParameter" => ensure(
            case.alg == "ECDH-ES" && protected.get("epk").is_none(),
            AuditReason::NegativeHeaderShape,
        ),
        "InvalidKeyAgreementKey" => ensure(
            protected.get("epk").is_some(),
            AuditReason::NegativeHeaderShape,
        ),
        "InvalidContentCipherInput" => {
            let tag = decode_base64url(&compact.tag)?;
            let iv = decode_base64url(&compact.iv)?;
            ensure(
                tag.len() != 16 || iv.len() != 12,
                AuditReason::NegativeCompactShape,
            )
        }
        "InvalidContentEncryptionKey" => {
            let cek_hex = case
                .cek_hex
                .as_deref()
                .ok_or_else(|| general(AuditReason::MissingField))?;
            let cek = decode_hex(cek_hex)?;
            ensure(
                !valid_cek_len(&case.enc, cek.len()),
                AuditReason::InvalidCekLength,
            )
        }
        "InvalidHeader" => audit_unsafe_or_mismatched_header(
            protected,
            has_duplicate_member(&compact.protected, "alg")?,
            Some(case.alg.as_str()),
        ),
        "InvalidCompact" => Ok(()),
        _ => Err(general(AuditReason::UnsupportedExpectedError)),
    }
}
