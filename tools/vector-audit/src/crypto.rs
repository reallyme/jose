// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

fn decrypt_direct_jwe(case: &JweCase, compact: &CompactJwe) -> AuditResult<Vec<u8>> {
    ensure(
        compact.encrypted_key.is_empty(),
        AuditReason::DirectEncryptedKey,
    )?;
    let cek_hex = case
        .cek_hex
        .as_deref()
        .ok_or_else(|| general(AuditReason::MissingField))?;
    let cek = decode_hex(cek_hex)?;
    decrypt_jwe_with_cek(case, compact, &cek)
}

fn decrypt_jwe_with_cek(case: &JweCase, compact: &CompactJwe, cek: &[u8]) -> AuditResult<Vec<u8>> {
    let iv = decode_base64url(&compact.iv)?;
    let ciphertext = decode_base64url(&compact.ciphertext)?;
    let tag = decode_base64url(&compact.tag)?;
    ensure(iv.len() == 12, AuditReason::InvalidIvLength)?;
    ensure(tag.len() == 16, AuditReason::InvalidTagLength)?;

    let mut ciphertext_and_tag = Vec::with_capacity(
        ciphertext
            .len()
            .checked_add(tag.len())
            .ok_or_else(|| general(AuditReason::JweDecrypt))?,
    );
    ciphertext_and_tag.extend_from_slice(&ciphertext);
    ciphertext_and_tag.extend_from_slice(&tag);

    let nonce = <&Nonce<U12>>::try_from(iv.as_slice())
        .map_err(|_| general(AuditReason::InvalidIvLength))?;

    match case.enc.as_str() {
        "A128GCM" => {
            ensure(cek.len() == 16, AuditReason::InvalidCekLength)?;
            let cipher = Aes128Gcm::new_from_slice(cek)
                .map_err(|_| general(AuditReason::InvalidCekLength))?;
            cipher
                .decrypt(
                    nonce,
                    Payload {
                        msg: &ciphertext_and_tag,
                        aad: compact.protected.as_bytes(),
                    },
                )
                .map_err(|_| general(AuditReason::JweDecrypt))
        }
        "A192GCM" => {
            ensure(cek.len() == 24, AuditReason::InvalidCekLength)?;
            let cipher = AesGcm::<Aes192, U12>::new_from_slice(cek)
                .map_err(|_| general(AuditReason::InvalidCekLength))?;
            cipher
                .decrypt(
                    nonce,
                    Payload {
                        msg: &ciphertext_and_tag,
                        aad: compact.protected.as_bytes(),
                    },
                )
                .map_err(|_| general(AuditReason::JweDecrypt))
        }
        "A256GCM" => {
            ensure(cek.len() == 32, AuditReason::InvalidCekLength)?;
            let cipher = Aes256Gcm::new_from_slice(cek)
                .map_err(|_| general(AuditReason::InvalidCekLength))?;
            cipher
                .decrypt(
                    nonce,
                    Payload {
                        msg: &ciphertext_and_tag,
                        aad: compact.protected.as_bytes(),
                    },
                )
                .map_err(|_| general(AuditReason::JweDecrypt))
        }
        _ => Err(general(AuditReason::UnsupportedContentEncryptionAlgorithm)),
    }
}

fn valid_cek_len(enc: &str, len: usize) -> bool {
    matches!(
        (enc, len),
        ("A128GCM", 16) | ("A192GCM", 24) | ("A256GCM", 32)
    )
}

fn parse_jws(input: &str) -> AuditResult<CompactJws> {
    let parts: Vec<&str> = input.split('.').collect();
    ensure(parts.len() == 3, AuditReason::CompactPartCount)?;
    ensure(!parts[0].is_empty(), AuditReason::CompactEmptyPart)?;
    ensure(!parts[1].is_empty(), AuditReason::CompactEmptyPart)?;
    Ok(CompactJws {
        protected: parts[0].to_owned(),
        payload: parts[1].to_owned(),
        signature: parts[2].to_owned(),
    })
}

fn parse_jwe(input: &str) -> AuditResult<CompactJwe> {
    let parts: Vec<&str> = input.split('.').collect();
    ensure(parts.len() == 5, AuditReason::CompactPartCount)?;
    ensure(!parts[0].is_empty(), AuditReason::CompactEmptyPart)?;
    ensure(!parts[2].is_empty(), AuditReason::CompactEmptyPart)?;
    ensure(!parts[4].is_empty(), AuditReason::CompactEmptyPart)?;
    Ok(CompactJwe {
        protected: parts[0].to_owned(),
        encrypted_key: parts[1].to_owned(),
        iv: parts[2].to_owned(),
        ciphertext: parts[3].to_owned(),
        tag: parts[4].to_owned(),
    })
}

fn decode_json_segment(segment: &str) -> AuditResult<Value> {
    let bytes = decode_base64url(segment)?;
    serde_json::from_slice(&bytes).map_err(|_| general(AuditReason::HeaderJson))
}

fn jws_signing_input(protected: &str, payload: &str) -> String {
    let mut out = String::with_capacity(protected.len() + payload.len() + 1);
    out.push_str(protected);
    out.push('.');
    out.push_str(payload);
    out
}

fn verify_signature(
    alg: SignatureAlgorithm,
    public_key: &[u8],
    signing_input: &[u8],
    signature: &[u8],
) -> AuditResult<bool> {
    if signature.len() != alg.signature_len() {
        return Ok(false);
    }

    match alg {
        SignatureAlgorithm::Es256 => {
            let key = P256VerifyingKey::from_sec1_bytes(public_key)
                .map_err(|_| general(AuditReason::PublicKeyRejected))?;
            let signature = P256Signature::from_slice(signature)
                .map_err(|_| general(AuditReason::SignatureLength))?;
            Ok(key.verify(signing_input, &signature).is_ok())
        }
        SignatureAlgorithm::Es256K => {
            let key = K256VerifyingKey::from_sec1_bytes(public_key)
                .map_err(|_| general(AuditReason::PublicKeyRejected))?;
            let signature = K256Signature::from_slice(signature)
                .map_err(|_| general(AuditReason::SignatureLength))?;
            Ok(key.verify(signing_input, &signature).is_ok())
        }
        SignatureAlgorithm::EdDsa => {
            let bytes: [u8; 32] = public_key
                .try_into()
                .map_err(|_| general(AuditReason::PublicKeyLength))?;
            let key = VerifyingKey::from_bytes(&bytes)
                .map_err(|_| general(AuditReason::PublicKeyRejected))?;
            let signature = Ed25519Signature::from_slice(signature)
                .map_err(|_| general(AuditReason::SignatureLength))?;
            Ok(key.verify(signing_input, &signature).is_ok())
        }
    }
}

fn decode_hex(input: &str) -> AuditResult<Vec<u8>> {
    hex::decode(input).map_err(|_| general(AuditReason::Hex))
}

fn decode_base64url(input: &str) -> AuditResult<Vec<u8>> {
    URL_SAFE_NO_PAD
        .decode(input)
        .map_err(|_| general(AuditReason::Base64Url))
}

fn ensure(condition: bool, reason: AuditReason) -> AuditResult<()> {
    if condition {
        Ok(())
    } else {
        Err(general(reason))
    }
}

fn general(reason: AuditReason) -> AuditError {
    AuditError {
        context: AuditContext::General,
        reason,
    }
}

fn manifest_error(reason: AuditReason) -> AuditError {
    AuditError {
        context: AuditContext::Manifest,
        reason,
    }
}

fn attach_case(error: AuditError, id: &str) -> AuditError {
    AuditError {
        context: AuditContext::Case(CaseId::from_str(id)),
        reason: error.reason,
    }
}
