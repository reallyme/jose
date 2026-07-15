// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

//! Independent audit for committed JOSE conformance vectors.
//!
//! This binary intentionally does not depend on `reallyme-jose`,
//! `reallyme-crypto`, or `reallyme-codec`. It validates the committed JSON,
//! compact serializations, signatures, and direct AES-GCM JWE fixtures with
//! independent crates so vector regressions are not masked by shared code.

use std::collections::HashSet;
use std::fmt::{Display, Formatter, Write};
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use aes::Aes192;
use aes_gcm::aead::consts::U12;
use aes_gcm::aead::{Aead, Payload};
use aes_gcm::{Aes128Gcm, Aes256Gcm, AesGcm, KeyInit, Nonce};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use ed25519_dalek::{Signature as Ed25519Signature, Verifier, VerifyingKey};
use k256::ecdsa::{Signature as K256Signature, VerifyingKey as K256VerifyingKey};
use p256::ecdsa::{Signature as P256Signature, VerifyingKey as P256VerifyingKey};
use serde::Deserialize;
use serde_json::Value;
use thiserror::Error;

const CASE_ID_BYTES: usize = 96;
const CASE_ID_BYTES_U8: u8 = 96;
const MANIFEST_FILE: &str = "conformance/vectors/manifest.json";
const JWS_FILE: &str = "conformance/vectors/jws-compact.json";
const SIGNED_JWT_FILE: &str = "conformance/vectors/signed-jwt.json";
const UNSIGNED_JWT_FILE: &str = "conformance/vectors/unsigned-jwt.json";
const JWE_FILE: &str = "conformance/vectors/jwe-compact.json";
const PANVA_FILE: &str = "conformance/vectors/panva-jose.json";

#[derive(Debug, Error)]
#[error("{context}: {reason}")]
struct AuditError {
    context: AuditContext,
    reason: AuditReason,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum AuditContext {
    General,
    Manifest,
    Case(CaseId),
}

impl Display for AuditContext {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::General => formatter.write_str("vector audit"),
            Self::Manifest => formatter.write_str("manifest"),
            Self::Case(case_id) => Display::fmt(case_id, formatter),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct CaseId {
    bytes: [u8; CASE_ID_BYTES],
    len: u8,
}

impl CaseId {
    fn from_str(value: &str) -> Self {
        let mut bytes = [0_u8; CASE_ID_BYTES];
        let source = value.as_bytes();
        let copy_len = source.len().min(CASE_ID_BYTES);
        bytes[..copy_len].copy_from_slice(&source[..copy_len]);
        let len = match u8::try_from(copy_len) {
            Ok(value) => value,
            Err(_) => CASE_ID_BYTES_U8,
        };
        Self { bytes, len }
    }

    fn as_bytes(&self) -> &[u8] {
        &self.bytes[..usize::from(self.len)]
    }
}

impl Display for CaseId {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        for byte in self.as_bytes() {
            if byte.is_ascii_graphic() || *byte == b' ' {
                formatter.write_char(char::from(*byte))?;
            } else {
                formatter.write_char('?')?;
            }
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Error, Eq, PartialEq)]
enum AuditReason {
    #[error("could not determine repository root")]
    CurrentDirectory,
    #[error("could not read vector file")]
    ReadFile,
    #[error("JSON decoding failed")]
    Json,
    #[error("hex decoding failed")]
    Hex,
    #[error("base64url decoding failed")]
    Base64Url,
    #[error("compact serialization has the wrong number of parts")]
    CompactPartCount,
    #[error("compact serialization part is empty")]
    CompactEmptyPart,
    #[error("duplicate vector id")]
    DuplicateCaseId,
    #[error("manifest references an unknown suite")]
    UnknownManifestSuite,
    #[error("manifest case count mismatch")]
    ManifestCaseCount,
    #[error("manifest path mismatch")]
    ManifestPath,
    #[error("unexpected suite name")]
    SuiteName,
    #[error("unsupported algorithm")]
    UnsupportedAlgorithm,
    #[error("unsupported content-encryption algorithm")]
    UnsupportedContentEncryptionAlgorithm,
    #[error("unsupported expected error")]
    UnsupportedExpectedError,
    #[error("required vector field is missing")]
    MissingField,
    #[error("header JSON is invalid")]
    HeaderJson,
    #[error("payload JSON is invalid")]
    PayloadJson,
    #[error("protected header does not match vector metadata")]
    HeaderMismatch,
    #[error("expected claims do not match payload")]
    ClaimsMismatch,
    #[error("signature length is invalid")]
    SignatureLength,
    #[error("public key length is invalid")]
    PublicKeyLength,
    #[error("public key was rejected by independent crypto")]
    PublicKeyRejected,
    #[error("happy-path signature did not verify independently")]
    SignatureDidNotVerify,
    #[error("negative signature vector verified independently")]
    InvalidSignatureVerified,
    #[error("negative header vector lacks the intended unsafe header")]
    NegativeHeaderShape,
    #[error("negative compact vector has valid compact structure")]
    NegativeCompactShape,
    #[error("unsupported-algorithm vector uses a supported header")]
    UnsupportedAlgorithmVectorInvalid,
    #[error("JWE direct vector has non-empty encrypted key")]
    DirectEncryptedKey,
    #[error("JWE IV length is invalid")]
    InvalidIvLength,
    #[error("JWE tag length is invalid")]
    InvalidTagLength,
    #[error("JWE CEK length is invalid")]
    InvalidCekLength,
    #[error("JWE ciphertext authentication failed")]
    JweDecrypt,
    #[error("JWE plaintext JSON mismatch")]
    JwePlaintextMismatch,
}

type AuditResult<T> = Result<T, AuditError>;

#[derive(Debug, Deserialize)]
struct Suite<T> {
    schema: String,
    suite: String,
    cases: Vec<T>,
}

#[derive(Debug, Deserialize)]
struct Manifest {
    schema: String,
    suites: Vec<ManifestSuite>,
}

#[derive(Debug, Deserialize)]
struct ManifestSuite {
    id: String,
    path: String,
    case_count: usize,
}

#[derive(Debug, Deserialize)]
struct JwsCase {
    id: String,
    alg: String,
    compact: String,
    public_key_hex: String,
    payload_utf8: Option<String>,
    expected_valid: Option<bool>,
    expected_error: Option<String>,
}

#[derive(Debug, Deserialize)]
struct SignedJwtCase {
    id: String,
    alg: String,
    compact: String,
    public_key_hex: String,
    verification_jwk: Value,
    expected_claims_json: Option<Value>,
    expected_error: Option<String>,
}

#[derive(Debug, Deserialize)]
struct UnsignedJwtCase {
    id: String,
    compact: String,
    expected_claims_json: Option<Value>,
    expected_error: Option<String>,
}

#[derive(Debug, Deserialize)]
struct JweCase {
    id: String,
    alg: String,
    enc: String,
    cek_hex: Option<String>,
    protected_header: Value,
    compact: String,
    expected_plaintext_json: Option<Value>,
    expected_error: Option<String>,
    derived_cek_hex: Option<String>,
}

#[derive(Debug, Deserialize)]
struct PanvaCase {
    id: String,
    format: String,
    alg: String,
    enc: Option<String>,
    compact: String,
    public_key_hex: Option<String>,
    payload_utf8: Option<String>,
    verification_jwk: Option<Value>,
    expected_claims_json: Option<Value>,
    protected_header: Option<Value>,
    expected_plaintext_json: Option<Value>,
    derived_cek_hex: Option<String>,
}

#[derive(Debug)]
struct AuditSummary {
    jws_cases: usize,
    signed_jwt_cases: usize,
    unsigned_jwt_cases: usize,
    jwe_cases: usize,
    panva_cases: usize,
}

#[derive(Debug)]
struct CompactJws {
    protected: String,
    payload: String,
    signature: String,
}

#[derive(Debug)]
struct CompactJwe {
    protected: String,
    encrypted_key: String,
    iv: String,
    ciphertext: String,
    tag: String,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum SignatureAlgorithm {
    Es256,
    Es256K,
    EdDsa,
}

impl SignatureAlgorithm {
    fn parse(input: &str) -> AuditResult<Self> {
        match input {
            "ES256" => Ok(Self::Es256),
            "ES256K" => Ok(Self::Es256K),
            "EdDSA" => Ok(Self::EdDsa),
            _ => Err(general(AuditReason::UnsupportedAlgorithm)),
        }
    }

    fn signature_len(self) -> usize {
        match self {
            Self::Es256 | Self::Es256K | Self::EdDsa => 64,
        }
    }
}

fn main() -> ExitCode {
    match run() {
        Ok(summary) => {
            println!(
                "vector audit passed: {} JWS, {} signed JWT, {} unsigned JWT, {} JWE, {} panva cases",
                summary.jws_cases,
                summary.signed_jwt_cases,
                summary.unsigned_jwt_cases,
                summary.jwe_cases,
                summary.panva_cases
            );
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("vector audit failed: {error}");
            ExitCode::FAILURE
        }
    }
}

fn run() -> AuditResult<AuditSummary> {
    let repo_root = repo_root()?;
    let manifest: Manifest = read_json(&repo_root, MANIFEST_FILE, AuditContext::Manifest)?;
    let jws: Suite<JwsCase> = read_json(&repo_root, JWS_FILE, AuditContext::General)?;
    let signed_jwt: Suite<SignedJwtCase> =
        read_json(&repo_root, SIGNED_JWT_FILE, AuditContext::General)?;
    let unsigned_jwt: Suite<UnsignedJwtCase> =
        read_json(&repo_root, UNSIGNED_JWT_FILE, AuditContext::General)?;
    let jwe: Suite<JweCase> = read_json(&repo_root, JWE_FILE, AuditContext::General)?;
    let panva: Suite<PanvaCase> = read_json(&repo_root, PANVA_FILE, AuditContext::General)?;

    audit_suite_header(&jws, "jws-compact")?;
    audit_suite_header(&signed_jwt, "signed-jwt")?;
    audit_suite_header(&unsigned_jwt, "unsigned-jwt")?;
    audit_suite_header(&jwe, "jwe-compact")?;
    audit_suite_header(&panva, "panva-jose")?;
    audit_manifest(&manifest, &jws, &signed_jwt, &unsigned_jwt, &jwe, &panva)?;

    let mut ids = HashSet::new();
    for case in &jws.cases {
        audit_unique_id(&mut ids, &case.id)?;
        audit_jws_case(case).map_err(|error| attach_case(error, &case.id))?;
    }
    for case in &signed_jwt.cases {
        audit_unique_id(&mut ids, &case.id)?;
        audit_signed_jwt_case(case).map_err(|error| attach_case(error, &case.id))?;
    }
    for case in &unsigned_jwt.cases {
        audit_unique_id(&mut ids, &case.id)?;
        audit_unsigned_jwt_case(case).map_err(|error| attach_case(error, &case.id))?;
    }
    for case in &jwe.cases {
        audit_unique_id(&mut ids, &case.id)?;
        audit_jwe_case(case).map_err(|error| attach_case(error, &case.id))?;
    }
    for case in &panva.cases {
        audit_unique_id(&mut ids, &case.id)?;
        audit_panva_case(case).map_err(|error| attach_case(error, &case.id))?;
    }

    Ok(AuditSummary {
        jws_cases: jws.cases.len(),
        signed_jwt_cases: signed_jwt.cases.len(),
        unsigned_jwt_cases: unsigned_jwt.cases.len(),
        jwe_cases: jwe.cases.len(),
        panva_cases: panva.cases.len(),
    })
}

fn repo_root() -> AuditResult<PathBuf> {
    if let Some(path) = std::env::args_os().nth(1) {
        Ok(PathBuf::from(path))
    } else {
        std::env::current_dir().map_err(|_| general(AuditReason::CurrentDirectory))
    }
}

fn read_json<T: for<'de> Deserialize<'de>>(
    repo_root: &Path,
    path: &str,
    context: AuditContext,
) -> AuditResult<T> {
    let bytes = std::fs::read(repo_root.join(path)).map_err(|_| AuditError {
        context,
        reason: AuditReason::ReadFile,
    })?;
    serde_json::from_slice(&bytes).map_err(|_| AuditError {
        context,
        reason: AuditReason::Json,
    })
}

fn audit_suite_header<T>(suite: &Suite<T>, expected_suite: &str) -> AuditResult<()> {
    ensure(
        suite.schema == "reallyme.identity.conformance.vectors.v1",
        AuditReason::SuiteName,
    )?;
    ensure(suite.suite == expected_suite, AuditReason::SuiteName)
}

fn audit_manifest(
    manifest: &Manifest,
    jws: &Suite<JwsCase>,
    signed_jwt: &Suite<SignedJwtCase>,
    unsigned_jwt: &Suite<UnsignedJwtCase>,
    jwe: &Suite<JweCase>,
    panva: &Suite<PanvaCase>,
) -> AuditResult<()> {
    ensure(
        manifest.schema == "reallyme.jose.conformance.vector_manifest.v1",
        AuditReason::SuiteName,
    )
    .map_err(|error| AuditError {
        context: AuditContext::Manifest,
        reason: error.reason,
    })?;

    for suite in &manifest.suites {
        let (expected_path, actual_count) = match suite.id.as_str() {
            "jws-compact" => ("jws-compact.json", jws.cases.len()),
            "signed-jwt" => ("signed-jwt.json", signed_jwt.cases.len()),
            "unsigned-jwt" => ("unsigned-jwt.json", unsigned_jwt.cases.len()),
            "jwe-compact" => ("jwe-compact.json", jwe.cases.len()),
            "panva-jose" => ("panva-jose.json", panva.cases.len()),
            _ => return Err(manifest_error(AuditReason::UnknownManifestSuite)),
        };
        ensure(suite.path == expected_path, AuditReason::ManifestPath).map_err(|error| {
            AuditError {
                context: AuditContext::Manifest,
                reason: error.reason,
            }
        })?;
        ensure(
            suite.case_count == actual_count,
            AuditReason::ManifestCaseCount,
        )
        .map_err(|error| AuditError {
            context: AuditContext::Manifest,
            reason: error.reason,
        })?;
    }
    Ok(())
}

fn audit_panva_case(case: &PanvaCase) -> AuditResult<()> {
    match case.format.as_str() {
        "jws-compact" => audit_jws_case(&JwsCase {
            id: case.id.clone(),
            alg: case.alg.clone(),
            compact: case.compact.clone(),
            public_key_hex: case
                .public_key_hex
                .clone()
                .ok_or_else(|| general(AuditReason::MissingField))?,
            payload_utf8: case.payload_utf8.clone(),
            expected_valid: Some(true),
            expected_error: None,
        }),
        "jwt-compact" => audit_signed_jwt_case(&SignedJwtCase {
            id: case.id.clone(),
            alg: case.alg.clone(),
            compact: case.compact.clone(),
            public_key_hex: case
                .public_key_hex
                .clone()
                .ok_or_else(|| general(AuditReason::MissingField))?,
            verification_jwk: case
                .verification_jwk
                .clone()
                .ok_or_else(|| general(AuditReason::MissingField))?,
            expected_claims_json: case.expected_claims_json.clone(),
            expected_error: None,
        }),
        "jwe-compact" => audit_jwe_case(&JweCase {
            id: case.id.clone(),
            alg: case.alg.clone(),
            enc: case
                .enc
                .clone()
                .ok_or_else(|| general(AuditReason::MissingField))?,
            cek_hex: None,
            protected_header: case
                .protected_header
                .clone()
                .ok_or_else(|| general(AuditReason::MissingField))?,
            compact: case.compact.clone(),
            expected_plaintext_json: case.expected_plaintext_json.clone(),
            expected_error: None,
            derived_cek_hex: case.derived_cek_hex.clone(),
        }),
        _ => Err(general(AuditReason::UnsupportedAlgorithm)),
    }
}

fn audit_unique_id(ids: &mut HashSet<String>, id: &str) -> AuditResult<()> {
    if ids.insert(id.to_owned()) {
        Ok(())
    } else {
        Err(AuditError {
            context: AuditContext::Case(CaseId::from_str(id)),
            reason: AuditReason::DuplicateCaseId,
        })
    }
}

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

    // aes-gcm 0.10 still exposes nonce construction through generic-array
    // 0.14. Keep this allowance local so the rest of the tool remains warning
    // clean and the audit can move to the non-deprecated constructor when the
    // dependency does.
    #[allow(deprecated)]
    let nonce = Nonce::from_slice(&iv);

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
