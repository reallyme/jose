// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

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
const MANIFEST_FILE: &str = "vectors/manifest.json";
const JWS_FILE: &str = "vectors/jws-compact.json";
const SIGNED_JWT_FILE: &str = "vectors/signed-jwt.json";
const UNSIGNED_JWT_FILE: &str = "vectors/unsigned-jwt.json";
const JWE_FILE: &str = "vectors/jwe-compact.json";
const PANVA_FILE: &str = "vectors/panva-jose.json";

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

include!("manifest.rs");
include!("cases.rs");
include!("crypto.rs");
