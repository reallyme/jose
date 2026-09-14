// SPDX-FileCopyrightText: 2026 ReallyMe LLC
//
// SPDX-License-Identifier: MIT OR Apache-2.0

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
