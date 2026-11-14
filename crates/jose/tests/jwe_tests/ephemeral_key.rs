// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

#[test]
fn built_in_ecdh_resolvers_validate_the_ephemeral_jwk_on_direct_calls() -> Result<(), JweError> {
    let seed = reallyme_jose::Zeroizing::new(private_scalar(5));
    let (p256_public, p256_private) =
        reallyme_crypto::p256::generate_p256_keypair_from_secret_key(&seed)
            .map_err(|_| JweError::InvalidKeyAgreementKey)?;
    check_ephemeral_jwk_inputs(
        "P-256",
        32,
        &reallyme_crypto::p256::decompress_public_key(&p256_public)
            .map_err(|_| JweError::InvalidKeyAgreementKey)?,
        &P256EcdhEsJweKeyResolver::new(&p256_private),
    )?;

    #[cfg(feature = "native")]
    {
        let seed = reallyme_jose::Zeroizing::new(private_scalar_with_len::<48>(5));
        let (public, private) = reallyme_crypto::p384::generate_p384_keypair_from_secret_key(&seed)
            .map_err(|_| JweError::InvalidKeyAgreementKey)?;
        check_ephemeral_jwk_inputs(
            "P-384",
            48,
            &reallyme_crypto::p384::decompress_p384(&public)
                .map_err(|_| JweError::InvalidKeyAgreementKey)?,
            &P384EcdhEsJweKeyResolver::new(&private),
        )?;

        let seed = reallyme_jose::Zeroizing::new(private_scalar_with_len::<66>(5));
        let (public, private) = reallyme_crypto::p521::generate_p521_keypair_from_secret_key(&seed)
            .map_err(|_| JweError::InvalidKeyAgreementKey)?;
        check_ephemeral_jwk_inputs(
            "P-521",
            66,
            &reallyme_crypto::p521::decompress_p521(&public)
                .map_err(|_| JweError::InvalidKeyAgreementKey)?,
            &P521EcdhEsJweKeyResolver::new(&private),
        )?;
    }
    Ok(())
}

fn check_ephemeral_jwk_inputs(
    curve: &str,
    width: usize,
    uncompressed: &[u8],
    resolver: &dyn JweContentEncryptionKeyResolver,
) -> Result<(), JweError> {
    let x_end = 1_usize.checked_add(width).ok_or(JweError::LengthOverflow)?;
    let x = uncompressed
        .get(1..x_end)
        .ok_or(JweError::InvalidKeyAgreementKey)?;
    let y = uncompressed
        .get(x_end..)
        .ok_or(JweError::InvalidKeyAgreementKey)?;
    let good = json!({
        "kty": "EC", "crv": curve, "x": bytes_to_base64url(x), "y": bytes_to_base64url(y),
    });
    let mut header = CompactJweProtectedHeader {
        alg: JweKeyManagementAlgorithm::EcdhEs,
        enc: JweContentEncryptionAlgorithm::A128Gcm,
        epk: Some(good.clone()),
        zip: None,
        kid: None,
        apu: None,
        apv: None,
        typ: None,
        cty: None,
    };
    assert_eq!(
        resolver.resolve_content_encryption_key(&header, &[])?.len(),
        16
    );

    let shorter = width.checked_sub(1).ok_or(JweError::LengthOverflow)?;
    let longer = width.checked_add(1).ok_or(JweError::LengthOverflow)?;
    let other_curve = if curve == "P-256" { "P-384" } else { "P-256" };
    for (member, value) in [
        ("d", json!("AQ")),
        ("kty", json!("OKP")),
        ("crv", json!("secp256k1")),
        ("crv", json!(other_curve)),
        ("x", json!(0)),
        ("x", json!("AQ==")),
        ("x", json!(bytes_to_base64url(&vec![0_u8; shorter]))),
        ("y", json!(bytes_to_base64url(&vec![0_u8; longer]))),
    ] {
        let mut changed = good.clone();
        changed
            .as_object_mut()
            .ok_or(JweError::InvalidKeyAgreementKey)?
            .insert(member.to_owned(), value);
        header.epk = Some(changed);
        assert!(
            matches!(
                resolver.resolve_content_encryption_key(&header, &[]),
                Err(JweError::InvalidKeyAgreementKey)
            ),
            "{curve} resolver must reject the modified {member} member"
        );
    }

    let mut substituted = good;
    let members = substituted
        .as_object_mut()
        .ok_or(JweError::InvalidKeyAgreementKey)?;
    members.remove("y");
    members.insert("d".to_owned(), json!("AQ"));
    header.epk = Some(substituted);
    assert!(matches!(
        resolver.resolve_content_encryption_key(&header, &[]),
        Err(JweError::InvalidKeyAgreementKey)
    ));

    Ok(())
}
