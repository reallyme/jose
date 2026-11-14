// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

#[test]
fn built_in_resolvers_reject_cross_mode_tokens_under_a_dual_mode_policy() -> Result<(), JweError> {
    let enc = JweContentEncryptionAlgorithm::A128Gcm;
    let modes = [
        JweKeyManagementAlgorithm::Direct,
        JweKeyManagementAlgorithm::EcdhEs,
    ];
    let suites = [enc];
    let policy = CompactJwePolicy::new(&modes, &suites);
    let direct_key = reallyme_jose::Zeroizing::new([7_u8; 16]);
    let direct = compact_jwe_dir_a128gcm(&direct_key, &[9_u8; 12], b"direct")?;
    let recipient_secret = reallyme_jose::Zeroizing::new(private_scalar(5));
    let (recipient_public, recipient_private) =
        reallyme_crypto::p256::generate_p256_keypair_from_secret_key(&recipient_secret)
            .map_err(|_| JweError::InvalidKeyAgreementKey)?;

    let ecdh = encrypt_compact_jwe_bytes(
        &CompactJweEncryptRequest::new(b"agreement", enc),
        &mut P256EcdhEsJweKeyEncryptor::new(&recipient_public),
        &mut FixedRandom::new([8_u8; 12]),
    )?;
    let direct_resolver = DirectJweKeyResolver::new(direct_key.as_slice());
    let ecdh_resolver = P256EcdhEsJweKeyResolver::new(&recipient_private);
    assert_eq!(
        decrypt_compact_jwe_bytes(&direct, &policy, &direct_resolver)?.as_slice(),
        b"direct"
    );
    assert_eq!(
        decrypt_compact_jwe_bytes(&ecdh, &policy, &ecdh_resolver)?.as_slice(),
        b"agreement"
    );

    assert!(matches!(
        decrypt_compact_jwe_bytes(&ecdh, &policy, &direct_resolver),
        Err(JweError::InvalidEncryptedKey)
    ));
    assert!(matches!(
        decrypt_compact_jwe_bytes(&direct, &policy, &ecdh_resolver),
        Err(JweError::InvalidEncryptedKey)
    ));
    #[cfg(feature = "native")]
    {
        // Each native ECDH-ES resolver must reject the mode before reading its key.
        for resolver in [
            &P384EcdhEsJweKeyResolver::new(&[]) as &dyn JweContentEncryptionKeyResolver,
            &P521EcdhEsJweKeyResolver::new(&[]),
        ] {
            assert!(matches!(
                decrypt_compact_jwe_bytes(&direct, &policy, resolver),
                Err(JweError::InvalidEncryptedKey)
            ));
        }
    }
    Ok(())
}

#[test]
fn aes_gcm_rejects_a_key_from_another_suite_at_provider_boundaries() -> Result<(), JweError> {
    struct FixedKey<'a>(&'a [u8]);

    impl JweContentEncryptionKeyEncryptor for FixedKey<'_> {
        fn prepare_content_encryption_key(
            &mut self,
            _request: &CompactJweEncryptRequest<'_>,
        ) -> Result<PreparedJweEncryptionKey, JweError> {
            PreparedJweEncryptionKey::new(
                JweKeyManagementAlgorithm::Direct,
                reallyme_jose::Zeroizing::new(self.0.to_vec()),
                Vec::new(),
                None,
            )
        }
    }

    impl JweContentEncryptionKeyResolver for FixedKey<'_> {
        fn resolve_content_encryption_key(
            &self,
            _header: &CompactJweProtectedHeader,
            _encrypted_key: &[u8],
        ) -> Result<reallyme_jose::Zeroizing<Vec<u8>>, JweError> {
            Ok(reallyme_jose::Zeroizing::new(self.0.to_vec()))
        }
    }

    struct UnavailableRandom;

    impl reallyme_jose::SecureRandom for UnavailableRandom {
        fn fill_secure(
            &mut self,
            _output: &mut [u8],
            output: RngOutputKind,
        ) -> Result<(), CryptoError> {
            Err(CryptoError::Rng {
                output,
                kind: RngFailureKind::EntropyUnavailable,
            })
        }
    }

    for (enc, key_len) in [
        (JweContentEncryptionAlgorithm::A128Gcm, 16),
        (JweContentEncryptionAlgorithm::A192Gcm, 24),
        (JweContentEncryptionAlgorithm::A256Gcm, 32),
    ] {
        let key = reallyme_jose::Zeroizing::new(vec![7_u8; key_len]);
        let request = CompactJweEncryptRequest::new(b"payload", enc);
        let suites = [enc];
        let policy = CompactJwePolicy::new(&[JweKeyManagementAlgorithm::Direct], &suites);
        let compact = encrypt_compact_jwe_bytes(
            &request,
            &mut FixedKey(&key),
            &mut FixedRandom::new([9_u8; 12]),
        )?;
        assert_eq!(
            decrypt_compact_jwe_bytes(&compact, &policy, &FixedKey(&key))?.as_slice(),
            b"payload"
        );

        for wrong_len in [16, 24, 32].into_iter().filter(|len| *len != key_len) {
            let wrong_key = reallyme_jose::Zeroizing::new(vec![7_u8; wrong_len]);
            assert!(matches!(
                encrypt_compact_jwe_bytes(
                    &request,
                    &mut FixedKey(&wrong_key),
                    &mut UnavailableRandom,
                ),
                Err(JweError::InvalidContentEncryptionKey)
            ));
            assert!(matches!(
                decrypt_compact_jwe_bytes(&compact, &policy, &FixedKey(&wrong_key)),
                Err(JweError::InvalidContentEncryptionKey)
            ));
        }

        let header = serde_json::from_value(json!({
            "alg":"ECDH-ES", "enc":enc.as_str(),
            "epk":{"kty":"EC","crv":"P-256","x":"AA","y":"AA"},
        }))
        .map_err(|_| JweError::InvalidHeader)?;
        let shared_secret = reallyme_jose::Zeroizing::new([11_u8; 32]);
        let derived = derive_ecdh_es_content_encryption_key(shared_secret.as_slice(), &header)?;
        assert_eq!(derived.len(), key_len);
    }
    Ok(())
}
