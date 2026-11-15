// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

// Derived from the protobuf contract. Change the schema and regenerate.

use super::{Contract, JoseOperationKind};
use buffa::Enumeration;

#[test]
fn schema_parity_and_invalid_values() {
    let cases = [
        (
            Contract::JOSE_OPERATION_KIND_JWS_SIGN,
            JoseOperationKind::JwsSign,
        ),
        (
            Contract::JOSE_OPERATION_KIND_JWS_VERIFY,
            JoseOperationKind::JwsVerify,
        ),
        (
            Contract::JOSE_OPERATION_KIND_SIGNATURE_SIGN,
            JoseOperationKind::SignatureSign,
        ),
        (
            Contract::JOSE_OPERATION_KIND_SIGNATURE_VERIFY,
            JoseOperationKind::SignatureVerify,
        ),
        (
            Contract::JOSE_OPERATION_KIND_SIGNATURE_SUITE_INFO,
            JoseOperationKind::SignatureSuiteInfo,
        ),
        (
            Contract::JOSE_OPERATION_KIND_JWT_ENCODE_UNSIGNED,
            JoseOperationKind::JwtEncodeUnsigned,
        ),
        (
            Contract::JOSE_OPERATION_KIND_JWT_DECODE_UNSIGNED,
            JoseOperationKind::JwtDecodeUnsigned,
        ),
        (
            Contract::JOSE_OPERATION_KIND_JWT_SIGN,
            JoseOperationKind::JwtSign,
        ),
        (
            Contract::JOSE_OPERATION_KIND_JWT_VERIFY,
            JoseOperationKind::JwtVerify,
        ),
        (
            Contract::JOSE_OPERATION_KIND_JWT_SIGN_WITH_PROVIDER,
            JoseOperationKind::JwtSignWithProvider,
        ),
        (
            Contract::JOSE_OPERATION_KIND_JWT_CLAIMS_PARSE,
            JoseOperationKind::JwtClaimsParse,
        ),
        (
            Contract::JOSE_OPERATION_KIND_JWE_ENCRYPT,
            JoseOperationKind::JweEncrypt,
        ),
        (
            Contract::JOSE_OPERATION_KIND_JWE_DECRYPT,
            JoseOperationKind::JweDecrypt,
        ),
        (
            Contract::JOSE_OPERATION_KIND_JWE_DERIVE_KEY,
            JoseOperationKind::JweDeriveKey,
        ),
        (
            Contract::JOSE_OPERATION_KIND_JWE_ENCRYPT_WITH_PROVIDER,
            JoseOperationKind::JweEncryptWithProvider,
        ),
        (
            Contract::JOSE_OPERATION_KIND_JWE_DECRYPT_WITH_PROVIDER,
            JoseOperationKind::JweDecryptWithProvider,
        ),
        (
            Contract::JOSE_OPERATION_KIND_CONTRACT_INFO,
            JoseOperationKind::ContractInfo,
        ),
    ];
    for (contract, native) in cases {
        assert_eq!(
            JoseOperationKind::try_from(buffa::EnumValue::from(contract)),
            Ok(native)
        );
        assert_eq!(Contract::from(native), contract);
    }
    for contract in Contract::values() {
        assert_eq!(
            JoseOperationKind::try_from(buffa::EnumValue::from(*contract)).is_ok(),
            cases.iter().any(|(value, _)| value == contract)
        );
    }
    for invalid in [0, -1, i32::MIN, i32::MAX] {
        assert!(JoseOperationKind::try_from(buffa::EnumValue::from(invalid)).is_err());
    }
}
