// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

// Derived from the protobuf contract. Change the schema and regenerate.

package me.really.jose

public enum class ReallyMeJoseErrorBranch {
    PRIMITIVE,
    PROVIDER,
    BACKEND,
    ;
    public companion object {
        @JvmStatic
        public fun fromContract(value: me.really.jose.v1.JoseErrorBranch?): ReallyMeJoseErrorBranch = when (value) {
            me.really.jose.v1.JoseErrorBranch.JOSE_ERROR_BRANCH_PRIMITIVE -> PRIMITIVE
            me.really.jose.v1.JoseErrorBranch.JOSE_ERROR_BRANCH_PROVIDER -> PROVIDER
            me.really.jose.v1.JoseErrorBranch.JOSE_ERROR_BRANCH_BACKEND -> BACKEND
            else -> throw ReallyMeJoseException.JoseFailure(ReallyMeJoseErrorBranch.PROVIDER, ReallyMeJoseErrorReason.PROVIDER_UNSUPPORTED)
        }
    }
}

internal fun protoErrorBranch(value: ReallyMeJoseErrorBranch): me.really.jose.v1.JoseErrorBranch = when (value) {
    ReallyMeJoseErrorBranch.PRIMITIVE -> me.really.jose.v1.JoseErrorBranch.JOSE_ERROR_BRANCH_PRIMITIVE
    ReallyMeJoseErrorBranch.PROVIDER -> me.really.jose.v1.JoseErrorBranch.JOSE_ERROR_BRANCH_PROVIDER
    ReallyMeJoseErrorBranch.BACKEND -> me.really.jose.v1.JoseErrorBranch.JOSE_ERROR_BRANCH_BACKEND
}

public enum class ReallyMeJoseSignatureAlgorithm {
    ED_DSA,
    ES256,
    ES256K,
    ;
    public companion object {
        @JvmStatic
        public fun fromContract(value: me.really.jose.v1.JoseSignatureAlgorithm?): ReallyMeJoseSignatureAlgorithm = when (value) {
            me.really.jose.v1.JoseSignatureAlgorithm.JOSE_SIGNATURE_ALGORITHM_EDDSA -> ED_DSA
            me.really.jose.v1.JoseSignatureAlgorithm.JOSE_SIGNATURE_ALGORITHM_ES256 -> ES256
            me.really.jose.v1.JoseSignatureAlgorithm.JOSE_SIGNATURE_ALGORITHM_ES256K -> ES256K
            else -> throw ReallyMeJoseException.JoseFailure(ReallyMeJoseErrorBranch.PROVIDER, ReallyMeJoseErrorReason.PROVIDER_UNSUPPORTED)
        }
    }
}

internal fun protoSignatureAlgorithm(value: ReallyMeJoseSignatureAlgorithm): me.really.jose.v1.JoseSignatureAlgorithm = when (value) {
    ReallyMeJoseSignatureAlgorithm.ED_DSA -> me.really.jose.v1.JoseSignatureAlgorithm.JOSE_SIGNATURE_ALGORITHM_EDDSA
    ReallyMeJoseSignatureAlgorithm.ES256 -> me.really.jose.v1.JoseSignatureAlgorithm.JOSE_SIGNATURE_ALGORITHM_ES256
    ReallyMeJoseSignatureAlgorithm.ES256K -> me.really.jose.v1.JoseSignatureAlgorithm.JOSE_SIGNATURE_ALGORITHM_ES256K
}

public enum class ReallyMeJoseJweKeyManagementAlgorithm {
    DIRECT,
    ECDH_ES_P256,
    ECDH_ES_P384,
    ECDH_ES_P521,
    ;
    public companion object {
        @JvmStatic
        public fun fromContract(value: me.really.jose.v1.JoseJweKeyManagementAlgorithm?): ReallyMeJoseJweKeyManagementAlgorithm = when (value) {
            me.really.jose.v1.JoseJweKeyManagementAlgorithm.JOSE_JWE_KEY_MANAGEMENT_ALGORITHM_DIRECT -> DIRECT
            me.really.jose.v1.JoseJweKeyManagementAlgorithm.JOSE_JWE_KEY_MANAGEMENT_ALGORITHM_ECDH_ES_P256 -> ECDH_ES_P256
            me.really.jose.v1.JoseJweKeyManagementAlgorithm.JOSE_JWE_KEY_MANAGEMENT_ALGORITHM_ECDH_ES_P384 -> ECDH_ES_P384
            me.really.jose.v1.JoseJweKeyManagementAlgorithm.JOSE_JWE_KEY_MANAGEMENT_ALGORITHM_ECDH_ES_P521 -> ECDH_ES_P521
            else -> throw ReallyMeJoseException.JoseFailure(ReallyMeJoseErrorBranch.PROVIDER, ReallyMeJoseErrorReason.PROVIDER_UNSUPPORTED)
        }
    }
}

internal fun protoKeyManagementAlgorithm(value: ReallyMeJoseJweKeyManagementAlgorithm): me.really.jose.v1.JoseJweKeyManagementAlgorithm = when (value) {
    ReallyMeJoseJweKeyManagementAlgorithm.DIRECT -> me.really.jose.v1.JoseJweKeyManagementAlgorithm.JOSE_JWE_KEY_MANAGEMENT_ALGORITHM_DIRECT
    ReallyMeJoseJweKeyManagementAlgorithm.ECDH_ES_P256 -> me.really.jose.v1.JoseJweKeyManagementAlgorithm.JOSE_JWE_KEY_MANAGEMENT_ALGORITHM_ECDH_ES_P256
    ReallyMeJoseJweKeyManagementAlgorithm.ECDH_ES_P384 -> me.really.jose.v1.JoseJweKeyManagementAlgorithm.JOSE_JWE_KEY_MANAGEMENT_ALGORITHM_ECDH_ES_P384
    ReallyMeJoseJweKeyManagementAlgorithm.ECDH_ES_P521 -> me.really.jose.v1.JoseJweKeyManagementAlgorithm.JOSE_JWE_KEY_MANAGEMENT_ALGORITHM_ECDH_ES_P521
}

public enum class ReallyMeJoseJweContentEncryptionAlgorithm {
    A128_GCM,
    A192_GCM,
    A256_GCM,
    ;
    public companion object {
        @JvmStatic
        public fun fromContract(value: me.really.jose.v1.JoseJweContentEncryptionAlgorithm?): ReallyMeJoseJweContentEncryptionAlgorithm = when (value) {
            me.really.jose.v1.JoseJweContentEncryptionAlgorithm.JOSE_JWE_CONTENT_ENCRYPTION_ALGORITHM_A128GCM -> A128_GCM
            me.really.jose.v1.JoseJweContentEncryptionAlgorithm.JOSE_JWE_CONTENT_ENCRYPTION_ALGORITHM_A192GCM -> A192_GCM
            me.really.jose.v1.JoseJweContentEncryptionAlgorithm.JOSE_JWE_CONTENT_ENCRYPTION_ALGORITHM_A256GCM -> A256_GCM
            else -> throw ReallyMeJoseException.JoseFailure(ReallyMeJoseErrorBranch.PROVIDER, ReallyMeJoseErrorReason.PROVIDER_UNSUPPORTED)
        }
    }
}

internal fun protoContentEncryptionAlgorithm(value: ReallyMeJoseJweContentEncryptionAlgorithm): me.really.jose.v1.JoseJweContentEncryptionAlgorithm = when (value) {
    ReallyMeJoseJweContentEncryptionAlgorithm.A128_GCM -> me.really.jose.v1.JoseJweContentEncryptionAlgorithm.JOSE_JWE_CONTENT_ENCRYPTION_ALGORITHM_A128GCM
    ReallyMeJoseJweContentEncryptionAlgorithm.A192_GCM -> me.really.jose.v1.JoseJweContentEncryptionAlgorithm.JOSE_JWE_CONTENT_ENCRYPTION_ALGORITHM_A192GCM
    ReallyMeJoseJweContentEncryptionAlgorithm.A256_GCM -> me.really.jose.v1.JoseJweContentEncryptionAlgorithm.JOSE_JWE_CONTENT_ENCRYPTION_ALGORITHM_A256GCM
}

public enum class ReallyMeJoseJweCompressionAlgorithm {
    DEFLATE,
    ;
    public companion object {
        @JvmStatic
        public fun fromContract(value: me.really.jose.v1.JoseJweCompressionAlgorithm?): ReallyMeJoseJweCompressionAlgorithm = when (value) {
            me.really.jose.v1.JoseJweCompressionAlgorithm.JOSE_JWE_COMPRESSION_ALGORITHM_DEFLATE -> DEFLATE
            else -> throw ReallyMeJoseException.JoseFailure(ReallyMeJoseErrorBranch.PROVIDER, ReallyMeJoseErrorReason.PROVIDER_UNSUPPORTED)
        }
    }
}

internal fun protoCompressionAlgorithm(value: ReallyMeJoseJweCompressionAlgorithm): me.really.jose.v1.JoseJweCompressionAlgorithm = when (value) {
    ReallyMeJoseJweCompressionAlgorithm.DEFLATE -> me.really.jose.v1.JoseJweCompressionAlgorithm.JOSE_JWE_COMPRESSION_ALGORITHM_DEFLATE
}
