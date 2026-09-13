// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//

package me.really.jose

import com.google.protobuf.ByteString
import com.google.protobuf.UnsafeByteOperations
import me.really.jose.v1.JoseCompactResult
import me.really.jose.v1.JoseError
import me.really.jose.v1.JoseExpectedBytes
import me.really.jose.v1.JoseExpectedString
import me.really.jose.v1.JoseJweContentEncryptionAlgorithm
import me.really.jose.v1.JoseJweDecryptResponse
import me.really.jose.v1.JoseJweEncryptResponse
import me.really.jose.v1.JoseJweHeaderValidationPolicy
import me.really.jose.v1.JoseJweKeyManagementAlgorithm
import me.really.jose.v1.JoseJwtDecodeUnsignedResponse
import me.really.jose.v1.JoseJwtEncodeUnsignedResponse
import me.really.jose.v1.JoseJwtHeaderValidationPolicy
import me.really.jose.v1.JoseJwtSignResponse
import me.really.jose.v1.JoseJwtTemporalValidationPolicy
import me.really.jose.v1.JoseJwtVerifyResponse
import me.really.jose.v1.JoseSignatureAlgorithm
import me.really.jose.v1.JoseJwsSignResponse
import me.really.jose.v1.JoseJwsVerifyResponse

internal inline fun <T> withOwned(vararg values: ByteArray, action: (List<ByteArray>) -> T): T {
    val maximum = ReallyMeJoseRustNativeProvider.binaryRequestLimit()
    var remaining = maximum
    for (value in values) {
        if (value.size > remaining) throw resourceLimit()
        remaining -= value.size
    }
    val owned = ArrayList<ByteArray>(values.size)
    return try {
        for (value in values) owned.add(value.copyOf())
        action(owned)
    } finally {
        owned.forEach { it.fill(0) }
    }
}

internal fun wrap(value: ByteArray): ByteString = UnsafeByteOperations.unsafeWrap(value)

internal fun utf8Length(value: String): Int {
    // Encoding to a temporary array both copies metadata and silently replaces
    // unpaired surrogates. Count valid code points before protobuf sees them.
    var length = 0
    var index = 0
    while (index < value.length) {
        val codeUnit = value[index]
        val width = when {
            codeUnit <= '\u007f' -> 1
            codeUnit <= '\u07ff' -> 2
            Character.isHighSurrogate(codeUnit) -> {
                index = Math.addExact(index, 1)
                if (index >= value.length || !Character.isLowSurrogate(value[index])) {
                    throw ReallyMeJoseException.InvalidInput()
                }
                4
            }
            Character.isLowSurrogate(codeUnit) -> throw ReallyMeJoseException.InvalidInput()
            else -> 3
        }
        length = try {
            Math.addExact(length, width)
        } catch (_: ArithmeticException) {
            throw resourceLimit()
        }
        index = Math.addExact(index, 1)
    }
    return length
}

internal fun compact(result: JoseCompactResult): String {
    requireClean(result)
    return result.compact
}

internal fun sdkError(error: JoseError): ReallyMeJoseException.JoseFailure {
    requireClean(error)
    val branch: ReallyMeJoseErrorBranch
    val reasonCode: Int
    when (error.errorCase) {
        JoseError.ErrorCase.PRIMITIVE -> {
            requireClean(error.primitive)
            branch = ReallyMeJoseErrorBranch.PRIMITIVE
            reasonCode = error.primitive.reasonValue
        }
        JoseError.ErrorCase.PROVIDER -> {
            requireClean(error.provider)
            branch = ReallyMeJoseErrorBranch.PROVIDER
            reasonCode = error.provider.reasonValue
        }
        JoseError.ErrorCase.BACKEND -> {
            requireClean(error.backend)
            branch = ReallyMeJoseErrorBranch.BACKEND
            reasonCode = error.backend.reasonValue
        }
        else -> malformed()
    }
    val reason = ReallyMeJoseErrorReason.fromCode(reasonCode) ?: malformed()
    val validBranch = when (branch) {
        ReallyMeJoseErrorBranch.PRIMITIVE -> reasonCode in 100..399 || reasonCode in 700..703
        ReallyMeJoseErrorBranch.PROVIDER -> reasonCode in 800..802
        ReallyMeJoseErrorBranch.BACKEND -> reasonCode in 900..902
    }
    if (!validBranch) malformed()
    return ReallyMeJoseException.JoseFailure(branch, reason)
}

internal fun resourceLimit(): ReallyMeJoseException.JoseFailure = ReallyMeJoseException.JoseFailure(
    ReallyMeJoseErrorBranch.PRIMITIVE,
    ReallyMeJoseErrorReason.COMMON_RESOURCE_LIMIT_EXCEEDED,
)

internal fun malformed(): Nothing = throw ReallyMeJoseException.MalformedProviderResponse()

internal fun requireClean(message: com.google.protobuf.MessageLite) {
    val clean = when (message) {
        is JoseCompactResult -> !message.reallyMeHasUnknownFieldsForValidation()
        is me.really.jose.v1.JoseVerifyResult -> !message.reallyMeHasUnknownFieldsForValidation()
        is me.really.jose.v1.JoseJwtClaimsResult -> !message.reallyMeHasUnknownFieldsForValidation()
        is me.really.jose.v1.JoseJwePlaintextResult -> !message.reallyMeHasUnknownFieldsForValidation()
        is JoseError -> !message.reallyMeHasUnknownFieldsForValidation()
        is me.really.jose.v1.JosePrimitiveError -> !message.reallyMeHasUnknownFieldsForValidation()
        is me.really.jose.v1.JoseProviderError -> !message.reallyMeHasUnknownFieldsForValidation()
        is me.really.jose.v1.JoseBackendError -> !message.reallyMeHasUnknownFieldsForValidation()
        is JoseJwsSignResponse -> !message.reallyMeHasUnknownFieldsForValidation()
        is JoseJwsVerifyResponse -> !message.reallyMeHasUnknownFieldsForValidation()
        is JoseJwtEncodeUnsignedResponse -> !message.reallyMeHasUnknownFieldsForValidation()
        is JoseJwtDecodeUnsignedResponse -> !message.reallyMeHasUnknownFieldsForValidation()
        is JoseJwtSignResponse -> !message.reallyMeHasUnknownFieldsForValidation()
        is JoseJwtVerifyResponse -> !message.reallyMeHasUnknownFieldsForValidation()
        is JoseJweEncryptResponse -> !message.reallyMeHasUnknownFieldsForValidation()
        is JoseJweDecryptResponse -> !message.reallyMeHasUnknownFieldsForValidation()
        else -> false
    }
    if (!clean) malformed()
}

internal fun protoSignatureAlgorithm(value: ReallyMeJoseSignatureAlgorithm): JoseSignatureAlgorithm = when (value) {
    ReallyMeJoseSignatureAlgorithm.ED_DSA -> JoseSignatureAlgorithm.JOSE_SIGNATURE_ALGORITHM_EDDSA
    ReallyMeJoseSignatureAlgorithm.ES256 -> JoseSignatureAlgorithm.JOSE_SIGNATURE_ALGORITHM_ES256
}

internal fun protoKeyManagementAlgorithm(
    value: ReallyMeJoseJweKeyManagementAlgorithm,
): JoseJweKeyManagementAlgorithm = when (value) {
    ReallyMeJoseJweKeyManagementAlgorithm.DIRECT -> JoseJweKeyManagementAlgorithm.JOSE_JWE_KEY_MANAGEMENT_ALGORITHM_DIRECT
    ReallyMeJoseJweKeyManagementAlgorithm.ECDH_ES_P256 -> JoseJweKeyManagementAlgorithm.JOSE_JWE_KEY_MANAGEMENT_ALGORITHM_ECDH_ES_P256
    ReallyMeJoseJweKeyManagementAlgorithm.ECDH_ES_P384 -> JoseJweKeyManagementAlgorithm.JOSE_JWE_KEY_MANAGEMENT_ALGORITHM_ECDH_ES_P384
    ReallyMeJoseJweKeyManagementAlgorithm.ECDH_ES_P521 -> JoseJweKeyManagementAlgorithm.JOSE_JWE_KEY_MANAGEMENT_ALGORITHM_ECDH_ES_P521
}

internal fun protoContentEncryptionAlgorithm(
    value: ReallyMeJoseJweContentEncryptionAlgorithm,
): JoseJweContentEncryptionAlgorithm = when (value) {
    ReallyMeJoseJweContentEncryptionAlgorithm.A128_GCM -> JoseJweContentEncryptionAlgorithm.JOSE_JWE_CONTENT_ENCRYPTION_ALGORITHM_A128GCM
    ReallyMeJoseJweContentEncryptionAlgorithm.A192_GCM -> JoseJweContentEncryptionAlgorithm.JOSE_JWE_CONTENT_ENCRYPTION_ALGORITHM_A192GCM
    ReallyMeJoseJweContentEncryptionAlgorithm.A256_GCM -> JoseJweContentEncryptionAlgorithm.JOSE_JWE_CONTENT_ENCRYPTION_ALGORITHM_A256GCM
}

internal fun protoJwtHeaderPolicy(value: ReallyMeJoseJwtHeaderPolicy): JoseJwtHeaderValidationPolicy {
    for (type in value.acceptedTypeValues) utf8Length(type)
    return JoseJwtHeaderValidationPolicy.newBuilder()
        .setAllowMissingTyp(value.allowMissingType)
        .setAllowEmbeddedKeyHeader(value.allowEmbeddedKeyHeader)
        .addAllAcceptedTypValues(value.acceptedTypeValues)
        .build()
}

internal fun protoJwtTemporalPolicy(value: ReallyMeJoseJwtTemporalPolicy): JoseJwtTemporalValidationPolicy {
    // Protobuf uint64 setters accept signed Long bit patterns. Reject negative
    // times before serialization can reinterpret them as far-future dates.
    if (value.nowUnix <= 0) {
        throw ReallyMeJoseException.JoseFailure(
            ReallyMeJoseErrorBranch.PRIMITIVE,
            ReallyMeJoseErrorReason.JWT_INVALID_VERIFICATION_TIME,
        )
    }
    if (value.clockSkewSeconds < 0 || value.maximumFutureIssuedAtSkewSeconds < 0) {
        throw ReallyMeJoseException.JoseFailure(
            ReallyMeJoseErrorBranch.PRIMITIVE,
            ReallyMeJoseErrorReason.JWT_INVALID_VERIFICATION_POLICY,
        )
    }
    utf8Length(value.expectedAudience)
    value.expectedIssuer?.let { utf8Length(it) }
    value.expectedSubject?.let { utf8Length(it) }
    return JoseJwtTemporalValidationPolicy.newBuilder()
        .setRequireExp(value.requireExpiration)
        .setRequireNbf(value.requireNotBefore)
        .setRequireIat(value.requireIssuedAt)
        .setClockSkewSeconds(value.clockSkewSeconds)
        .setMaxFutureIatSkewSeconds(value.maximumFutureIssuedAtSkewSeconds)
        .setNowUnix(value.nowUnix)
        .setExpectedAudience(value.expectedAudience)
        .setExpectedIssuer(value.expectedIssuer ?: "")
        .setExpectedSubject(value.expectedSubject ?: "")
        .build()
}

internal fun protoJweHeaderPolicy(
    value: ReallyMeJoseJweHeaderPolicy,
    owned: MutableList<ByteArray>,
): JoseJweHeaderValidationPolicy {
    value.expectedKeyIdentifier?.let { utf8Length(it) }
    value.expectedType?.let { utf8Length(it) }
    value.expectedContentType?.let { utf8Length(it) }
    val builder = JoseJweHeaderValidationPolicy.newBuilder().setRequireKid(value.requireKeyIdentifier)
    if (value.expectedKeyIdentifier != null) {
        builder.setExpectedKid(JoseExpectedString.newBuilder().setValue(value.expectedKeyIdentifier).build())
    }
    if (value.expectedType != null) {
        builder.setExpectedTyp(JoseExpectedString.newBuilder().setValue(value.expectedType).build())
    }
    if (value.expectedContentType != null) {
        builder.setExpectedCty(JoseExpectedString.newBuilder().setValue(value.expectedContentType).build())
    }
    value.agreementPartyUInfoCopy()?.let { bytes ->
        owned.add(bytes)
        builder.setExpectedApu(JoseExpectedBytes.newBuilder().setValue(wrap(bytes)).build())
    }
    value.agreementPartyVInfoCopy()?.let { bytes ->
        owned.add(bytes)
        builder.setExpectedApv(JoseExpectedBytes.newBuilder().setValue(wrap(bytes)).build())
    }
    return builder.build()
}
