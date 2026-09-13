// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//

package me.really.jose

import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith

private const val KNOWN_COMPACT: String =
    "eyJhbGciOiJFZERTQSJ9.cmVhbGx5bWUtY29uZm9ybWFuY2UtY2lk." +
        "V-aqJPOjWYJ7P8hK-oyiqUsjO1kjXPsUp7YbXcTu2oXEJtElJoidqgSomnnsVBdING1fzza_rZwkdaE1RRYGDg"
private const val PUBLIC_KEY_HEX: String =
    "fd1724385aa0c75b64fb78cd602fa1d991fdebf76b13c58ed702eac835e9f618"
private const val PRIVATE_KEY_HEX: String =
    "0909090909090909090909090909090909090909090909090909090909090909"

class ReallyMeJoseTest {
    @Test
    fun knownAnswerAndTypedFailure() {
        val publicKey = decodeHex(PUBLIC_KEY_HEX)
        ReallyMeJose.verifyJws(ReallyMeJoseSignatureAlgorithm.ED_DSA, KNOWN_COMPACT, publicKey)

        val failure = assertFailsWith<ReallyMeJoseException.JoseFailure> {
            ReallyMeJose.verifyJws(
                ReallyMeJoseSignatureAlgorithm.ED_DSA,
                KNOWN_COMPACT.replace("V-aq", "A-aq"),
                publicKey,
            )
        }
        assertEquals(ReallyMeJoseErrorBranch.PRIMITIVE, failure.branch)
        assertEquals(ReallyMeJoseErrorReason.JWS_INVALID_SIGNATURE, failure.reason)
    }

    @Test
    fun jwsAndJwtRoundTripsUseCanonicalRoute() {
        val privateKey = decodeHex(PRIVATE_KEY_HEX)
        val publicKey = decodeHex(PUBLIC_KEY_HEX)
        val signed = ReallyMeJose.signJws(
            ReallyMeJoseSignatureAlgorithm.ED_DSA,
            privateKey,
            "stage-15-jws".toByteArray(),
        )
        ReallyMeJose.verifyJws(ReallyMeJoseSignatureAlgorithm.ED_DSA, signed, publicKey)

        val jwk =
            """{"alg":"EdDSA","crv":"Ed25519","kid":"k-ed","kty":"OKP","use":"sig","x":"_RckOFqgx1tk-3jNYC-h2ZH96_drE8WO1wLqyDXp9hg"}"""
                .toByteArray()
        val claims = """{"sub":"stage-15-signed"}""".toByteArray()
        val jwt = ReallyMeJose.signJwt(claims, jwk, privateKey)
        assertContentEquals(
            claims,
            ReallyMeJose.verifyJwt(jwt, jwk, publicKey, signatureOnly = true),
        )
    }

    @Test
    fun unsignedJwtAndDirectJweRoundTrip() {
        val claims = """{"sub":"stage-15"}""".toByteArray()
        val unsigned = ReallyMeJose.encodeUnsignedJwt(claims)
        assertContentEquals(claims, ReallyMeJose.decodeUnsignedJwt(unsigned))

        val key = ByteArray(16) { 8 }
        val plaintext = "stage-15 plaintext".toByteArray()
        val encrypted = ReallyMeJose.encryptJwe(
            ReallyMeJoseJweKeyManagementAlgorithm.DIRECT,
            ReallyMeJoseJweContentEncryptionAlgorithm.A128_GCM,
            key,
            plaintext,
            keyIdentifier = "stage-15",
        )
        val decrypted = ReallyMeJose.decryptJwe(
            encrypted,
            ReallyMeJoseJweKeyManagementAlgorithm.DIRECT,
            ReallyMeJoseJweContentEncryptionAlgorithm.A128_GCM,
            key,
            ReallyMeJoseJweHeaderPolicy(
                requireKeyIdentifier = true,
                expectedKeyIdentifier = "stage-15",
            ),
        )
        assertContentEquals(plaintext, decrypted)
    }

    @Test
    fun signedLongTimesCannotBecomeUnsignedFarFutureTimes() {
        val jwk =
            """{"alg":"EdDSA","crv":"Ed25519","kty":"OKP","x":"_RckOFqgx1tk-3jNYC-h2ZH96_drE8WO1wLqyDXp9hg"}"""
                .toByteArray()
        val privateKey = decodeHex(PRIVATE_KEY_HEX)
        val publicKey = decodeHex(PUBLIC_KEY_HEX)
        val claims = """{"aud":"test","nbf":1000}""".toByteArray()
        try {
            val token = ReallyMeJose.signJwt(claims, jwk, privateKey)
            for (now in listOf(-1L, Long.MIN_VALUE, 0L)) {
                val failure = assertFailsWith<ReallyMeJoseException.JoseFailure> {
                    ReallyMeJose.verifyJwt(
                        token, jwk, publicKey,
                        temporalPolicy = ReallyMeJoseJwtTemporalPolicy(
                            false, false, false, 0, 0, now, "test",
                        ),
                    )
                }
                assertEquals(ReallyMeJoseErrorReason.JWT_INVALID_VERIFICATION_TIME, failure.reason)
            }
            for ((clockSkew, issuedAtSkew) in listOf(-1L to 0L, 0L to -1L)) {
                val failure = assertFailsWith<ReallyMeJoseException.JoseFailure> {
                    ReallyMeJose.verifyJwt(
                        token, jwk, publicKey,
                        temporalPolicy = ReallyMeJoseJwtTemporalPolicy(
                            false, false, false, clockSkew, issuedAtSkew, 1000, "test",
                        ),
                    )
                }
                assertEquals(ReallyMeJoseErrorReason.JWT_INVALID_VERIFICATION_POLICY, failure.reason)
            }
            val future = ReallyMeJose.verifyJwt(
                token, jwk, publicKey,
                temporalPolicy = ReallyMeJoseJwtTemporalPolicy(
                    false, false, false, 0, 0, 1000, "test",
                ),
            )
            assertContentEquals(claims, future)
            future.fill(0)
        } finally {
            privateKey.fill(0)
            claims.fill(0)
            jwk.fill(0)
        }
    }

    @Test
    fun malformedUtf16CannotBeReplacedInProtectedMetadata() {
        val key = ByteArray(16) { 8 }
        try {
            for (metadata in listOf("\ud800", "\udc00", "a\ud800z")) {
                assertFailsWith<ReallyMeJoseException.InvalidInput> {
                    ReallyMeJose.encryptJwe(
                        ReallyMeJoseJweKeyManagementAlgorithm.DIRECT,
                        ReallyMeJoseJweContentEncryptionAlgorithm.A128_GCM,
                        key, ByteArray(0), keyIdentifier = metadata,
                    )
                }
            }
            // An ill-formed expected identifier must not match a real "?"
            // identifier after the protobuf encoder replaces its surrogate.
            val replacementToken = ReallyMeJose.encryptJwe(
                ReallyMeJoseJweKeyManagementAlgorithm.DIRECT,
                ReallyMeJoseJweContentEncryptionAlgorithm.A128_GCM,
                key, ByteArray(0), keyIdentifier = "?",
            )
            assertFailsWith<ReallyMeJoseException.InvalidInput> {
                ReallyMeJose.decryptJwe(
                    replacementToken, ReallyMeJoseJweKeyManagementAlgorithm.DIRECT,
                    ReallyMeJoseJweContentEncryptionAlgorithm.A128_GCM,
                    key, ReallyMeJoseJweHeaderPolicy(expectedKeyIdentifier = "\ud800"),
                )
            }
            val valid = "\ud83d\udd10"
            val token = ReallyMeJose.encryptJwe(
                ReallyMeJoseJweKeyManagementAlgorithm.DIRECT,
                ReallyMeJoseJweContentEncryptionAlgorithm.A128_GCM,
                key, ByteArray(0), keyIdentifier = valid,
            )
            assertContentEquals(ByteArray(0), ReallyMeJose.decryptJwe(
                token, ReallyMeJoseJweKeyManagementAlgorithm.DIRECT,
                ReallyMeJoseJweContentEncryptionAlgorithm.A128_GCM,
                key, ReallyMeJoseJweHeaderPolicy(expectedKeyIdentifier = valid),
            ))
        } finally {
            key.fill(0)
        }
    }

    @Test
    fun everyKnownErrorReasonMustMatchItsBranch() {
        // Exercise the private decoder directly without widening the production
        // API or substituting a process-global JNI provider.
        val decode = Class.forName("me.really.jose.OperationSupportKt")
            .getDeclaredMethod("sdkError", me.really.jose.v1.JoseError::class.java)
        decode.isAccessible = true
        for (reason in ReallyMeJoseErrorReason.entries) {
            val expected = when (reason.code) {
                in 800..802 -> ReallyMeJoseErrorBranch.PROVIDER
                in 900..902 -> ReallyMeJoseErrorBranch.BACKEND
                else -> ReallyMeJoseErrorBranch.PRIMITIVE
            }
            for (branch in ReallyMeJoseErrorBranch.entries) {
                val error = me.really.jose.v1.JoseError.newBuilder()
                when (branch) {
                    ReallyMeJoseErrorBranch.PRIMITIVE -> error.setPrimitive(
                        me.really.jose.v1.JosePrimitiveError.newBuilder().setReasonValue(reason.code),
                    )
                    ReallyMeJoseErrorBranch.PROVIDER -> error.setProvider(
                        me.really.jose.v1.JoseProviderError.newBuilder().setReasonValue(reason.code),
                    )
                    ReallyMeJoseErrorBranch.BACKEND -> error.setBackend(
                        me.really.jose.v1.JoseBackendError.newBuilder().setReasonValue(reason.code),
                    )
                }
                if (branch == expected) {
                    val actual = kotlin.test.assertIs<ReallyMeJoseException.JoseFailure>(
                        decode.invoke(null, error.build()),
                    )
                    assertEquals(branch, actual.branch)
                    assertEquals(reason, actual.reason)
                } else {
                    val failure = assertFailsWith<java.lang.reflect.InvocationTargetException> {
                        decode.invoke(null, error.build())
                    }
                    kotlin.test.assertIs<ReallyMeJoseException.MalformedProviderResponse>(failure.cause)
                }
            }
        }
    }

    @Test
    fun utf8LengthMatchesJdkForEveryUnicodeScalar() {
        val measure = Class.forName("me.really.jose.OperationSupportKt")
            .getDeclaredMethod("utf8Length", String::class.java)
        measure.isAccessible = true
        // Group scalars to test transitions between UTF-8 widths and surrogate
        // pairs without a million reflective calls.
        for (start in 0..0x10ffff step 1024) {
            val value = buildString {
                for (scalar in start..minOf(start + 1023, 0x10ffff)) {
                    if (scalar !in 0xd800..0xdfff) appendCodePoint(scalar)
                }
            }
            assertEquals(value.toByteArray(Charsets.UTF_8).size, measure.invoke(null, value))
        }
    }

    @Test
    fun oversizedManagedInputFailsBeforeJniCopy() {
        val oversized = "a".repeat(1_398_104)
        val failure = assertFailsWith<ReallyMeJoseException.JoseFailure> {
            ReallyMeJose.verifyJws(
                ReallyMeJoseSignatureAlgorithm.ED_DSA,
                oversized,
                ByteArray(0),
            )
        }
        assertEquals(ReallyMeJoseErrorReason.COMMON_RESOURCE_LIMIT_EXCEEDED, failure.reason)
    }
}

private fun decodeHex(value: String): ByteArray {
    require(value.length % 2 == 0)
    return ByteArray(value.length / 2) { index ->
        value.substring(index * 2, index * 2 + 2).toInt(16).toByte()
    }
}
