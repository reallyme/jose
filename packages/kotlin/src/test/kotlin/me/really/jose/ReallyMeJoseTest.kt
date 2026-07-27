// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

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
