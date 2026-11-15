// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

package me.really.jose

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue
import me.really.jose.v1.JoseJweEncryptRequest

class ContractParityTest {
    @Test
    fun algorithmViewsAreTotalAndRejectUnspecifiedAndUnknown() {
        for (value in ReallyMeJoseSignatureAlgorithm.entries) {
            assertEquals(value, ReallyMeJoseSignatureAlgorithm.fromContract(protoSignatureAlgorithm(value)))
        }
        for (value in ReallyMeJoseJweKeyManagementAlgorithm.entries) {
            assertEquals(value, ReallyMeJoseJweKeyManagementAlgorithm.fromContract(protoKeyManagementAlgorithm(value)))
        }
        for (value in ReallyMeJoseJweContentEncryptionAlgorithm.entries) {
            assertEquals(value, ReallyMeJoseJweContentEncryptionAlgorithm.fromContract(protoContentEncryptionAlgorithm(value)))
        }
        for (value in ReallyMeJoseJweCompressionAlgorithm.entries) {
            assertEquals(value, ReallyMeJoseJweCompressionAlgorithm.fromContract(protoCompressionAlgorithm(value)))
        }
        for (raw in listOf(0, -1, Int.MAX_VALUE)) {
            val attempts: List<() -> Unit> = listOf(
                { ReallyMeJoseSignatureAlgorithm.fromContract(me.really.jose.v1.JoseSignatureAlgorithm.forNumber(raw)) },
                { ReallyMeJoseJweKeyManagementAlgorithm.fromContract(me.really.jose.v1.JoseJweKeyManagementAlgorithm.forNumber(raw)) },
                { ReallyMeJoseJweContentEncryptionAlgorithm.fromContract(me.really.jose.v1.JoseJweContentEncryptionAlgorithm.forNumber(raw)) },
                { ReallyMeJoseJweCompressionAlgorithm.fromContract(me.really.jose.v1.JoseJweCompressionAlgorithm.forNumber(raw)) },
            )
            for (attempt in attempts) {
                val failure = assertFailsWith<ReallyMeJoseException.JoseFailure> { attempt() }
                assertEquals(ReallyMeJoseErrorReason.PROVIDER_UNSUPPORTED, failure.reason)
            }
        }
    }

    @Test
    fun explicitEmptyHeadersKeepPresenceAndPolicyLimitsMatchSchema() {
        val request = JoseJweEncryptRequest.newBuilder().setKid("").setApu(com.google.protobuf.ByteString.EMPTY).build()
        val decoded = JoseJweEncryptRequest.parseFrom(request.toByteArray())
        assertTrue(decoded.hasKid())
        assertTrue(decoded.hasApu())
        assertEquals("", decoded.kid)
        protoJwtHeaderPolicy(ReallyMeJoseJwtHeaderPolicy(false, false, List(JoseContractValues.ACCEPTED_TYPE_VALUES) { "JWT" }))
        val failure = assertFailsWith<ReallyMeJoseException.JoseFailure> {
            protoJwtHeaderPolicy(ReallyMeJoseJwtHeaderPolicy(false, false, List(JoseContractValues.ACCEPTED_TYPE_VALUES + 1) { "JWT" }))
        }
        assertEquals(ReallyMeJoseErrorReason.COMMON_RESOURCE_LIMIT_EXCEEDED, failure.reason)
    }
}
