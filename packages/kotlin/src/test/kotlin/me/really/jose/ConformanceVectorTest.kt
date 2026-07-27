// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

package me.really.jose

import com.google.gson.JsonElement
import com.google.gson.JsonObject
import com.google.gson.JsonParser
import java.io.InputStreamReader
import me.really.jose.v1.JoseError
import me.really.jose.v1.JoseJwsVerifyRequest
import me.really.jose.v1.JoseJwtDecodeUnsignedRequest
import me.really.jose.v1.JoseJwtTemporalValidationPolicy
import me.really.jose.v1.JoseJwtVerifyRequest
import me.really.jose.v1.JoseOperationRequest
import me.really.jose.v1.JoseOperationResponse
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue

class ConformanceVectorTest {
    @Test
    fun completeJwsCorpusPreservesTypedResults() {
        vectorCases("jws-compact.json").forEach(::runJwsCase)
    }

    @Test
    fun completeJwtCorporaPreserveClaimsAndTypedFailures() {
        vectorCases("signed-jwt.json").forEach(::runSignedJwtCase)
        vectorCases("unsigned-jwt.json").forEach(::runUnsignedJwtCase)
    }

    @Test
    fun completeJweCorpusPreservesPlaintextAndTypedFailures() {
        vectorCases("jwe-compact.json").forEach(::runJweCase)
    }

    @Test
    fun panvaInteropCorpusUsesTheSameTypedFacade() {
        vectorCases("panva-jose.json").forEach { vector ->
            when (requiredString(vector, "format")) {
                "jws-compact" -> runJwsCase(vector)
                "signed-jwt", "jwt-compact" -> runSignedJwtCase(vector)
                "jwe-compact" -> runJweCase(vector)
                else -> throw AssertionError("unsupported conformance vector format")
            }
        }
    }

    @Test
    fun binaryAndProtoJsonWireRoutesAreByteIdentical() {
        val vector = vectorCases("unsigned-jwt.json").first()
        val compact = requiredString(vector, "compact")
        val request = JoseOperationRequest.newBuilder()
            .setJwtDecodeUnsigned(JoseJwtDecodeUnsignedRequest.newBuilder().setCompact(compact))
            .build()
        val binary = request.toByteArray()
        val json = """{"jwtDecodeUnsigned":{"compact":"$compact"}}""".toByteArray()
        val binaryResponse = ReallyMeJose.executeWireRequest(binary)
        val jsonResponse = ReallyMeJose.executeWireJsonRequest(json)
        try {
            assertContentEquals(binaryResponse, jsonResponse)
        } finally {
            binary.fill(0)
            json.fill(0)
            binaryResponse.fill(0)
            jsonResponse.fill(0)
        }
    }

    @Test
    fun hostileWireInputsAndProviderSelectionPreserveExactErrors() {
        val malformedBinary = byteArrayOf(0xff.toByte())
        val malformedJson = """{"jwtDecodeUnsigned":""".toByteArray()
        val binaryResponse = ReallyMeJose.executeWireRequest(malformedBinary)
        val jsonResponse = ReallyMeJose.executeWireJsonRequest(malformedJson)
        try {
            assertBoundaryError(binaryResponse, ReallyMeJoseErrorReason.COMMON_MALFORMED_PROTOBUF)
            assertBoundaryError(jsonResponse, ReallyMeJoseErrorReason.COMMON_MALFORMED_JSON)
        } finally {
            malformedBinary.fill(0)
            malformedJson.fill(0)
            binaryResponse.fill(0)
            jsonResponse.fill(0)
        }

        val unsupportedRequest = JoseOperationRequest.newBuilder()
            .setJwsVerify(JoseJwsVerifyRequest.newBuilder().setAlgorithmValue(999))
            .build().toByteArray()
        val unsupportedResponse = ReallyMeJose.executeWireRequest(unsupportedRequest)
        try {
            val response = JoseOperationResponse.parseFrom(unsupportedResponse)
            assertEquals(JoseOperationResponse.ResponseCase.JWS_VERIFY, response.responseCase)
            assertEquals(ReallyMeJoseErrorBranch.PROVIDER, branch(response.jwsVerify.error))
            assertEquals(ReallyMeJoseErrorReason.PROVIDER_UNSUPPORTED, reason(response.jwsVerify.error))
        } finally {
            unsupportedRequest.fill(0)
            unsupportedResponse.fill(0)
        }
    }

    @Test
    fun temporalWirePolicyRequiresExplicitVerificationTime() {
        val vector = vectorCases("signed-jwt.json").first()
        val jwk = requiredObject(vector, "verification_jwk").toString().toByteArray()
        val publicKey = decodeVectorHex(requiredString(vector, "public_key_hex"))
        val request = JoseOperationRequest.newBuilder().setJwtVerify(
            JoseJwtVerifyRequest.newBuilder()
                .setCompact(requiredString(vector, "compact"))
                .setJwkJson(com.google.protobuf.ByteString.copyFrom(jwk))
                .setPublicKey(com.google.protobuf.ByteString.copyFrom(publicKey))
                .setTemporalPolicy(
                    JoseJwtTemporalValidationPolicy.newBuilder().setRequireExp(true),
                ),
        ).build().toByteArray()
        val responseBytes = ReallyMeJose.executeWireRequest(request)
        try {
            val response = JoseOperationResponse.parseFrom(responseBytes)
            assertEquals(JoseOperationResponse.ResponseCase.JWT_VERIFY, response.responseCase)
            assertEquals(ReallyMeJoseErrorBranch.PRIMITIVE, branch(response.jwtVerify.error))
            assertEquals(
                ReallyMeJoseErrorReason.JWT_INVALID_VERIFICATION_TIME,
                reason(response.jwtVerify.error),
            )
        } finally {
            jwk.fill(0)
            publicKey.fill(0)
            request.fill(0)
            responseBytes.fill(0)
        }
    }
}

private fun assertBoundaryError(bytes: ByteArray, expected: ReallyMeJoseErrorReason) {
    val response = JoseOperationResponse.parseFrom(bytes)
    assertEquals(JoseOperationResponse.ResponseCase.BOUNDARY_ERROR, response.responseCase)
    assertEquals(ReallyMeJoseErrorBranch.PRIMITIVE, branch(response.boundaryError))
    assertEquals(expected, reason(response.boundaryError))
}

private fun branch(error: JoseError): ReallyMeJoseErrorBranch = when (error.errorCase) {
    JoseError.ErrorCase.PRIMITIVE -> ReallyMeJoseErrorBranch.PRIMITIVE
    JoseError.ErrorCase.PROVIDER -> ReallyMeJoseErrorBranch.PROVIDER
    JoseError.ErrorCase.BACKEND -> ReallyMeJoseErrorBranch.BACKEND
    else -> throw AssertionError("wire error branch is missing")
}

private fun reason(error: JoseError): ReallyMeJoseErrorReason {
    val code = when (error.errorCase) {
        JoseError.ErrorCase.PRIMITIVE -> error.primitive.reasonValue
        JoseError.ErrorCase.PROVIDER -> error.provider.reasonValue
        JoseError.ErrorCase.BACKEND -> error.backend.reasonValue
        else -> throw AssertionError("wire error branch is missing")
    }
    return ReallyMeJoseErrorReason.entries.firstOrNull { it.code == code }
        ?: throw AssertionError("wire error reason is unknown")
}

private fun runJwsCase(vector: JsonObject) {
    val algorithm = when (requiredString(vector, "alg")) {
        "EdDSA" -> ReallyMeJoseSignatureAlgorithm.ED_DSA
        "ES256" -> ReallyMeJoseSignatureAlgorithm.ES256
        else -> throw AssertionError("unsupported JWS vector algorithm")
    }
    val publicKey = decodeVectorHex(requiredString(vector, "public_key_hex"))
    try {
        val expectedError = optionalString(vector, "expected_error")
        if (vector.get("expected_valid")?.asBoolean == true) {
            ReallyMeJose.verifyJws(algorithm, requiredString(vector, "compact"), publicKey)
        } else {
            assertTypedFailure(expectedJwsReason(requireNotNull(expectedError))) {
                ReallyMeJose.verifyJws(algorithm, requiredString(vector, "compact"), publicKey)
            }
        }
    } finally {
        publicKey.fill(0)
    }
}

private fun runSignedJwtCase(vector: JsonObject) {
    val publicKey = decodeVectorHex(requiredString(vector, "public_key_hex"))
    val jwk = requiredObject(vector, "verification_jwk").toString().toByteArray(Charsets.UTF_8)
    try {
        val temporalPolicy = vector.get("now_unix")?.takeUnless(JsonElement::isJsonNull)?.asLong?.let { now ->
            assertEquals("strict", optionalString(vector, "temporal_policy") ?: "strict")
            ReallyMeJoseJwtTemporalPolicy(
                true,
                false,
                false,
                60,
                60,
                now,
                "did:me:verifier",
            )
        }
        val expected = vector.get("expected_claims_json")
        val expectedError = optionalString(vector, "expected_error")
        if (expected != null && !expected.isJsonNull) {
            val actual = ReallyMeJose.verifyJwt(
                requiredString(vector, "compact"), jwk, publicKey,
                temporalPolicy = temporalPolicy,
                signatureOnly = temporalPolicy == null,
            )
            try {
                assertEquals(expected, parseJsonBytes(actual))
            } finally {
                actual.fill(0)
            }
        } else {
            assertTypedFailure(expectedJwtReason(requireNotNull(expectedError))) {
                ReallyMeJose.verifyJwt(
                    requiredString(vector, "compact"), jwk, publicKey,
                    temporalPolicy = temporalPolicy,
                    signatureOnly = temporalPolicy == null,
                ).fill(0)
            }
        }
    } finally {
        jwk.fill(0)
        publicKey.fill(0)
    }
}

private fun runUnsignedJwtCase(vector: JsonObject) {
    val expected = vector.get("expected_claims_json")
    val expectedError = optionalString(vector, "expected_error")
    if (expected != null && !expected.isJsonNull) {
        val actual = ReallyMeJose.decodeUnsignedJwt(requiredString(vector, "compact"))
        try {
            assertEquals(expected, parseJsonBytes(actual))
        } finally {
            actual.fill(0)
        }
    } else {
        assertTypedFailure(expectedJwtReason(requireNotNull(expectedError))) {
            ReallyMeJose.decodeUnsignedJwt(requiredString(vector, "compact")).fill(0)
        }
    }
}

private fun runJweCase(vector: JsonObject) {
    val keyHex = optionalString(vector, "recipient_private_key_hex")
        ?: optionalString(vector, "cek_hex")
        ?: throw AssertionError("JWE vector key is missing")
    val key = decodeVectorHex(keyHex)
    try {
        val keyManagement = when (requiredString(vector, "alg")) {
            "ECDH-ES" -> when (key.size) {
                32 -> ReallyMeJoseJweKeyManagementAlgorithm.ECDH_ES_P256
                48 -> ReallyMeJoseJweKeyManagementAlgorithm.ECDH_ES_P384
                66 -> ReallyMeJoseJweKeyManagementAlgorithm.ECDH_ES_P521
                else -> throw AssertionError("unsupported ECDH-ES vector key length")
            }
            else -> ReallyMeJoseJweKeyManagementAlgorithm.DIRECT
        }
        val contentEncryption = when (requiredString(vector, "enc")) {
            "A192GCM" -> ReallyMeJoseJweContentEncryptionAlgorithm.A192_GCM
            "A256GCM" -> ReallyMeJoseJweContentEncryptionAlgorithm.A256_GCM
            else -> ReallyMeJoseJweContentEncryptionAlgorithm.A128_GCM
        }
        val expected = vector.get("expected_plaintext_json")
        val expectedError = optionalString(vector, "expected_error")
        if (expected != null && !expected.isJsonNull) {
            val actual = ReallyMeJose.decryptJwe(
                requiredString(vector, "compact"), keyManagement, contentEncryption, key,
            )
            try {
                assertEquals(expected, parseJsonBytes(actual))
            } finally {
                actual.fill(0)
            }
        } else {
            assertTypedFailure(expectedJweReason(requireNotNull(expectedError))) {
                ReallyMeJose.decryptJwe(
                    requiredString(vector, "compact"), keyManagement, contentEncryption, key,
                ).fill(0)
            }
        }
    } finally {
        key.fill(0)
    }
}

private fun assertTypedFailure(
    reason: ReallyMeJoseErrorReason,
    operation: () -> Unit,
) {
    val failure = assertFailsWith<ReallyMeJoseException.JoseFailure>(block = operation)
    assertEquals(ReallyMeJoseErrorBranch.PRIMITIVE, failure.branch)
    assertEquals(reason, failure.reason)
}

private fun expectedJwsReason(name: String): ReallyMeJoseErrorReason = when (name) {
    "InvalidCompactEncoding" -> ReallyMeJoseErrorReason.JWS_INVALID_COMPACT
    "HeaderMismatch" -> ReallyMeJoseErrorReason.JWS_HEADER_MISMATCH
    "BadSignatureBase64" -> ReallyMeJoseErrorReason.JWS_BAD_SIGNATURE_BASE64
    "InvalidSignature" -> ReallyMeJoseErrorReason.JWS_INVALID_SIGNATURE
    else -> throw AssertionError("unknown JWS vector error")
}

private fun expectedJwtReason(name: String): ReallyMeJoseErrorReason = when (name.substringBefore(':')) {
    "InvalidJwtFormat" -> ReallyMeJoseErrorReason.JWT_INVALID_COMPACT
    "InvalidHeader" -> ReallyMeJoseErrorReason.JWT_INVALID_HEADER
    "UnsupportedAlgorithm" -> ReallyMeJoseErrorReason.JWT_UNSUPPORTED_ALGORITHM
    "AlgorithmMismatch" -> ReallyMeJoseErrorReason.JWT_ALGORITHM_MISMATCH
    "KeyIdMismatch" -> ReallyMeJoseErrorReason.JWT_KID_POLICY_MISMATCH
    "InvalidSignature" -> ReallyMeJoseErrorReason.JWT_INVALID_SIGNATURE
    "MissingRequiredTemporalClaim" -> ReallyMeJoseErrorReason.JWT_MISSING_REQUIRED_TEMPORAL_CLAIM
    "InvalidTemporalClaimValue" -> ReallyMeJoseErrorReason.JWT_INVALID_TEMPORAL_CLAIM_VALUE
    "Expired" -> ReallyMeJoseErrorReason.JWT_EXPIRED
    "NotYetValid" -> ReallyMeJoseErrorReason.JWT_NOT_YET_VALID
    "IssuedAtInFuture" -> ReallyMeJoseErrorReason.JWT_ISSUED_AT_IN_FUTURE
    else -> throw AssertionError("unknown JWT vector error")
}

private fun expectedJweReason(name: String): ReallyMeJoseErrorReason = when (name) {
    "InvalidCompact" -> ReallyMeJoseErrorReason.JWE_INVALID_COMPACT
    "InvalidEncoding" -> ReallyMeJoseErrorReason.JWE_INVALID_ENCODING
    "InvalidHeader" -> ReallyMeJoseErrorReason.JWE_INVALID_HEADER
    "UnsupportedKeyManagementAlgorithm" -> ReallyMeJoseErrorReason.JWE_UNSUPPORTED_KEY_MANAGEMENT_ALGORITHM
    "UnsupportedContentEncryptionAlgorithm" -> ReallyMeJoseErrorReason.JWE_UNSUPPORTED_CONTENT_ENCRYPTION_ALGORITHM
    "MissingRequiredHeaderParameter" -> ReallyMeJoseErrorReason.JWE_MISSING_REQUIRED_HEADER_PARAMETER
    "HeaderPolicyMismatch" -> ReallyMeJoseErrorReason.JWE_HEADER_POLICY_MISMATCH
    "InvalidEncryptedKey" -> ReallyMeJoseErrorReason.JWE_INVALID_ENCRYPTED_KEY
    "InvalidContentEncryptionKey" -> ReallyMeJoseErrorReason.JWE_INVALID_CONTENT_ENCRYPTION_KEY
    "InvalidContentCipherInput" -> ReallyMeJoseErrorReason.JWE_INVALID_CONTENT_CIPHER_INPUT
    "Decrypt" -> ReallyMeJoseErrorReason.JWE_DECRYPT_FAILED
    "Encrypt" -> ReallyMeJoseErrorReason.JWE_ENCRYPT_FAILED
    "InvalidKeyAgreementKey" -> ReallyMeJoseErrorReason.JWE_INVALID_KEY_AGREEMENT_KEY
    "InvalidPayloadJson" -> ReallyMeJoseErrorReason.JWE_INVALID_PAYLOAD_JSON
    else -> throw AssertionError("unknown JWE vector error")
}

private fun vectorCases(resource: String): List<JsonObject> {
    val stream = requireNotNull(ConformanceVectorTest::class.java.getResourceAsStream("/$resource"))
    val root = InputStreamReader(stream, Charsets.UTF_8).use(JsonParser::parseReader)
    val array = requiredObject(root, "root").getAsJsonArray("cases")
        ?: throw AssertionError("vector cases are missing")
    assertTrue(array.size() > 0)
    return array.map { requiredObject(it, "case") }
}

private fun requiredObject(element: JsonElement, field: String): JsonObject =
    element.takeIf(JsonElement::isJsonObject)?.asJsonObject
        ?: throw AssertionError("vector object is invalid: $field")

private fun requiredObject(value: JsonObject, field: String): JsonObject =
    value.get(field)?.takeIf(JsonElement::isJsonObject)?.asJsonObject
        ?: throw AssertionError("vector object field is invalid: $field")

private fun requiredString(value: JsonObject, field: String): String =
    optionalString(value, field) ?: throw AssertionError("vector string field is missing: $field")

private fun optionalString(value: JsonObject, field: String): String? {
    val element = value.get(field) ?: return null
    if (element.isJsonNull) return null
    if (!element.isJsonPrimitive || !element.asJsonPrimitive.isString) {
        throw AssertionError("vector string field is invalid: $field")
    }
    return element.asString
}

private fun decodeVectorHex(value: String): ByteArray {
    if (value.length % 2 != 0) throw AssertionError("vector hex length is invalid")
    return ByteArray(value.length / 2) { index ->
        value.substring(index * 2, index * 2 + 2).toIntOrNull(16)?.toByte()
            ?: throw AssertionError("vector hex is invalid")
    }
}

private fun parseJsonBytes(value: ByteArray): JsonElement {
    val text = value.toString(Charsets.UTF_8)
    return JsonParser.parseString(text)
}
