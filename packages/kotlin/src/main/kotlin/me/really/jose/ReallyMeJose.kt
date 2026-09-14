// SPDX-FileCopyrightText: 2026 ReallyMe LLC
//
// SPDX-License-Identifier: MIT OR Apache-2.0

package me.really.jose

import com.google.protobuf.CodedInputStream
import com.google.protobuf.InvalidProtocolBufferException
import me.really.jose.v1.JoseJweDecryptRequest
import me.really.jose.v1.JoseJweDecryptResponse
import me.really.jose.v1.JoseJweEncryptRequest
import me.really.jose.v1.JoseJweEncryptResponse
import me.really.jose.v1.JoseJwtDecodeUnsignedRequest
import me.really.jose.v1.JoseJwtDecodeUnsignedResponse
import me.really.jose.v1.JoseJwtEncodeUnsignedRequest
import me.really.jose.v1.JoseJwtEncodeUnsignedResponse
import me.really.jose.v1.JoseJwtSignRequest
import me.really.jose.v1.JoseJwtSignResponse
import me.really.jose.v1.JoseJwtVerifyRequest
import me.really.jose.v1.JoseJwtVerifyResponse
import me.really.jose.v1.JoseOperationContractVersion
import me.really.jose.v1.JoseOperationRequest
import me.really.jose.v1.JoseOperationResponse
import me.really.jose.v1.JoseJwsSignRequest
import me.really.jose.v1.JoseJwsSignResponse
import me.really.jose.v1.JoseJwsVerifyRequest
import me.really.jose.v1.JoseJwsVerifyResponse


private const val MAX_PROTOBUF_RECURSION_DEPTH: Int = 32

/** Typed Kotlin/JVM facade over the canonical Rust JOSE operation contract. */
public object ReallyMeJose {
    @JvmStatic
    public fun signJws(
        algorithm: ReallyMeJoseSignatureAlgorithm,
        privateKey: ByteArray,
        payload: ByteArray,
    ): String = withOwned(privateKey, payload) { owned ->
        requireAggregate(owned[0].size, owned[1].size)
        val operation = JoseJwsSignRequest.newBuilder()
            .setAlgorithm(protoSignatureAlgorithm(algorithm))
            .setPrivateKey(wrap(owned[0]))
            .setPayload(wrap(owned[1]))
            .build()
        val response = execute(JoseOperationRequest.newBuilder().setJwsSign(operation).build())
        if (response.responseCase != JoseOperationResponse.ResponseCase.JWS_SIGN) malformed()
        val selected = response.jwsSign
        requireClean(selected)
        when (selected.outcomeCase) {
            JoseJwsSignResponse.OutcomeCase.RESULT -> compact(selected.result)
            JoseJwsSignResponse.OutcomeCase.ERROR -> throw sdkError(selected.error)
            else -> malformed()
        }
    }

    @JvmStatic
    public fun verifyJws(
        algorithm: ReallyMeJoseSignatureAlgorithm,
        compact: String,
        publicKey: ByteArray,
    ): Unit = withOwned(publicKey) { owned ->
        requireAggregate(utf8Length(compact), owned[0].size)
        val operation = JoseJwsVerifyRequest.newBuilder()
            .setAlgorithm(protoSignatureAlgorithm(algorithm))
            .setCompact(compact)
            .setPublicKey(wrap(owned[0]))
            .build()
        val response = execute(JoseOperationRequest.newBuilder().setJwsVerify(operation).build())
        if (response.responseCase != JoseOperationResponse.ResponseCase.JWS_VERIFY) malformed()
        val selected = response.jwsVerify
        requireClean(selected)
        when (selected.outcomeCase) {
            JoseJwsVerifyResponse.OutcomeCase.RESULT -> requireClean(selected.result)
            JoseJwsVerifyResponse.OutcomeCase.ERROR -> throw sdkError(selected.error)
            else -> malformed()
        }
    }

    @JvmStatic
    public fun encodeUnsignedJwt(claimsJson: ByteArray): String = withOwned(claimsJson) { owned ->
        requireAggregate(owned[0].size)
        val operation = JoseJwtEncodeUnsignedRequest.newBuilder()
            .setClaimsJson(wrap(owned[0]))
            .build()
        val response = execute(JoseOperationRequest.newBuilder().setJwtEncodeUnsigned(operation).build())
        if (response.responseCase != JoseOperationResponse.ResponseCase.JWT_ENCODE_UNSIGNED) malformed()
        val selected = response.jwtEncodeUnsigned
        requireClean(selected)
        when (selected.outcomeCase) {
            JoseJwtEncodeUnsignedResponse.OutcomeCase.RESULT -> compact(selected.result)
            JoseJwtEncodeUnsignedResponse.OutcomeCase.ERROR -> throw sdkError(selected.error)
            else -> malformed()
        }
    }

    @JvmStatic
    public fun decodeUnsignedJwt(compact: String): ByteArray {
        requireAggregate(utf8Length(compact))
        val operation = JoseJwtDecodeUnsignedRequest.newBuilder().setCompact(compact).build()
        val response = execute(JoseOperationRequest.newBuilder().setJwtDecodeUnsigned(operation).build())
        if (response.responseCase != JoseOperationResponse.ResponseCase.JWT_DECODE_UNSIGNED) malformed()
        val selected = response.jwtDecodeUnsigned
        requireClean(selected)
        return when (selected.outcomeCase) {
            JoseJwtDecodeUnsignedResponse.OutcomeCase.RESULT -> {
                requireClean(selected.result)
                selected.result.claimsJson.toByteArray()
            }
            JoseJwtDecodeUnsignedResponse.OutcomeCase.ERROR -> throw sdkError(selected.error)
            else -> malformed()
        }
    }

    @JvmStatic
    @JvmOverloads
    public fun signJwt(
        claimsJson: ByteArray,
        jwkJson: ByteArray,
        privateKey: ByteArray,
        type: String = "",
    ): String = withOwned(claimsJson, jwkJson, privateKey) { owned ->
        requireAggregate(owned[0].size, owned[1].size, owned[2].size, utf8Length(type))
        val operation = JoseJwtSignRequest.newBuilder()
            .setClaimsJson(wrap(owned[0]))
            .setJwkJson(wrap(owned[1]))
            .setPrivateKey(wrap(owned[2]))
            .setTyp(type)
            .build()
        val response = execute(JoseOperationRequest.newBuilder().setJwtSign(operation).build())
        if (response.responseCase != JoseOperationResponse.ResponseCase.JWT_SIGN) malformed()
        val selected = response.jwtSign
        requireClean(selected)
        when (selected.outcomeCase) {
            JoseJwtSignResponse.OutcomeCase.RESULT -> compact(selected.result)
            JoseJwtSignResponse.OutcomeCase.ERROR -> throw sdkError(selected.error)
            else -> malformed()
        }
    }

    @JvmStatic
    @JvmOverloads
    public fun verifyJwt(
        compact: String,
        jwkJson: ByteArray,
        publicKey: ByteArray,
        headerPolicy: ReallyMeJoseJwtHeaderPolicy? = null,
        temporalPolicy: ReallyMeJoseJwtTemporalPolicy? = null,
        signatureOnly: Boolean = false,
    ): ByteArray = withOwned(jwkJson, publicKey) { owned ->
        requireAggregate(utf8Length(compact), owned[0].size, owned[1].size)
        val builder = JoseJwtVerifyRequest.newBuilder()
            .setCompact(compact)
            .setJwkJson(wrap(owned[0]))
            .setPublicKey(wrap(owned[1]))
            .setSignatureOnly(signatureOnly)
        if (headerPolicy != null) builder.setHeaderPolicy(protoJwtHeaderPolicy(headerPolicy))
        if (temporalPolicy != null) builder.setTemporalPolicy(protoJwtTemporalPolicy(temporalPolicy))
        val response = execute(JoseOperationRequest.newBuilder().setJwtVerify(builder.build()).build())
        if (response.responseCase != JoseOperationResponse.ResponseCase.JWT_VERIFY) malformed()
        val selected = response.jwtVerify
        requireClean(selected)
        when (selected.outcomeCase) {
            JoseJwtVerifyResponse.OutcomeCase.RESULT -> {
                requireClean(selected.result)
                selected.result.claimsJson.toByteArray()
            }
            JoseJwtVerifyResponse.OutcomeCase.ERROR -> throw sdkError(selected.error)
            else -> malformed()
        }
    }

    @JvmStatic
    @JvmOverloads
    public fun encryptJwe(
        keyManagementAlgorithm: ReallyMeJoseJweKeyManagementAlgorithm,
        contentEncryptionAlgorithm: ReallyMeJoseJweContentEncryptionAlgorithm,
        key: ByteArray,
        plaintext: ByteArray,
        keyIdentifier: String = "",
        agreementPartyUInfo: ByteArray = ByteArray(0),
        agreementPartyVInfo: ByteArray = ByteArray(0),
        type: String = "",
        contentType: String = "",
    ): String = withOwned(key, plaintext, agreementPartyUInfo, agreementPartyVInfo) { owned ->
        requireAggregate(
            owned[0].size, owned[1].size, utf8Length(keyIdentifier), owned[2].size,
            owned[3].size, utf8Length(type), utf8Length(contentType),
        )
        val operation = JoseJweEncryptRequest.newBuilder()
            .setKeyManagementAlgorithm(protoKeyManagementAlgorithm(keyManagementAlgorithm))
            .setContentEncryptionAlgorithm(protoContentEncryptionAlgorithm(contentEncryptionAlgorithm))
            .setKey(wrap(owned[0]))
            .setPlaintext(wrap(owned[1]))
            .setKid(keyIdentifier)
            .setApu(wrap(owned[2]))
            .setApv(wrap(owned[3]))
            .setTyp(type)
            .setCty(contentType)
            .build()
        val response = execute(JoseOperationRequest.newBuilder().setJweEncrypt(operation).build())
        if (response.responseCase != JoseOperationResponse.ResponseCase.JWE_ENCRYPT) malformed()
        val selected = response.jweEncrypt
        requireClean(selected)
        when (selected.outcomeCase) {
            JoseJweEncryptResponse.OutcomeCase.RESULT -> compact(selected.result)
            JoseJweEncryptResponse.OutcomeCase.ERROR -> throw sdkError(selected.error)
            else -> malformed()
        }
    }

    @JvmStatic
    @JvmOverloads
    public fun decryptJwe(
        compact: String,
        keyManagementAlgorithm: ReallyMeJoseJweKeyManagementAlgorithm,
        contentEncryptionAlgorithm: ReallyMeJoseJweContentEncryptionAlgorithm,
        key: ByteArray,
        headerPolicy: ReallyMeJoseJweHeaderPolicy? = null,
    ): ByteArray = withOwned(key) { owned ->
        requireAggregate(utf8Length(compact), owned[0].size)
        val policyOwned = mutableListOf<ByteArray>()
        try {
            val builder = JoseJweDecryptRequest.newBuilder()
                .setCompact(compact)
                .setKeyManagementAlgorithm(protoKeyManagementAlgorithm(keyManagementAlgorithm))
                .setContentEncryptionAlgorithm(protoContentEncryptionAlgorithm(contentEncryptionAlgorithm))
                .setKey(wrap(owned[0]))
            if (headerPolicy != null) builder.setHeaderPolicy(protoJweHeaderPolicy(headerPolicy, policyOwned))
            val response = execute(JoseOperationRequest.newBuilder().setJweDecrypt(builder.build()).build())
            if (response.responseCase != JoseOperationResponse.ResponseCase.JWE_DECRYPT) malformed()
            val selected = response.jweDecrypt
            requireClean(selected)
            when (selected.outcomeCase) {
                JoseJweDecryptResponse.OutcomeCase.RESULT -> {
                    requireClean(selected.result)
                    selected.result.plaintext.toByteArray()
                }
                JoseJweDecryptResponse.OutcomeCase.ERROR -> throw sdkError(selected.error)
                else -> malformed()
            }
        } finally {
            policyOwned.forEach { it.fill(0) }
        }
    }

    /** Explicit wire API. The caller owns and must clear the returned array. */
    @JvmStatic
    public fun executeWireRequest(request: ByteArray): ByteArray = executeOwned(request, false)

    /** Explicit ProtoJSON wire API returning a canonical binary response. */
    @JvmStatic
    public fun executeWireJsonRequest(request: ByteArray): ByteArray = executeOwned(request, true)

    private fun execute(request: JoseOperationRequest): JoseOperationResponse {
        if (request.serializedSize > ReallyMeJoseRustNativeProvider.binaryRequestLimit()) {
            throw resourceLimit()
        }
        val requestBytes = request.toByteArray()
        val responseBytes = try {
            ReallyMeJoseRustNativeProvider.requireLoaded()
            ReallyMeJoseNative.executeOperationNative(requestBytes)
        } finally {
            requestBytes.fill(0)
        }
        try {
            val input = CodedInputStream.newInstance(responseBytes)
            input.setRecursionLimit(MAX_PROTOBUF_RECURSION_DEPTH)
            input.setSizeLimit(ReallyMeJoseRustNativeProvider.responseLimit())
            val response = JoseOperationResponse.parseFrom(input)
            if (
                response.contractVersion != JoseOperationContractVersion.JOSE_OPERATION_CONTRACT_VERSION_V1 ||
                response.reallyMeHasUnknownFieldsForValidation()
            ) malformed()
            if (response.responseCase == JoseOperationResponse.ResponseCase.BOUNDARY_ERROR) {
                throw sdkError(response.boundaryError)
            }
            return response
        } catch (_: InvalidProtocolBufferException) {
            malformed()
        } finally {
            responseBytes.fill(0)
        }
    }

    private fun executeOwned(request: ByteArray, json: Boolean): ByteArray {
        val limit = if (json) {
            ReallyMeJoseRustNativeProvider.jsonRequestLimit()
        } else {
            ReallyMeJoseRustNativeProvider.binaryRequestLimit()
        }
        if (request.size > limit) throw resourceLimit()
        val owned = request.copyOf()
        try {
            return if (json) {
                ReallyMeJoseNative.executeOperationJsonNative(owned)
            } else {
                ReallyMeJoseNative.executeOperationNative(owned)
            }
        } finally {
            owned.fill(0)
        }
    }

    private fun requireAggregate(vararg lengths: Int) {
        var aggregate = 0
        val maximum = ReallyMeJoseRustNativeProvider.binaryRequestLimit()
        for (length in lengths) {
            aggregate = try {
                Math.addExact(aggregate, length)
            } catch (_: ArithmeticException) {
                throw resourceLimit()
            }
            if (aggregate > maximum) throw resourceLimit()
        }
    }
}
