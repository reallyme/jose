// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

package me.really.jose

public enum class ReallyMeJoseSignatureAlgorithm { ED_DSA, ES256 }

public enum class ReallyMeJoseJweKeyManagementAlgorithm { DIRECT, ECDH_ES_P256, ECDH_ES_P384, ECDH_ES_P521 }

public enum class ReallyMeJoseJweContentEncryptionAlgorithm { A128_GCM, A192_GCM, A256_GCM }

public class ReallyMeJoseJwtHeaderPolicy(
    public val allowMissingType: Boolean,
    public val allowEmbeddedKeyHeader: Boolean,
    acceptedTypeValues: List<String>,
) {
    public val acceptedTypeValues: List<String> = acceptedTypeValues.toList()
}

public class ReallyMeJoseJwtTemporalPolicy(
    public val requireExpiration: Boolean,
    public val requireNotBefore: Boolean,
    public val requireIssuedAt: Boolean,
    public val clockSkewSeconds: Long,
    public val maximumFutureIssuedAtSkewSeconds: Long,
    public val nowUnix: Long,
    public val expectedAudience: String,
    public val expectedIssuer: String? = null,
    public val expectedSubject: String? = null,
)

/** Header policy keeps sensitive party information in wipeable arrays. */
public class ReallyMeJoseJweHeaderPolicy(
    public val requireKeyIdentifier: Boolean = false,
    public val expectedKeyIdentifier: String? = null,
    public val expectedType: String? = null,
    public val expectedContentType: String? = null,
    expectedAgreementPartyUInfo: ByteArray? = null,
    expectedAgreementPartyVInfo: ByteArray? = null,
) : AutoCloseable {
    private val ownedAgreementPartyUInfo: ByteArray? = expectedAgreementPartyUInfo?.copyOf()
    private val ownedAgreementPartyVInfo: ByteArray? = expectedAgreementPartyVInfo?.copyOf()

    internal fun agreementPartyUInfoCopy(): ByteArray? = ownedAgreementPartyUInfo?.copyOf()

    internal fun agreementPartyVInfoCopy(): ByteArray? = ownedAgreementPartyVInfo?.copyOf()

    /** Clears the policy's owned party-information copies. */
    override fun close() {
        ownedAgreementPartyUInfo?.fill(0)
        ownedAgreementPartyVInfo?.fill(0)
    }
}
