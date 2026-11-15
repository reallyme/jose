// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

package me.really.jose

public class ReallyMeJoseJwtHeaderPolicy(
    public val allowMissingType: Boolean,
    public val allowEmbeddedKeyHeader: Boolean,
    acceptedTypeValues: List<String>,
) {
    public val acceptedTypeValues: List<String> = acceptedTypeValues.toList()
}

public class ReallyMeJoseJwtClaimsPolicy(
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
    allowedCompressionAlgorithms: List<ReallyMeJoseJweCompressionAlgorithm> = emptyList(),
) : AutoCloseable {
    /** Preserves the pre-compression JVM constructor while keeping compression opt-in. */
    public constructor(
        requireKeyIdentifier: Boolean,
        expectedKeyIdentifier: String?,
        expectedType: String?,
        expectedContentType: String?,
        expectedAgreementPartyUInfo: ByteArray?,
        expectedAgreementPartyVInfo: ByteArray?,
    ) : this(
        requireKeyIdentifier,
        expectedKeyIdentifier,
        expectedType,
        expectedContentType,
        expectedAgreementPartyUInfo,
        expectedAgreementPartyVInfo,
        emptyList(),
    )

    private val ownedAgreementPartyUInfo: ByteArray? = expectedAgreementPartyUInfo?.copyOf()
    private val ownedAgreementPartyVInfo: ByteArray? = expectedAgreementPartyVInfo?.copyOf()
    public val allowedCompressionAlgorithms: List<ReallyMeJoseJweCompressionAlgorithm> =
        allowedCompressionAlgorithms.toList()

    internal fun agreementPartyUInfoCopy(): ByteArray? = ownedAgreementPartyUInfo?.copyOf()

    internal fun agreementPartyVInfoCopy(): ByteArray? = ownedAgreementPartyVInfo?.copyOf()

    /** Clears the policy's owned party-information copies. */
    override fun close() {
        ownedAgreementPartyUInfo?.fill(0)
        ownedAgreementPartyVInfo?.fill(0)
    }
}

/** Absent options use JWT; a present options object with null type omits typ. */
public class ReallyMeJoseJwtHeaderOptions(public val type: String? = null) {
    override fun toString(): String = "ReallyMeJoseJwtHeaderOptions{<redacted>}"
}
