// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

// Derived from the protobuf contract. Change the schema and regenerate.

package me.really.jose

/** Explicit schema verification mode. Temporal-only does not authorize an audience. */
public sealed interface ReallyMeJoseJwtVerification {
    public data object SignatureOnly : ReallyMeJoseJwtVerification
    public class Claims(public val policy: ReallyMeJoseJwtClaimsPolicy) : ReallyMeJoseJwtVerification
    public class TemporalOnly(public val policy: ReallyMeJoseJwtTemporalPolicy) : ReallyMeJoseJwtVerification
}

public class ReallyMeJoseJwtTemporalPolicy(
    public val requireExpiration: Boolean,
    public val requireNotBefore: Boolean,
    public val requireIssuedAt: Boolean,
    public val clockSkewSeconds: Long,
    public val maximumFutureIssuedAtSkewSeconds: Long,
    public val nowUnix: Long,
)
