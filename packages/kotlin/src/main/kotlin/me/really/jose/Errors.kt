// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

package me.really.jose

import me.really.jose.v1.JoseSdkErrorCode

/** Audit-safe JVM exceptions. No variant contains secrets, PII, paths, or backend text. */
// Keep the domain hierarchy explicit while preserving conventional unchecked
// JVM exception behavior for Java and Kotlin callers.
internal typealias ReallyMeJoseExceptionBase = RuntimeException

public sealed class ReallyMeJoseException(
    message: String,
    /** Stable SDK error code defined in the protobuf contract. */
    public val code: JoseSdkErrorCode,
) : ReallyMeJoseExceptionBase(message) {
    public class JoseFailure(
        public val branch: ReallyMeJoseErrorBranch,
        public val reason: ReallyMeJoseErrorReason,
    ) : ReallyMeJoseException("JOSE operation failed", JoseSdkErrorCode.JOSE_SDK_ERROR_CODE_JOSE_FAILURE)

    public class InvalidInput : ReallyMeJoseException("invalid input", JoseSdkErrorCode.JOSE_SDK_ERROR_CODE_INVALID_INPUT)

    public class NativeProviderFailure : ReallyMeJoseException("native provider failure", JoseSdkErrorCode.JOSE_SDK_ERROR_CODE_PROVIDER_FAILURE)

    public class MalformedProviderResponse : ReallyMeJoseException(
        "malformed provider response",
        JoseSdkErrorCode.JOSE_SDK_ERROR_CODE_MALFORMED_PROVIDER_RESPONSE,
    )
}
