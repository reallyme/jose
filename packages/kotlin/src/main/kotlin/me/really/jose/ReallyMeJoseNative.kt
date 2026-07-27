// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

package me.really.jose

internal object ReallyMeJoseNative {
    external fun probeNative(): Int

    external fun abiVersionNative(): Int

    external fun maxRequestBytesNative(): Long

    external fun maxJsonRequestBytesNative(): Long

    external fun maxResponseBytesNative(): Long

    external fun executeOperationNative(request: ByteArray): ByteArray

    external fun executeOperationJsonNative(request: ByteArray): ByteArray
}
