// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

package me.really.jose

import java.nio.file.Files
import java.nio.file.LinkOption
import java.nio.file.attribute.PosixFileAttributeView
import java.nio.file.attribute.PosixFilePermissions
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertFailsWith
import kotlin.test.assertNull
import kotlin.test.assertTrue

class NativeProviderSecurityTest {
    @Test
    fun providerLoadingAndContractValidationFailClosed() {
        assertFailsWith<ReallyMeJoseException.InvalidInput> {
            ReallyMeJoseRustNativeProvider.loadLibrary("")
        }
        assertFailsWith<ReallyMeJoseException.NativeProviderFailure> {
            ReallyMeJoseRustNativeProvider.loadLibrary("/tmp/reallyme-jose-missing-library.dylib")
        }
        assertTrue(ReallyMeJoseRustNativeProvider.isCompatibleAbiVersion(1))
        assertFalse(ReallyMeJoseRustNativeProvider.isCompatibleAbiVersion(0))
        assertTrue(ReallyMeJoseRustNativeProvider.isValidNativeLimit(1))
        assertFalse(ReallyMeJoseRustNativeProvider.isValidNativeLimit(0))
        assertFalse(ReallyMeJoseRustNativeProvider.isValidNativeLimit(-1))
        assertFalse(
            ReallyMeJoseRustNativeProvider.isValidNativeLimit(Int.MAX_VALUE.toLong() + 1),
        )
    }

    @Test
    fun platformSelectionAndDigestMetadataAreStrict() {
        assertNull(
            ReallyMeJoseRustNativeProvider.platformNativeResource(
                osName = "Linux",
                osArch = "aarch64",
                androidRuntime = true,
            ),
        )
        assertEquals(
            ReallyMeJoseRustNativeProvider.NativeResource(
                fileName = "libreallyme_jose_ffi.so",
                path = "/me/really/jose/native/linux-aarch64/libreallyme_jose_ffi.so",
                digestPath = "/me/really/jose/native/linux-aarch64/libreallyme_jose_ffi.so.sha256",
            ),
            ReallyMeJoseRustNativeProvider.platformNativeResource(
                osName = "Linux",
                osArch = "aarch64",
                androidRuntime = false,
            ),
        )

        val digestHex = "ab".repeat(32)
        val expected = ReallyMeJoseRustNativeProvider.parseDigestMetadata(
            "$digestHex 4096\n".toByteArray(Charsets.US_ASCII),
        )
        assertEquals(4096L, expected?.size)
        assertContentEquals(ByteArray(32) { 0xab.toByte() }, expected?.sha256)
        assertNull(
            ReallyMeJoseRustNativeProvider.parseDigestMetadata(
                "${digestHex.uppercase()} 4096\n".toByteArray(Charsets.US_ASCII),
            ),
        )
        assertNull(
            ReallyMeJoseRustNativeProvider.parseDigestMetadata(
                "$digestHex 134217729\n".toByteArray(Charsets.US_ASCII),
            ),
        )
    }

    @Test
    fun extractionRejectsUnsafePosixRootAndCreatesPrivateDirectory() {
        val root = Files.createTempDirectory("reallyme-jose-loader-test-")
        val posix = Files.getFileAttributeView(
            root,
            PosixFileAttributeView::class.java,
            LinkOption.NOFOLLOW_LINKS,
        )
        if (posix == null) {
            Files.deleteIfExists(root)
            return
        }

        var extracted: java.nio.file.Path? = null
        try {
            Files.setPosixFilePermissions(root, PosixFilePermissions.fromString("rwxrwxrwx"))
            assertNull(ReallyMeJoseRustNativeProvider.createPrivateExtractionDirectory(root.toString()))

            Files.setPosixFilePermissions(root, PosixFilePermissions.fromString("rwx------"))
            extracted = ReallyMeJoseRustNativeProvider.createPrivateExtractionDirectory(root.toString())
            assertEquals(
                PosixFilePermissions.fromString("rwx------"),
                extracted?.let { Files.getPosixFilePermissions(it, LinkOption.NOFOLLOW_LINKS) },
            )
        } finally {
            extracted?.let { Files.deleteIfExists(it) }
            Files.setPosixFilePermissions(root, PosixFilePermissions.fromString("rwx------"))
            Files.deleteIfExists(root)
        }
    }
}
