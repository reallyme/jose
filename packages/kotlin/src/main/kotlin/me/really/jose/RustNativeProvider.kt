// SPDX-FileCopyrightText: 2026 ReallyMe LLC
//
// SPDX-License-Identifier: MIT OR Apache-2.0

package me.really.jose

import java.io.File
import java.io.FileOutputStream
import java.io.IOException
import java.io.InputStream
import java.nio.charset.StandardCharsets
import java.nio.file.Files
import java.nio.file.LinkOption
import java.nio.file.Path
import java.nio.file.StandardOpenOption
import java.nio.file.attribute.PosixFileAttributeView
import java.nio.file.attribute.PosixFilePermissions
import java.security.MessageDigest
import java.util.Locale

/**
 * Explicit loader for the ReallyMe Rust JOSE provider.
 *
 * Kotlin does not implement JOSE primitives locally. The Maven artifact ships
 * platform native libraries as resources and loads the matching one on first
 * use; `loadLibrary(path)` remains available for local development and tests
 * against a freshly built Rust cdylib.
 */
public object ReallyMeJoseRustNativeProvider {
    private const val RESOURCE_ROOT: String = "/me/really/jose/native"
    private const val ANDROID_LIBRARY_NAME: String = "reallyme_jose_ffi"
    private const val EXPECTED_JOSE_ABI_VERSION: Int = 1
    private const val MAX_NATIVE_LIBRARY_BYTES: Long = 134_217_728L
    private const val MAX_MANAGED_LIMIT_BYTES: Long = Int.MAX_VALUE.toLong()
    private const val DIGEST_BYTE_LENGTH: Int = 32
    private const val DIGEST_METADATA_MAX_BYTES: Int = 96
    private const val COPY_BUFFER_BYTES: Int = 8_192

    private val digestMetadataPattern: Regex = Regex("^([0-9a-f]{64}) ([1-9][0-9]{0,11})\\n$")

    @Volatile
    private var loaded: Boolean = false

    @Volatile
    private var maxRequestBytes: Int = 0

    @Volatile
    private var maxJsonRequestBytes: Int = 0

    @Volatile
    private var maxResponseBytes: Int = 0

    @JvmStatic
    @Synchronized
    public fun loadLibrary(path: String) {
        if (path.isEmpty()) {
            throw ReallyMeJoseException.InvalidInput()
        }
        val library = File(path)
        if (loaded) {
            if (!library.isFile) {
                throw ReallyMeJoseException.NativeProviderFailure()
            }
            return
        }
        try {
            System.load(library.absolutePath)
            if (!validateLoadedNativeContract()) {
                throw ReallyMeJoseException.NativeProviderFailure()
            }
            loaded = true
        } catch (_: LinkageError) {
            throw ReallyMeJoseException.NativeProviderFailure()
        } catch (_: SecurityException) {
            throw ReallyMeJoseException.NativeProviderFailure()
        }
    }

    @Synchronized
    internal fun requireLoaded() {
        if (loaded) {
            return
        }
        if (isAndroidRuntime() && loadAndroidLibrary()) {
            return
        }
        if (!loadBundledLibrary()) {
            throw ReallyMeJoseException.NativeProviderFailure()
        }
    }

    private fun loadAndroidLibrary(): Boolean {
        return try {
            // Android installs AAR `jniLibs/<abi>/libreallyme_jose_ffi.so`
            // under the app native-library directory. Those files are not
            // classpath resources, so the JVM resource extraction path cannot
            // see them; the platform loader must resolve them by library name.
            System.loadLibrary(ANDROID_LIBRARY_NAME)
            if (!validateLoadedNativeContract()) {
                false
            } else {
                loaded = true
                true
            }
        } catch (_: LinkageError) {
            false
        } catch (_: SecurityException) {
            false
        }
    }

    private fun loadBundledLibrary(): Boolean {
        val resource = platformNativeResource() ?: return false
        val expected = readExpectedDigest(resource.digestPath) ?: return false
        val extracted = extractVerifiedLibrary(resource, expected) ?: return false

        return loadExtractedLibrary(extracted)
    }

    private fun readExpectedDigest(path: String): ExpectedNativeDigest? {
        val stream = ReallyMeJoseRustNativeProvider::class.java.getResourceAsStream(path)
            ?: return null
        val metadata = try {
            stream.use { readBounded(it, DIGEST_METADATA_MAX_BYTES) }
        } catch (_: IOException) {
            return null
        } catch (_: SecurityException) {
            return null
        } ?: return null
        return try {
            parseDigestMetadata(metadata)
        } finally {
            metadata.fill(0)
        }
    }

    internal fun parseDigestMetadata(metadata: ByteArray): ExpectedNativeDigest? {
        val match = digestMetadataPattern.matchEntire(
            metadata.toString(StandardCharsets.US_ASCII),
        ) ?: return null
        val size = match.groupValues[2].toLongOrNull() ?: return null
        if (size > MAX_NATIVE_LIBRARY_BYTES) {
            return null
        }
        val digest = decodeLowerHex(match.groupValues[1]) ?: return null
        return ExpectedNativeDigest(digest, size)
    }

    private fun extractVerifiedLibrary(
        resource: NativeResource,
        expected: ExpectedNativeDigest,
    ): File? {
        val directory = createPrivateExtractionDirectory() ?: return null
        val target = directory.resolve(resource.fileName)
        var completed = false
        val buffer = ByteArray(COPY_BUFFER_BYTES)
        try {
            val source = ReallyMeJoseRustNativeProvider::class.java
                .getResourceAsStream(resource.path) ?: return null
            val digest = MessageDigest.getInstance("SHA-256")
            var copied = 0L
            source.use { input ->
                FileOutputStream(target.toFile()).use { output ->
                    while (true) {
                        val read = input.read(buffer)
                        if (read < 0) {
                            break
                        }
                        if (read == 0) {
                            return null
                        }
                        val remaining = MAX_NATIVE_LIBRARY_BYTES - copied
                        if (read.toLong() > remaining) {
                            return null
                        }
                        output.write(buffer, 0, read)
                        digest.update(buffer, 0, read)
                        copied += read.toLong()
                    }
                    output.fd.sync()
                }
            }
            if (
                copied != expected.size ||
                !MessageDigest.isEqual(digest.digest(), expected.sha256)
            ) {
                return null
            }
            if (!makeExtractedLibraryReadOnly(target)) {
                return null
            }
            if (!verifyExtractedLibrary(target, expected)) {
                return null
            }
            directory.toFile().deleteOnExit()
            target.toFile().deleteOnExit()
            completed = true
            return target.toFile()
        } catch (_: IOException) {
            return null
        } catch (_: SecurityException) {
            return null
        } finally {
            buffer.fill(0)
            if (!completed) {
                NativeExtractionPolicy.deleteExtractionFiles(target, directory)
            }
        }
    }

    internal fun createPrivateExtractionDirectory(
        configuredRoot: String? = System.getProperty("java.io.tmpdir"),
    ): Path? = NativeExtractionPolicy.createPrivateExtractionDirectory(configuredRoot)

    internal fun isSecurePosixTempMode(mode: Int): Boolean =
        NativeExtractionPolicy.isSecurePosixTempMode(mode)

    internal fun isTrustedPosixTempOwner(owner: String, currentUser: String): Boolean =
        NativeExtractionPolicy.isTrustedPosixTempOwner(owner, currentUser)

    internal fun isTrustedAclPrincipal(
        principal: String,
        currentUser: String,
        description: String = principal,
    ): Boolean = NativeExtractionPolicy.isTrustedAclPrincipal(
        principal,
        currentUser,
        description,
    )


    private fun makeExtractedLibraryReadOnly(path: Path): Boolean {
        return try {
            val posixView = Files.getFileAttributeView(
                path,
                PosixFileAttributeView::class.java,
                LinkOption.NOFOLLOW_LINKS,
            )
            if (posixView != null) {
                Files.setPosixFilePermissions(
                    path,
                    PosixFilePermissions.fromString("r--------"),
                )
                true
            } else {
                NativeExtractionPolicy.restrictAclToOwner(path, writable = false)
            }
        } catch (_: IOException) {
            false
        } catch (_: SecurityException) {
            false
        }
    }

    private fun verifyExtractedLibrary(path: Path, expected: ExpectedNativeDigest): Boolean {
        return try {
            if (Files.size(path) != expected.size || Files.isSymbolicLink(path)) {
                return false
            }
            val digest = MessageDigest.getInstance("SHA-256")
            val buffer = ByteArray(COPY_BUFFER_BYTES)
            var readTotal = 0L
            try {
                Files.newInputStream(path, StandardOpenOption.READ).use { input ->
                    while (true) {
                        val read = input.read(buffer)
                        if (read < 0) {
                            break
                        }
                        if (read == 0) {
                            return false
                        }
                        val remaining = expected.size - readTotal
                        if (read.toLong() > remaining) {
                            return false
                        }
                        digest.update(buffer, 0, read)
                        readTotal += read.toLong()
                    }
                }
            } finally {
                buffer.fill(0)
            }
            readTotal == expected.size &&
                MessageDigest.isEqual(digest.digest(), expected.sha256)
        } catch (_: IOException) {
            false
        } catch (_: SecurityException) {
            false
        }
    }

    private fun readBounded(input: InputStream, maximum: Int): ByteArray? {
        val result = ByteArray(maximum + 1)
        var offset = 0
        while (offset < result.size) {
            val read = input.read(result, offset, result.size - offset)
            if (read < 0) {
                return result.copyOf(offset).also { result.fill(0) }
            }
            if (read == 0) {
                result.fill(0)
                return null
            }
            offset += read
        }
        result.fill(0)
        return null
    }

    private fun decodeLowerHex(value: String): ByteArray? {
        if (value.length != DIGEST_BYTE_LENGTH * 2) {
            return null
        }
        val output = ByteArray(DIGEST_BYTE_LENGTH)
        for (index in output.indices) {
            val high = Character.digit(value[index * 2], 16)
            val low = Character.digit(value[index * 2 + 1], 16)
            if (high < 0 || low < 0) {
                output.fill(0)
                return null
            }
            output[index] = ((high shl 4) or low).toByte()
        }
        return output
    }

    private fun loadExtractedLibrary(path: File): Boolean {
        return try {
            System.load(path.absolutePath)
            if (!validateLoadedNativeContract()) {
                false
            } else {
                loaded = true
                true
            }
        } catch (_: LinkageError) {
            false
        } catch (_: SecurityException) {
            false
        }
    }

    internal fun platformNativeResource(
        osName: String? = System.getProperty("os.name"),
        osArch: String? = System.getProperty("os.arch"),
        androidRuntime: Boolean = isAndroidRuntime(),
    ): NativeResource? {
        if (androidRuntime) {
            return null
        }
        val os = normalizedOs(osName) ?: return null
        val arch = normalizedArch(osArch) ?: return null
        val fileName = nativeLibraryFileName(os)
        return NativeResource(
            fileName = fileName,
            path = "$RESOURCE_ROOT/$os-$arch/$fileName",
            digestPath = "$RESOURCE_ROOT/$os-$arch/$fileName.sha256",
        )
    }

    internal fun normalizedOs(osName: String?): String? {
        val value = osName?.lowercase(Locale.ROOT) ?: return null
        return when {
            value.contains("mac") || value.contains("darwin") -> "macos"
            value.contains("linux") -> "linux"
            value.contains("windows") -> "windows"
            else -> null
        }
    }

    internal fun normalizedArch(osArch: String?): String? {
        return when (osArch?.lowercase(Locale.ROOT)) {
            "aarch64", "arm64" -> "aarch64"
            "amd64", "x86_64" -> "x86_64"
            else -> null
        }
    }

    internal fun isAndroidRuntime(
        runtimeName: String? = System.getProperty("java.runtime.name"),
        vmName: String? = System.getProperty("java.vm.name"),
        vmVendor: String? = System.getProperty("java.vm.vendor"),
    ): Boolean {
        return containsAndroidMarker(runtimeName) ||
            containsAndroidMarker(vmName) ||
            containsAndroidMarker(vmVendor)
    }

    private fun containsAndroidMarker(value: String?): Boolean {
        val normalized = value?.lowercase(Locale.ROOT) ?: return false
        return normalized.contains("android") || normalized.contains("dalvik")
    }

    private fun nativeLibraryFileName(os: String): String =
        when (os) {
            "macos" -> "libreallyme_jose_ffi.dylib"
            "windows" -> "reallyme_jose_ffi.dll"
            else -> "libreallyme_jose_ffi.so"
        }

    internal fun binaryRequestLimit(): Int {
        requireLoaded()
        return maxRequestBytes
    }

    internal fun jsonRequestLimit(): Int {
        requireLoaded()
        return maxJsonRequestBytes
    }

    internal fun responseLimit(): Int {
        requireLoaded()
        return maxResponseBytes
    }

    internal fun isCompatibleAbiVersion(actualVersion: Int): Boolean =
        actualVersion == EXPECTED_JOSE_ABI_VERSION

    internal fun isValidNativeLimit(limit: Long): Boolean =
        limit in 1..MAX_MANAGED_LIMIT_BYTES

    private fun validateLoadedNativeContract(): Boolean {
        if (ReallyMeJoseNative.probeNative() != 1) {
            return false
        }
        if (!isCompatibleAbiVersion(ReallyMeJoseNative.abiVersionNative())) {
            return false
        }
        val inputLimit = ReallyMeJoseNative.maxRequestBytesNative()
        val outputLimit = ReallyMeJoseNative.maxJsonRequestBytesNative()
        val operationLimit = ReallyMeJoseNative.maxResponseBytesNative()
        if (
            !isValidNativeLimit(inputLimit) ||
            !isValidNativeLimit(outputLimit) ||
            !isValidNativeLimit(operationLimit) ||
            operationLimit > outputLimit
        ) {
            return false
        }
        maxRequestBytes = inputLimit.toInt()
        maxJsonRequestBytes = outputLimit.toInt()
        maxResponseBytes = operationLimit.toInt()
        return true
    }

    internal data class NativeResource(
        val fileName: String,
        val path: String,
        val digestPath: String,
    )

    internal data class ExpectedNativeDigest(
        val sha256: ByteArray,
        val size: Long,
    )
}
