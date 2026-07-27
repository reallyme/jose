// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

import org.gradle.api.publish.maven.tasks.PublishToMavenLocal
import org.gradle.api.publish.maven.tasks.PublishToMavenRepository
import groovy.json.JsonSlurper
import java.net.URI
import java.security.MessageDigest
import java.util.zip.ZipFile

plugins {
    id("com.android.library") version "9.3.0"
    id("com.android.application") version "9.3.0" apply false
    `maven-publish`
    signing
}

group = "me.really"
version = "0.3.0"

dependencyLocking {
    lockAllConfigurations()
}

val configuredAndroidJniLibsDir = providers.gradleProperty("reallyme.jose.androidJniLibsDir")
    .map { file(it) }
val jniLibsDir = configuredAndroidJniLibsDir
    .orElse(layout.buildDirectory.dir("generated/android-jniLibs").map { it.asFile })
val configuredNativeAssetsDir = providers.gradleProperty("reallyme.jose.androidNativeAssetsDir")
val nativeAssetsDir = configuredNativeAssetsDir
    .map { file(it) }
    .orElse(layout.buildDirectory.dir("generated/android-native-assets").map { it.asFile })
val requireJniLibs = providers.gradleProperty("reallyme.jose.requireAndroidJniLibs")
    .map { it == "true" }
    .orElse(false)
val remoteMavenRepositoryUrl = providers.gradleProperty("reallyme.maven.repositoryUrl")
    .orElse(providers.environmentVariable("REALLYME_MAVEN_REPOSITORY_URL"))
val remoteMavenUsername = providers.gradleProperty("reallyme.maven.username")
    .orElse(providers.environmentVariable("REALLYME_MAVEN_USERNAME"))
val remoteMavenPassword = providers.gradleProperty("reallyme.maven.password")
    .orElse(providers.environmentVariable("REALLYME_MAVEN_PASSWORD"))
val signingKey = providers.gradleProperty("signingInMemoryKey")
    .orElse(providers.environmentVariable("MAVEN_SIGNING_KEY"))
val signingPassword = providers.gradleProperty("signingInMemoryKeyPassword")
    .orElse(providers.environmentVariable("MAVEN_SIGNING_PASSWORD"))
val localReleaseRepositoryDir = providers.gradleProperty("reallyme.maven.localReleaseRepositoryDir")
    .map { file(it) }
fun nonBlank(value: String?): String? = value?.trim()?.takeIf { it.isNotEmpty() }

val remoteMavenRepositoryUrlValue = nonBlank(remoteMavenRepositoryUrl.orNull)
val remoteMavenUsernameValue = nonBlank(remoteMavenUsername.orNull)
val remoteMavenPasswordValue = nonBlank(remoteMavenPassword.orNull)
val signingKeyValue = nonBlank(signingKey.orNull)
val signingPasswordValue = nonBlank(signingPassword.orNull)
val remoteMavenRepositoryUri = remoteMavenRepositoryUrlValue?.let { value ->
    val parsed = try {
        URI(value)
    } catch (_: IllegalArgumentException) {
        throw GradleException("remote Maven repository URL is invalid")
    }
    if (
        parsed.scheme != "https" ||
        parsed.host.isNullOrBlank() ||
        parsed.userInfo != null ||
        parsed.query != null ||
        parsed.fragment != null
    ) {
        throw GradleException(
            "remote Maven repository URL must be an absolute HTTPS URL without embedded credentials, a query, or a fragment"
        )
    }
    parsed
}

val requiredAndroidJniLibs = listOf(
    "arm64-v8a/libreallyme_jose_ffi.so",
    "armeabi-v7a/libreallyme_jose_ffi.so",
    "x86_64/libreallyme_jose_ffi.so",
    "x86/libreallyme_jose_ffi.so",
)
val androidJniLib64BitLoadAlignments = mapOf(
    "arm64-v8a/libreallyme_jose_ffi.so" to 16_384L,
    "x86_64/libreallyme_jose_ffi.so" to 16_384L,
)
val androidJniLib32BitAlignmentPolicy = mapOf(
    "armeabi-v7a/libreallyme_jose_ffi.so" to "presence-and-manifest",
    "x86/libreallyme_jose_ffi.so" to "presence-and-manifest",
)
val requiredAndroidNativeManifest = "reallyme-jose/native-manifest.json"
val androidNdkVersion = "29.0.14206865"

fun sha256Hex(bytes: ByteArray): String {
    val digest = MessageDigest.getInstance("SHA-256").digest(bytes)
    return digest.joinToString(separator = "") { byte -> "%02x".format(byte) }
}

fun checkedOutCommitSha(): String {
    val checkedOutSha = providers.exec {
        workingDir = layout.projectDirectory.dir("../..").asFile
        commandLine("git", "rev-parse", "HEAD")
    }.standardOutput.asText.get().trim()
    val fullSha = Regex("^[0-9a-f]{40}$")
    if (!fullSha.matches(checkedOutSha)) {
        throw GradleException("checked-out git commit SHA is not a lowercase full SHA")
    }
    val githubSha = providers.environmentVariable("GITHUB_SHA").orNull
    if (githubSha != null) {
        if (!fullSha.matches(githubSha)) {
            throw GradleException("GITHUB_SHA is not a lowercase full SHA")
        }
        if (githubSha != checkedOutSha) {
            throw GradleException("GITHUB_SHA does not match the checked-out source SHA")
        }
    }
    return checkedOutSha
}

fun verifyAndroidNativeManifest(
    manifestText: String,
    nativeBytes: Map<String, ByteArray>,
) {
    val parsed = try {
        JsonSlurper().parseText(manifestText)
    } catch (_: RuntimeException) {
        throw GradleException("Android native manifest is not valid JSON")
    }
    val root = parsed as? Map<*, *>
        ?: throw GradleException("Android native manifest root is not an object")
    if ((root["schemaVersion"] as? Number)?.toInt() != 1) {
        throw GradleException("Android native manifest schema version is invalid")
    }
    if (root["package"] != "reallyme-jose-native") {
        throw GradleException("Android native manifest package identity is invalid")
    }
    if (root["commitSha"] != checkedOutCommitSha()) {
        throw GradleException("Android native manifest source SHA does not match the checkout")
    }
    val entries = root["entries"] as? List<*>
        ?: throw GradleException("Android native manifest entries are invalid")
    if (entries.size != nativeBytes.size) {
        throw GradleException("Android native manifest entry count is invalid")
    }
    val seenPaths = mutableSetOf<String>()
    for (entryValue in entries) {
        val entry = entryValue as? Map<*, *>
            ?: throw GradleException("Android native manifest entry is not an object")
        val relativePath = entry["path"] as? String
            ?: throw GradleException("Android native manifest entry path is invalid")
        if (!seenPaths.add(relativePath)) {
            throw GradleException("Android native manifest contains a duplicate path")
        }
        val bytes = nativeBytes[relativePath]
            ?: throw GradleException("Android native manifest contains an unexpected path")
        val expectedSize = (entry["size"] as? Number)?.toLong()
            ?: throw GradleException("Android native manifest entry size is invalid")
        val expectedDigest = entry["sha256"] as? String
            ?: throw GradleException("Android native manifest entry digest is invalid")
        if (expectedSize != bytes.size.toLong() || expectedDigest != sha256Hex(bytes)) {
            throw GradleException("Android native manifest does not match packaged JNI bytes")
        }
    }
    if (seenPaths != nativeBytes.keys) {
        throw GradleException("Android native manifest does not cover every required JNI path")
    }
}

fun readElfLittleEndian(bytes: ByteArray, offset: Int, byteCount: Int): Long {
    if (offset < 0 || byteCount < 0 || offset > bytes.size - byteCount) {
        throw GradleException("invalid ELF header offset")
    }
    var value = 0L
    for (index in 0 until byteCount) {
        value = value or ((bytes[offset + index].toLong() and 0xffL) shl (8 * index))
    }
    return value
}

fun verifyElf64LoadAlignment(file: File, relativePath: String, requiredAlignment: Long) {
    val bytes = file.readBytes()
    try {
        if (
            bytes.size < 64 ||
            bytes[0] != 0x7f.toByte() ||
            bytes[1] != 'E'.code.toByte() ||
            bytes[2] != 'L'.code.toByte() ||
            bytes[3] != 'F'.code.toByte()
        ) {
            throw GradleException("Android JNI library is not an ELF file: $relativePath")
        }
        if (bytes[4] != 2.toByte() || bytes[5] != 1.toByte()) {
            throw GradleException("Android JNI library is not a little-endian ELF64 file: $relativePath")
        }
        val programHeaderOffset = readElfLittleEndian(bytes, 32, 8)
        val programHeaderEntrySize = readElfLittleEndian(bytes, 54, 2)
        val programHeaderCount = readElfLittleEndian(bytes, 56, 2)
        if (programHeaderEntrySize < 56 || programHeaderCount == 0L) {
            throw GradleException("Android JNI library has no usable ELF program headers: $relativePath")
        }
        var sawLoadSegment = false
        for (index in 0L until programHeaderCount) {
            val headerOffset = Math.addExact(
                programHeaderOffset,
                Math.multiplyExact(index, programHeaderEntrySize),
            )
            if (headerOffset < 0 || headerOffset > bytes.size.toLong() - programHeaderEntrySize) {
                throw GradleException("Android JNI library has truncated ELF program headers: $relativePath")
            }
            val headerOffsetInt = Math.toIntExact(headerOffset)
            if (readElfLittleEndian(bytes, headerOffsetInt, 4) == 1L) {
                sawLoadSegment = true
                val loadAlignment = readElfLittleEndian(bytes, Math.addExact(headerOffsetInt, 48), 8)
                if (loadAlignment < requiredAlignment || loadAlignment % requiredAlignment != 0L) {
                    throw GradleException(
                        "Android JNI library LOAD alignment does not satisfy the 16 KiB policy: $relativePath"
                    )
                }
            }
        }
        if (!sawLoadSegment) {
            throw GradleException("Android JNI library has no ELF LOAD segments: $relativePath")
        }
    } finally {
        bytes.fill(0)
    }
}

android {
    namespace = "me.really.jose"
    compileSdk = 36
    ndkVersion = androidNdkVersion

    defaultConfig {
        minSdk = 24
        consumerProguardFiles("consumer-rules.pro")
        aarMetadata {
            minCompileSdk = 36
        }
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_21
        targetCompatibility = JavaVersion.VERSION_21
    }

    sourceSets {
        named("main") {
            java.directories.clear()
            java.directories.add("../kotlin/src/main/kotlin")
            java.directories.add("../../gen/java")
            java.directories.add("../../gen/kotlin")
            kotlin.directories.clear()
            kotlin.directories.add("../kotlin/src/main/kotlin")
            kotlin.directories.add("../../gen/kotlin")
            jniLibs.directories.clear()
            jniLibs.directories.add(jniLibsDir.get().path)
            assets.directories.add(nativeAssetsDir.get().path)
        }
    }

    packaging {
        jniLibs {
            // The release workflows hash the staged libraries before building
            // the AAR. Keep Gradle from mutating those bytes after attestation.
            keepDebugSymbols.add("**/libreallyme_jose_ffi.so")
        }
    }

    publishing {
        singleVariant("release") {
            withSourcesJar()
        }
    }
}

dependencies {
    api("com.google.protobuf:protobuf-javalite:4.35.1")
    api("com.google.protobuf:protobuf-kotlin-lite:4.35.1")
}

val generateAndroidNativeManifest = tasks.register("generateAndroidNativeManifest") {
    group = "build"
    description = "Generates the Android native checksum manifest for local AAR builds."
    onlyIf {
        !configuredNativeAssetsDir.isPresent &&
            (requireJniLibs.get() || jniLibsDir.get().isDirectory)
    }
    inputs.dir(jniLibsDir).optional()
    outputs.file(nativeAssetsDir.map { it.resolve(requiredAndroidNativeManifest) })
    doLast {
        val root = jniLibsDir.get()
        val nativeFiles = requiredAndroidJniLibs.map { relativePath ->
            val file = root.resolve(relativePath)
            if (!file.isFile) {
                throw GradleException(
                    "missing freshly built ReallyMe JOSE Android jniLib for manifest: $relativePath; " +
                        "run scripts/build_android_native_resources.sh and pass " +
                        "-Preallyme.jose.androidJniLibsDir"
                )
            }
            file
        }
        val commitSha = checkedOutCommitSha()
        val entries = nativeFiles.map { file ->
            val relativePath = root.toPath().relativize(file.toPath()).toString().replace(File.separatorChar, '/')
            val bytes = file.readBytes()
            """{"path":"$relativePath","sha256":"${sha256Hex(bytes)}","size":${bytes.size}}"""
        }.joinToString(",")
        val manifest = """
            {"schemaVersion":1,"package":"reallyme-jose-native","commitSha":"$commitSha","entries":[$entries]}
        """.trimIndent() + "\n"
        val manifestFile = nativeAssetsDir.get().resolve(requiredAndroidNativeManifest)
        manifestFile.parentFile.mkdirs()
        manifestFile.writeText(manifest)
    }
}

val verifyAndroidJniLibs = tasks.register("verifyAndroidJniLibs") {
    group = "verification"
    description = "Verifies that release Android AARs include every supported Rust JNI library."
    dependsOn(generateAndroidNativeManifest)
    inputs.dir(jniLibsDir).optional()
    inputs.dir(nativeAssetsDir).optional()
    onlyIf { requireJniLibs.get() }
    doLast {
        val root = jniLibsDir.get()
        val assetsRoot = nativeAssetsDir.get()
        val missing = requiredAndroidJniLibs.filter { relativePath ->
            !root.resolve(relativePath).isFile
        }
        if (missing.isNotEmpty()) {
            throw GradleException(
                "missing ReallyMe JOSE Android jniLibs: ${missing.joinToString(", ")}"
            )
        }
        if (!assetsRoot.resolve(requiredAndroidNativeManifest).isFile) {
            throw GradleException(
                "missing ReallyMe JOSE Android native manifest: $requiredAndroidNativeManifest"
            )
        }
        val nativeBytes = requiredAndroidJniLibs.associateWith { relativePath ->
            root.resolve(relativePath).readBytes()
        }
        try {
            verifyAndroidNativeManifest(
                assetsRoot.resolve(requiredAndroidNativeManifest).readText(),
                nativeBytes,
            )
        } finally {
            nativeBytes.values.forEach { bytes -> bytes.fill(0) }
        }
        androidJniLib64BitLoadAlignments.forEach { (relativePath, requiredAlignment) ->
            verifyElf64LoadAlignment(root.resolve(relativePath), relativePath, requiredAlignment)
        }
        androidJniLib32BitAlignmentPolicy.keys.forEach { relativePath ->
            if (!requiredAndroidJniLibs.contains(relativePath)) {
                throw GradleException("untracked Android 32-bit JNI library policy: $relativePath")
            }
        }
    }
}

tasks.named("preBuild") {
    dependsOn(generateAndroidNativeManifest, verifyAndroidJniLibs)
}

tasks.register("verifyReleaseAarContainsJniLibs") {
    group = "verification"
    description = "Verifies that the release AAR contains the expected jniLibs entries."
    dependsOn(generateAndroidNativeManifest, "bundleReleaseAar")
    doLast {
        val aarFiles = layout.buildDirectory.dir("outputs/aar").get().asFile
            .listFiles { file -> file.isFile && file.name.endsWith("-release.aar") }
            ?.toList()
            .orEmpty()
        if (aarFiles.size != 1) {
            throw GradleException(
                "expected exactly one release AAR, found ${aarFiles.size}"
            )
        }
        ZipFile(aarFiles.single()).use { archive ->
            val manifestEntry = archive.getEntry("assets/$requiredAndroidNativeManifest")
                ?: throw GradleException(
                    "release AAR is missing native manifest asset: $requiredAndroidNativeManifest"
                )
            val manifestText = archive.getInputStream(manifestEntry)
                .bufferedReader()
                .use { it.readText() }
            val packagedNativePaths = archive.entries().asSequence()
                .map { it.name }
                .filter { it.startsWith("jni/") && it.endsWith(".so") }
                .map { it.removePrefix("jni/") }
                .toSet()
            if (packagedNativePaths != requiredAndroidJniLibs.toSet()) {
                throw GradleException("release AAR JNI inventory does not match the frozen ABI matrix")
            }
            val nativeBytes = requiredAndroidJniLibs.associateWith { relativePath ->
                val entry = archive.getEntry("jni/$relativePath")
                    ?: throw GradleException("release AAR is missing JNI entry: $relativePath")
                archive.getInputStream(entry).use { it.readBytes() }
            }
            try {
                verifyAndroidNativeManifest(manifestText, nativeBytes)
            } finally {
                nativeBytes.values.forEach { bytes -> bytes.fill(0) }
            }
        }
    }
}

tasks.withType<PublishToMavenLocal>().configureEach {
    dependsOn("verifyReleaseAarContainsJniLibs")
}

tasks.withType<PublishToMavenRepository>().configureEach {
    dependsOn("verifyReleaseAarContainsJniLibs")
}

val verifyRemoteMavenPublishingConfigured = tasks.register("verifyRemoteMavenPublishingConfigured") {
    group = "verification"
    description = "Verifies that remote Maven publishing credentials are configured."
    doLast {
        val missing = buildList {
            if (remoteMavenRepositoryUrlValue == null) {
                add("REALLYME_MAVEN_REPOSITORY_URL or -Preallyme.maven.repositoryUrl")
            }
            if (remoteMavenUsernameValue == null) {
                add("REALLYME_MAVEN_USERNAME or -Preallyme.maven.username")
            }
            if (remoteMavenPasswordValue == null) {
                add("REALLYME_MAVEN_PASSWORD or -Preallyme.maven.password")
            }
            if (signingKeyValue == null) {
                add("MAVEN_SIGNING_KEY or -PsigningInMemoryKey")
            }
            if (signingPasswordValue == null) {
                add("MAVEN_SIGNING_PASSWORD or -PsigningInMemoryKeyPassword")
            }
        }
        if (missing.isNotEmpty()) {
            throw GradleException(
                "remote Maven publishing is not configured; missing non-empty ${missing.joinToString(", ")}"
            )
        }
    }
}

tasks.named("publish") {
    dependsOn(verifyRemoteMavenPublishingConfigured)
}

tasks.withType<PublishToMavenRepository>().configureEach {
    if (name.endsWith("ToRemoteReleaseRepository")) {
        dependsOn(verifyRemoteMavenPublishingConfigured)
    }
}

publishing {
    publications {
        create<MavenPublication>("release") {
            artifactId = "jose-android"
            afterEvaluate {
                from(components["release"])
            }
            pom {
                name.set("ReallyMe JOSE Android")
                description.set("ReallyMe JOSE Android facade backed by bundled Rust JNI libraries.")
                url.set("https://github.com/reallyme/jose")
                licenses {
                    license {
                        name.set("Apache License, Version 2.0")
                        url.set("https://www.apache.org/licenses/LICENSE-2.0.txt")
                        distribution.set("repo")
                    }
                }
                developers {
                    developer {
                        id.set("reallyme")
                        name.set("ReallyMe LLC")
                        organization.set("ReallyMe LLC")
                        organizationUrl.set("https://github.com/reallyme")
                    }
                }
                scm {
                    connection.set("scm:git:https://github.com/reallyme/jose.git")
                    developerConnection.set("scm:git:ssh://git@github.com/reallyme/jose.git")
                    url.set("https://github.com/reallyme/jose")
                }
            }
        }
    }
    repositories {
        localReleaseRepositoryDir.orNull?.let { repositoryDir ->
            maven {
                name = "localRelease"
                url = repositoryDir.toURI()
            }
        }
        if (remoteMavenRepositoryUri != null) {
            maven {
                name = "remoteRelease"
                url = remoteMavenRepositoryUri
                credentials {
                    username = remoteMavenUsernameValue
                    password = remoteMavenPasswordValue
                }
            }
        }
    }
}

signing {
    useInMemoryPgpKeys(signingKeyValue, signingPasswordValue)
    sign(publishing.publications["release"])
    setRequired {
        gradle.taskGraph.allTasks.any { task ->
            task.name.endsWith("ToRemoteReleaseRepository")
        }
    }
}
