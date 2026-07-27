// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

import org.gradle.api.publish.maven.tasks.PublishToMavenLocal
import org.gradle.api.publish.maven.tasks.PublishToMavenRepository
import org.gradle.external.javadoc.StandardJavadocDocletOptions
import org.gradle.jvm.tasks.Jar
import groovy.json.JsonSlurper
import java.net.URI
import java.security.MessageDigest
import java.util.zip.ZipFile

plugins {
    kotlin("jvm") version "2.4.0"
    `java-library`
    `maven-publish`
    signing
}

group = "me.really"
version = "0.3.0"

dependencyLocking {
    lockAllConfigurations()
}

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
val configuredNativeResourcesDir = providers.gradleProperty("reallyme.jose.nativeResourcesDir")
val nativeResourcesDir = configuredNativeResourcesDir
    .map { file(it) }
    .orElse(layout.buildDirectory.dir("generated/native-resources").map { it.asFile })
val requireFullNativeResources = providers.gradleProperty("reallyme.jose.requireFullNativeResources")
    .map { it == "true" }
    .orElse(false)
val requiredNativeResources = listOf(
    "me/really/jose/native/linux-x86_64/libreallyme_jose_ffi.so",
    "me/really/jose/native/linux-x86_64/libreallyme_jose_ffi.so.sha256",
    "me/really/jose/native/linux-aarch64/libreallyme_jose_ffi.so",
    "me/really/jose/native/linux-aarch64/libreallyme_jose_ffi.so.sha256",
    "me/really/jose/native/macos-x86_64/libreallyme_jose_ffi.dylib",
    "me/really/jose/native/macos-x86_64/libreallyme_jose_ffi.dylib.sha256",
    "me/really/jose/native/macos-aarch64/libreallyme_jose_ffi.dylib",
    "me/really/jose/native/macos-aarch64/libreallyme_jose_ffi.dylib.sha256",
    "me/really/jose/native/windows-x86_64/reallyme_jose_ffi.dll",
    "me/really/jose/native/windows-x86_64/reallyme_jose_ffi.dll.sha256",
    "me/really/jose/native/native-manifest.json",
)
val hostNativePlatform = when {
    System.getProperty("os.name").contains("Mac", ignoreCase = true) -> "macos"
    System.getProperty("os.name").contains("Linux", ignoreCase = true) -> "linux"
    System.getProperty("os.name").contains("Windows", ignoreCase = true) -> "windows"
    else -> throw GradleException("unsupported host operating system for ReallyMe JOSE JNI resources")
}
val hostNativeArch = when (System.getProperty("os.arch").lowercase()) {
    "aarch64", "arm64" -> "aarch64"
    "amd64", "x86_64" -> "x86_64"
    else -> throw GradleException("unsupported host architecture for ReallyMe JOSE JNI resources")
}
val hostNativeLibraryName = when (hostNativePlatform) {
    "macos" -> "libreallyme_jose_ffi.dylib"
    "windows" -> "reallyme_jose_ffi.dll"
    else -> "libreallyme_jose_ffi.so"
}
val requiredHostNativeResource =
    "me/really/jose/native/$hostNativePlatform-$hostNativeArch/$hostNativeLibraryName"
val requiredHostNativeDigest = "$requiredHostNativeResource.sha256"
fun sha256Hex(file: File): String {
    val digest = MessageDigest.getInstance("SHA-256")
    file.inputStream().use { input ->
        val buffer = ByteArray(DEFAULT_BUFFER_SIZE)
        try {
            while (true) {
                val read = input.read(buffer)
                if (read < 0) {
                    break
                }
                if (read > 0) {
                    digest.update(buffer, 0, read)
                }
            }
        } finally {
            buffer.fill(0)
        }
    }
    return digest.digest().joinToString(separator = "") { byte ->
        "%02x".format(byte)
    }
}

fun sha256Hex(bytes: ByteArray): String {
    val digest = MessageDigest.getInstance("SHA-256").digest(bytes)
    return digest.joinToString(separator = "") { byte ->
        "%02x".format(byte)
    }
}

fun expectedNativeDigestMetadata(file: File): String =
    "${sha256Hex(file)} ${file.length()}\n"

fun expectedNativeDigestMetadata(bytes: ByteArray): String =
    "${sha256Hex(bytes)} ${bytes.size}\n"

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

fun verifyJvmNativeManifest(
    manifestText: String,
    nativeBytes: Map<String, ByteArray>,
) {
    val parsed = try {
        JsonSlurper().parseText(manifestText)
    } catch (_: RuntimeException) {
        throw GradleException("JVM native manifest is not valid JSON")
    }
    val root = parsed as? Map<*, *>
        ?: throw GradleException("JVM native manifest root is not an object")
    if ((root["schemaVersion"] as? Number)?.toInt() != 1) {
        throw GradleException("JVM native manifest schema version is invalid")
    }
    if (root["package"] != "reallyme-jose-native") {
        throw GradleException("JVM native manifest package identity is invalid")
    }
    if (root["commitSha"] != checkedOutCommitSha()) {
        throw GradleException("JVM native manifest source SHA does not match the checkout")
    }
    val entries = root["entries"] as? List<*>
        ?: throw GradleException("JVM native manifest entries are invalid")
    if (entries.size != nativeBytes.size) {
        throw GradleException("JVM native manifest entry count is invalid")
    }
    val seenPaths = mutableSetOf<String>()
    for (entryValue in entries) {
        val entry = entryValue as? Map<*, *>
            ?: throw GradleException("JVM native manifest entry is not an object")
        val relativePath = entry["path"] as? String
            ?: throw GradleException("JVM native manifest entry path is invalid")
        if (!seenPaths.add(relativePath)) {
            throw GradleException("JVM native manifest contains a duplicate path")
        }
        val bytes = nativeBytes[relativePath]
            ?: throw GradleException("JVM native manifest contains an unexpected path")
        val size = (entry["size"] as? Number)?.toLong()
            ?: throw GradleException("JVM native manifest entry size is invalid")
        val digest = entry["sha256"] as? String
            ?: throw GradleException("JVM native manifest entry digest is invalid")
        if (size != bytes.size.toLong() || digest != sha256Hex(bytes)) {
            throw GradleException("JVM native manifest does not match packaged native bytes")
        }
    }
    if (seenPaths != nativeBytes.keys) {
        throw GradleException("JVM native manifest does not cover every required native path")
    }
}

kotlin {
    jvmToolchain(21)
    sourceSets {
        main {
            kotlin.srcDir("../../gen/kotlin")
        }
    }
}

java {
    withSourcesJar()
    withJavadocJar()
}

sourceSets {
    named("main") {
        java.srcDir("../../gen/java")
        resources.srcDir(nativeResourcesDir)
    }
    named("test") {
        // SDK tests consume the exact audited corpus used by Rust rather than
        // maintaining a language-specific copy that could drift silently.
        resources.srcDir("../../vectors")
    }
}

val buildHostNativeLibrary = tasks.register<Exec>("buildHostNativeLibrary") {
    group = "build"
    description = "Builds the host Rust JNI library for local JVM tests."
    onlyIf { !configuredNativeResourcesDir.isPresent }
    workingDir = layout.projectDirectory.dir("../..").asFile
    // FFI unwinding is a workspace-owned release invariant. Ambient codegen
    // flags must not override the audited profile used for packaged binaries.
    environment.remove("CARGO_ENCODED_RUSTFLAGS")
    environment.remove("RUSTFLAGS")
    commandLine("cargo", "build", "--locked", "-p", "reallyme-jose-ffi", "--profile", "release-ffi")
}

val stageHostNativeResource = tasks.register<Copy>("stageHostNativeResource") {
    group = "build"
    description = "Stages the host Rust JNI library as a JVM package resource for local tests."
    onlyIf { !configuredNativeResourcesDir.isPresent }
    dependsOn(buildHostNativeLibrary)
    from(layout.projectDirectory.file("../../target/release-ffi/$hostNativeLibraryName"))
    into(nativeResourcesDir.map {
        it.resolve("me/really/jose/native/$hostNativePlatform-$hostNativeArch")
    })
}

val writeHostNativeDigest = tasks.register("writeHostNativeDigest") {
    group = "build"
    description = "Writes bounded integrity metadata for the local host JNI library."
    onlyIf { !configuredNativeResourcesDir.isPresent }
    dependsOn(stageHostNativeResource)
    val library = nativeResourcesDir.map { it.resolve(requiredHostNativeResource) }
    val sidecar = nativeResourcesDir.map { it.resolve(requiredHostNativeDigest) }
    inputs.file(library)
    outputs.file(sidecar)
    doLast {
        val libraryFile = library.get()
        val sidecarFile = sidecar.get()
        sidecarFile.parentFile.mkdirs()
        sidecarFile.writeText(expectedNativeDigestMetadata(libraryFile))
    }
}

dependencies {
    api("com.google.protobuf:protobuf-javalite:4.35.1")
    api("com.google.protobuf:protobuf-kotlin-lite:4.35.1")
    testImplementation("com.google.code.gson:gson:2.11.0")
    testImplementation("org.junit.jupiter:junit-jupiter-api:5.11.4")
    testImplementation(kotlin("test"))
    testRuntimeOnly("org.junit.jupiter:junit-jupiter-engine:5.11.4")
}

tasks.test {
    useJUnitPlatform()
    providers.environmentVariable("REALLYME_JOSE_FFI_LIBRARY_PATH").orNull?.let { libraryPath ->
        systemProperty("reallyme.jose.testLibraryPath", libraryPath)
    }
}

tasks.named("processResources") {
    dependsOn(writeHostNativeDigest)
}

tasks.named<Jar>("sourcesJar") {
    dependsOn(writeHostNativeDigest)
    // Native runtime resources belong only in the executable JAR. Excluding
    // them from source artifacts prevents duplicate binaries and provenance
    // metadata from being distributed through a non-runtime classifier.
    exclude("me/really/jose/native/**")
}

tasks.withType<Javadoc>().configureEach {
    val standardOptions = options as StandardJavadocDocletOptions
    standardOptions.addStringOption("Xdoclint:none", "-quiet")
}

val verifyBundledNativeResources = tasks.register("verifyBundledNativeResources") {
    group = "verification"
    description = "Verifies that release JVM artifacts include every supported native FFI library."
    inputs.dir(nativeResourcesDir)
    doLast {
        val root = nativeResourcesDir.get()
        val missing = requiredNativeResources.filter { relativePath ->
            !root.resolve(relativePath).isFile
        }
        if (missing.isNotEmpty()) {
            throw GradleException(
                "missing ReallyMe JOSE native resources: ${missing.joinToString(", ")}"
            )
        }
        for (relativePath in requiredNativeResources.filter { it.endsWith(".so") || it.endsWith(".dylib") || it.endsWith(".dll") }) {
            val library = root.resolve(relativePath)
            val sidecar = root.resolve("$relativePath.sha256")
            val expected = expectedNativeDigestMetadata(library)
            if (sidecar.readText() != expected) {
                throw GradleException(
                    "ReallyMe JOSE native digest does not match $relativePath"
                )
            }
        }
        val nativePrefix = "me/really/jose/native/"
        val nativeBytes = requiredNativeResources
            .filter { it.endsWith(".so") || it.endsWith(".dylib") || it.endsWith(".dll") }
            .associate { relativePath ->
                relativePath.removePrefix(nativePrefix) to root.resolve(relativePath).readBytes()
            }
        try {
            verifyJvmNativeManifest(
                root.resolve("me/really/jose/native/native-manifest.json").readText(),
                nativeBytes,
            )
        } finally {
            nativeBytes.values.forEach { bytes -> bytes.fill(0) }
        }
    }
}

val verifyHostBundledNativeResource = tasks.register("verifyHostBundledNativeResource") {
    group = "verification"
    description = "Verifies that local JVM artifacts include the host Rust JNI library."
    dependsOn(writeHostNativeDigest)
    inputs.dir(nativeResourcesDir)
    doLast {
        val root = nativeResourcesDir.get()
        if (!root.resolve(requiredHostNativeResource).isFile) {
            throw GradleException(
                "missing ReallyMe JOSE host native resource: $requiredHostNativeResource"
            )
        }
        if (!root.resolve(requiredHostNativeDigest).isFile) {
            throw GradleException(
                "missing ReallyMe JOSE host native digest: $requiredHostNativeDigest"
            )
        }
        if (
            root.resolve(requiredHostNativeDigest).readText() !=
            expectedNativeDigestMetadata(root.resolve(requiredHostNativeResource))
        ) {
            throw GradleException(
                "ReallyMe JOSE host native digest does not match $requiredHostNativeResource"
            )
        }
    }
}

val verifyJarContainsNativeResources = tasks.register("verifyJarContainsNativeResources") {
    group = "verification"
    description = "Verifies that the packaged JVM JAR contains native resources with matching digests."
    val jarTask = tasks.named<Jar>("jar")
    dependsOn(jarTask)
    if (requireFullNativeResources.get()) {
        dependsOn(verifyBundledNativeResources)
    } else {
        dependsOn(verifyHostBundledNativeResource)
    }
    inputs.file(jarTask.flatMap { it.archiveFile })
    doLast {
        val requiredResources = if (requireFullNativeResources.get()) {
            requiredNativeResources
        } else {
            listOf(requiredHostNativeResource, requiredHostNativeDigest)
        }
        ZipFile(jarTask.get().archiveFile.get().asFile).use { archive ->
            for (relativePath in requiredResources) {
                archive.getEntry(relativePath)
                    ?: throw GradleException("JVM JAR is missing native resource: $relativePath")
            }
            val nativeLibraries = requiredResources.filter {
                it.endsWith(".so") || it.endsWith(".dylib") || it.endsWith(".dll")
            }
            for (relativePath in nativeLibraries) {
                val libraryEntry = archive.getEntry(relativePath)
                    ?: throw GradleException("JVM JAR is missing native library: $relativePath")
                val sidecarEntry = archive.getEntry("$relativePath.sha256")
                    ?: throw GradleException("JVM JAR is missing native digest: $relativePath.sha256")
                val bytes = archive.getInputStream(libraryEntry).use { it.readBytes() }
                try {
                    val sidecarText = archive.getInputStream(sidecarEntry)
                        .bufferedReader(Charsets.US_ASCII)
                        .use { it.readText() }
                    if (sidecarText != expectedNativeDigestMetadata(bytes)) {
                        throw GradleException("JVM JAR native digest does not match $relativePath")
                    }
                } finally {
                    bytes.fill(0)
                }
            }
        }
    }
}

tasks.withType<PublishToMavenLocal>().configureEach {
    dependsOn(verifyJarContainsNativeResources)
    if (requireFullNativeResources.get()) {
        dependsOn(verifyBundledNativeResources)
    }
}

tasks.withType<PublishToMavenRepository>().configureEach {
    dependsOn(verifyBundledNativeResources, verifyJarContainsNativeResources)
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
        create<MavenPublication>("maven") {
            artifactId = "jose"
            from(components["java"])
            pom {
                name.set("ReallyMe JOSE")
                description.set("ReallyMe typed JOSE facade for Java and Kotlin/JVM.")
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
    sign(publishing.publications["maven"])
    setRequired {
        gradle.taskGraph.allTasks.any { task ->
            task.name.endsWith("ToRemoteReleaseRepository")
        }
    }
}
