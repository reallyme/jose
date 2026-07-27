#!/usr/bin/env node
// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

import { createHash, timingSafeEqual } from "node:crypto";
import { execFileSync } from "node:child_process";
import { lstatSync, readFileSync } from "node:fs";
import { resolve } from "node:path";

const VERSION_PATTERN = /^(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)$/u;
const MAX_ARTIFACT_BYTES = 536_870_912;
const MAX_NATIVE_LIBRARY_BYTES = 134_217_728;
const MAX_MANIFEST_BYTES = 1_048_576;
const FULL_SHA_PATTERN = /^[0-9a-f]{40}$/u;
const SHA256_PATTERN = /^[0-9a-f]{64}$/u;

const fail = (reason) => {
  console.error(`Maven release repository verification failed: ${reason}`);
  process.exit(1);
};

const [, , rootArgument, version, mode = "--all"] = process.argv;
if (
  rootArgument === undefined ||
  version === undefined ||
  !VERSION_PATTERN.test(version) ||
  !["--all", "--jvm-only", "--android-only"].includes(mode)
) {
  fail("expected repository root, semantic version, and optional package selection");
}
const root = resolve(rootArgument);

const expectedSourceSha = () => {
  let checkedOutSha;
  try {
    checkedOutSha = execFileSync("git", ["rev-parse", "HEAD"], {
      encoding: "utf8",
      maxBuffer: 1024,
      stdio: ["ignore", "pipe", "ignore"],
    }).trim();
  } catch {
    fail("unable to determine checked-out source SHA");
  }
  if (!FULL_SHA_PATTERN.test(checkedOutSha)) {
    fail("checked-out source SHA is malformed");
  }
  const releaseSha = process.env.RELEASE_SHA;
  if (releaseSha !== undefined && (!FULL_SHA_PATTERN.test(releaseSha) || releaseSha !== checkedOutSha)) {
    fail("release SHA does not match the checked-out source");
  }
  return checkedOutSha;
};
const sourceSha = expectedSourceSha();

const requireRegular = (relativePath, maximumBytes = MAX_ARTIFACT_BYTES) => {
  const path = resolve(root, relativePath);
  let status;
  try { status = lstatSync(path); } catch { fail(`missing ${relativePath}`); }
  if (status.isSymbolicLink() || !status.isFile() || status.size < 1 || status.size > maximumBytes) {
    fail(`${relativePath} is not a bounded regular file`);
  }
  return { path, size: status.size };
};

const readRegularBytes = (relativePath, maximumBytes) => {
  const file = requireRegular(relativePath, maximumBytes);
  let bytes;
  try { bytes = readFileSync(file.path); } catch { fail(`${relativePath} cannot be read`); }
  if (bytes.length !== file.size) {
    bytes.fill(0);
    fail(`${relativePath} changed while it was read`);
  }
  return bytes;
};

const jvmPrefix = `me/really/jose/${version}/jose-${version}`;
const androidPrefix = `me/really/jose-android/${version}/jose-android-${version}`;
const verifiesJvm = mode !== "--android-only";
const verifiesAndroid = mode !== "--jvm-only";
const jvmJar = verifiesJvm ? requireRegular(`${jvmPrefix}.jar`).path : undefined;
const androidAar = verifiesAndroid ? requireRegular(`${androidPrefix}.aar`).path : undefined;
const metadataFiles = [];
if (verifiesJvm) metadataFiles.push(
  `${jvmPrefix}-sources.jar`, `${jvmPrefix}-javadoc.jar`, `${jvmPrefix}.pom`, `${jvmPrefix}.module`,
);
if (verifiesAndroid) metadataFiles.push(
  `${androidPrefix}-sources.jar`, `${androidPrefix}.pom`, `${androidPrefix}.module`,
);
for (const relativePath of metadataFiles) requireRegular(relativePath);

const listArchive = (path) => {
  try {
    return execFileSync("unzip", ["-Z1", path], {
      encoding: "utf8",
      maxBuffer: 16_777_216,
      stdio: ["ignore", "pipe", "ignore"],
    }).split("\n").filter(Boolean);
  } catch { fail("a package archive cannot be listed"); }
};

const readArchiveEntry = (path, entry, maximumBytes) => {
  try {
    return execFileSync("unzip", ["-p", path, entry], {
      maxBuffer: maximumBytes,
      stdio: ["ignore", "pipe", "ignore"],
    });
  } catch {
    fail("a bounded package archive entry cannot be read");
  }
};

const verifyNativeManifest = (archive, entry, packageName, archivePrefix, expectedLibraries) => {
  let manifest;
  try {
    manifest = JSON.parse(
      readArchiveEntry(archive, entry, MAX_MANIFEST_BYTES).toString("utf8"),
    );
  } catch {
    fail(`${packageName} native manifest is malformed`);
  }
  if (
    manifest?.schemaVersion !== 1 ||
    manifest?.package !== "reallyme-jose-native" ||
    manifest?.commitSha !== sourceSha ||
    !Array.isArray(manifest?.entries) ||
    manifest.entries.length === 0
  ) {
    fail(`${packageName} native manifest is not bound to the release source SHA`);
  }
  const expectedPaths = expectedLibraries
    .map((library) => library.slice(archivePrefix.length))
    .sort();
  const manifestPaths = [];
  for (const manifestEntry of manifest.entries) {
    if (
      manifestEntry === null ||
      typeof manifestEntry !== "object" ||
      Array.isArray(manifestEntry) ||
      Object.keys(manifestEntry).sort().join(",") !== "path,sha256,size" ||
      typeof manifestEntry.path !== "string" ||
      !SHA256_PATTERN.test(manifestEntry.sha256) ||
      !Number.isSafeInteger(manifestEntry.size) ||
      manifestEntry.size < 1 ||
      manifestEntry.size > MAX_NATIVE_LIBRARY_BYTES
    ) {
      fail(`${packageName} native manifest contains an invalid entry`);
    }
    manifestPaths.push(manifestEntry.path);
    const archivePath = `${archivePrefix}${manifestEntry.path}`;
    if (!expectedLibraries.includes(archivePath)) {
      fail(`${packageName} native manifest contains an unexpected path`);
    }
    const bytes = readArchiveEntry(archive, archivePath, MAX_NATIVE_LIBRARY_BYTES);
    const expectedDigest = Buffer.from(manifestEntry.sha256, "hex");
    const actualDigest = createHash("sha256").update(bytes).digest();
    const matches =
      bytes.length === manifestEntry.size &&
      expectedDigest.length === actualDigest.length &&
      timingSafeEqual(expectedDigest, actualDigest);
    if (packageName === "JVM") {
      const sidecar = readArchiveEntry(archive, `${archivePath}.sha256`, 256);
      const expectedSidecar = Buffer.from(`${manifestEntry.sha256} ${manifestEntry.size}\n`, "ascii");
      const sidecarMatches =
        sidecar.length === expectedSidecar.length &&
        timingSafeEqual(sidecar, expectedSidecar);
      sidecar.fill(0);
      expectedSidecar.fill(0);
      if (!sidecarMatches) {
        bytes.fill(0);
        expectedDigest.fill(0);
        actualDigest.fill(0);
        fail("JVM native digest sidecar does not match its manifest entry");
      }
    }
    bytes.fill(0);
    expectedDigest.fill(0);
    actualDigest.fill(0);
    if (!matches) {
      fail(`${packageName} native library bytes do not match the manifest`);
    }
  }
  if (
    manifestPaths.length !== expectedPaths.length ||
    manifestPaths.sort().some((path, index) => path !== expectedPaths[index])
  ) {
    fail(`${packageName} native manifest inventory is not exact`);
  }
};

if (verifiesJvm) {
  const jvmEntries = new Set(listArchive(jvmJar));
  const requiredJvmNativeEntries = [
    "me/really/jose/native/linux-x86_64/libreallyme_jose_ffi.so",
    "me/really/jose/native/linux-aarch64/libreallyme_jose_ffi.so",
    "me/really/jose/native/macos-x86_64/libreallyme_jose_ffi.dylib",
    "me/really/jose/native/macos-aarch64/libreallyme_jose_ffi.dylib",
    "me/really/jose/native/windows-x86_64/reallyme_jose_ffi.dll",
    "me/really/jose/native/native-manifest.json",
  ];
  for (const entry of requiredJvmNativeEntries) {
    if (!jvmEntries.has(entry) || (entry !== "me/really/jose/native/native-manifest.json" && !jvmEntries.has(`${entry}.sha256`))) {
      fail(`JVM artifact is missing ${entry} or its digest`);
    }
  }
  const exactJvmNativeEntries = requiredJvmNativeEntries.flatMap((entry) =>
    entry.endsWith("native-manifest.json") ? [entry] : [entry, `${entry}.sha256`]
  ).sort();
  const actualJvmNativeEntries = [...jvmEntries]
    .filter((entry) => entry.startsWith("me/really/jose/native/") && !entry.endsWith("/"))
    .sort();
  if (JSON.stringify(actualJvmNativeEntries) !== JSON.stringify(exactJvmNativeEntries)) {
    fail("JVM artifact native inventory is not exact");
  }
  verifyNativeManifest(
    jvmJar,
    "me/really/jose/native/native-manifest.json",
    "JVM",
    "me/really/jose/native/",
    requiredJvmNativeEntries.filter((entry) => !entry.endsWith("native-manifest.json")),
  );
}

if (verifiesAndroid) {
  const androidEntries = new Set(listArchive(androidAar));
  for (const abi of ["arm64-v8a", "armeabi-v7a", "x86_64", "x86"]) {
    if (!androidEntries.has(`jni/${abi}/libreallyme_jose_ffi.so`)) {
      fail(`Android artifact is missing ${abi}`);
    }
  }
  if (!androidEntries.has("assets/reallyme-jose/native-manifest.json")) {
    fail("Android artifact is missing its native manifest");
  }
  const expectedAndroidLibraries = ["arm64-v8a", "armeabi-v7a", "x86_64", "x86"]
    .map((abi) => `jni/${abi}/libreallyme_jose_ffi.so`)
    .sort();
  const actualAndroidLibraries = [...androidEntries]
    .filter((entry) => entry.startsWith("jni/") && entry.endsWith(".so"))
    .sort();
  if (JSON.stringify(actualAndroidLibraries) !== JSON.stringify(expectedAndroidLibraries)) {
    fail("Android artifact native inventory is not exact");
  }
  verifyNativeManifest(
    androidAar,
    "assets/reallyme-jose/native-manifest.json",
    "Android",
    "jni/",
    expectedAndroidLibraries,
  );
}

const sourceArchives = [];
if (verifiesJvm) sourceArchives.push([`${jvmPrefix}-sources.jar`, "me/really/jose/native/"]);
if (verifiesAndroid) sourceArchives.push([`${androidPrefix}-sources.jar`, "jni/"]);
if (verifiesAndroid) sourceArchives.push([`${androidPrefix}-sources.jar`, "assets/reallyme-jose/"]);
for (const [artifact, prefix] of sourceArchives) {
  if (listArchive(requireRegular(artifact).path).some((entry) => entry.startsWith(prefix))) {
    fail(`${artifact} contains release native binaries`);
  }
}

const packages = [];
if (verifiesJvm) packages.push([jvmPrefix, "jose"]);
if (verifiesAndroid) packages.push([androidPrefix, "jose-android"]);
for (const [prefix, artifact] of packages) {
  const pom = readRegularBytes(`${prefix}.pom`, 1_048_576).toString("utf8");
  for (const value of [
    "<groupId>me.really</groupId>",
    `<artifactId>${artifact}</artifactId>`,
    `<version>${version}</version>`,
    "<name>Apache License, Version 2.0</name>",
    "https://github.com/reallyme/jose",
  ]) {
    if (!pom.includes(value)) fail(`${artifact} POM is missing required release metadata`);
  }
  let moduleMetadata;
  try { moduleMetadata = JSON.parse(readRegularBytes(`${prefix}.module`, 4_194_304).toString("utf8")); }
  catch { fail(`${artifact} Gradle module metadata is malformed`); }
  if (
    moduleMetadata?.component?.group !== "me.really" ||
    moduleMetadata?.component?.module !== artifact ||
    moduleMetadata?.component?.version !== version
  ) {
    fail(`${artifact} Gradle module identity is incorrect`);
  }
}

console.log("Selected Maven publication artifacts, metadata, and native inventories verified");
