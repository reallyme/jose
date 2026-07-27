#!/usr/bin/env node
// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

import { createHash, timingSafeEqual } from "node:crypto";
import { createReadStream } from "node:fs";
import { pathToFileURL } from "node:url";
import {
  collectMavenReleaseFiles,
  MavenReleaseFileError,
} from "./collect_maven_release_files.mjs";

export const MavenPromotionReason = Object.freeze({
  INVALID_ARGUMENTS: "invalid-arguments",
  INVALID_REPOSITORY: "invalid-repository",
  MISSING_CREDENTIALS: "missing-repository-credentials",
  REMOTE_CHECK_FAILED: "remote-existence-check-failed",
  VERSION_EXISTS: "release-version-already-exists",
  UPLOAD_FAILED: "release-upload-failed",
  REMOTE_VERIFY_FAILED: "remote-byte-verification-failed",
  ROLLBACK_FAILED: "partial-release-rollback-failed",
});

export class MavenPromotionError extends Error {
  constructor(reason) {
    super(reason);
    this.name = "MavenPromotionError";
    this.reason = reason;
  }
}

const requireRepositoryUrl = (value) => {
  let url;
  try {
    url = new URL(value);
  } catch {
    throw new MavenPromotionError(MavenPromotionReason.INVALID_REPOSITORY);
  }
  if (
    url.protocol !== "https:" ||
    url.username.length !== 0 ||
    url.password.length !== 0 ||
    url.search.length !== 0 ||
    url.hash.length !== 0
  ) {
    throw new MavenPromotionError(MavenPromotionReason.INVALID_REPOSITORY);
  }
  if (!url.pathname.endsWith("/")) {
    url.pathname = `${url.pathname}/`;
  }
  return url;
};

const releaseUrl = (repositoryUrl, relativePath) => {
  const encodedPath = relativePath.split("/").map(encodeURIComponent).join("/");
  return new URL(encodedPath, repositoryUrl);
};

const discardBody = async (response) => {
  if (response.body !== null) {
    try {
      await response.body.cancel();
    } catch {
      // The status code remains authoritative when a server closes early.
    }
  }
};

const requireAbsent = async (fetchImpl, repositoryUrl, headers, relativePath) => {
  let response;
  try {
    response = await fetchImpl(releaseUrl(repositoryUrl, relativePath), {
      headers: { ...headers, Range: "bytes=0-0" },
      method: "GET",
      redirect: "error",
      signal: AbortSignal.timeout(30_000),
    });
  } catch {
    throw new MavenPromotionError(MavenPromotionReason.REMOTE_CHECK_FAILED);
  }
  await discardBody(response);
  if (response.status === 404) {
    return;
  }
  if (response.status === 200 || response.status === 206) {
    throw new MavenPromotionError(MavenPromotionReason.VERSION_EXISTS);
  }
  throw new MavenPromotionError(MavenPromotionReason.REMOTE_CHECK_FAILED);
};

const uploadFile = async (fetchImpl, repositoryUrl, headers, file) => {
  const body = createReadStream(file.absolutePath);
  // fetch normally owns stream errors. Keeping a local listener also contains
  // late open failures when a test double or repository rejects before reading.
  body.on("error", () => {});
  let response;
  try {
    response = await fetchImpl(releaseUrl(repositoryUrl, file.relativePath), {
      body,
      duplex: "half",
      headers: {
        ...headers,
        "Content-Length": String(file.size),
        "Content-Type": "application/octet-stream",
        "If-None-Match": "*",
      },
      method: "PUT",
      redirect: "error",
      signal: AbortSignal.timeout(120_000),
    });
  } catch {
    body.destroy();
    throw new MavenPromotionError(MavenPromotionReason.UPLOAD_FAILED);
  }
  await discardBody(response);
  if (![200, 201, 204].includes(response.status)) {
    body.destroy();
    if (response.status === 409 || response.status === 412) {
      throw new MavenPromotionError(MavenPromotionReason.VERSION_EXISTS);
    }
    throw new MavenPromotionError(MavenPromotionReason.UPLOAD_FAILED);
  }
};

const verifyRemoteFile = async (fetchImpl, repositoryUrl, headers, file) => {
  let response;
  try {
    response = await fetchImpl(releaseUrl(repositoryUrl, file.relativePath), {
      headers,
      method: "GET",
      redirect: "error",
      signal: AbortSignal.timeout(120_000),
    });
  } catch {
    throw new MavenPromotionError(MavenPromotionReason.REMOTE_VERIFY_FAILED);
  }
  if (response.status !== 200 || response.body === null) {
    await discardBody(response);
    throw new MavenPromotionError(MavenPromotionReason.REMOTE_VERIFY_FAILED);
  }

  const contentLength = response.headers.get("content-length");
  if (contentLength !== null && contentLength !== String(file.size)) {
    await discardBody(response);
    throw new MavenPromotionError(MavenPromotionReason.REMOTE_VERIFY_FAILED);
  }

  const hash = createHash("sha256");
  const reader = response.body.getReader();
  let totalLength = 0;
  while (true) {
    let part;
    try {
      part = await reader.read();
    } catch {
      throw new MavenPromotionError(MavenPromotionReason.REMOTE_VERIFY_FAILED);
    }
    if (part.done) {
      break;
    }
    if (!(part.value instanceof Uint8Array) || part.value.length > file.size - totalLength) {
      throw new MavenPromotionError(MavenPromotionReason.REMOTE_VERIFY_FAILED);
    }
    totalLength += part.value.length;
    hash.update(part.value);
  }
  const expectedDigest = Buffer.from(file.sha256, "hex");
  const actualDigest = hash.digest();
  const matches =
    totalLength === file.size &&
    expectedDigest.length === actualDigest.length &&
    timingSafeEqual(expectedDigest, actualDigest);
  expectedDigest.fill(0);
  actualDigest.fill(0);
  if (!matches) {
    throw new MavenPromotionError(MavenPromotionReason.REMOTE_VERIFY_FAILED);
  }
};

const rollback = async (fetchImpl, repositoryUrl, headers, uploadedFiles) => {
  let complete = true;
  for (const file of [...uploadedFiles].reverse()) {
    try {
      const response = await fetchImpl(releaseUrl(repositoryUrl, file.relativePath), {
        headers,
        method: "DELETE",
        redirect: "error",
        signal: AbortSignal.timeout(30_000),
      });
      await discardBody(response);
      if (![200, 202, 204, 404].includes(response.status)) {
        complete = false;
      }
    } catch {
      complete = false;
    }
  }
  return complete;
};

export const promoteMavenRelease = async ({
  fetchImpl = fetch,
  password,
  repository,
  root,
  username,
  version,
}) => {
  if (
    typeof username !== "string" ||
    username.trim().length === 0 ||
    typeof password !== "string" ||
    password.length === 0 ||
    username.includes("\n") ||
    username.includes("\r") ||
    password.includes("\n") ||
    password.includes("\r")
  ) {
    throw new MavenPromotionError(MavenPromotionReason.MISSING_CREDENTIALS);
  }
  const repositoryUrl = requireRepositoryUrl(repository);
  let release;
  try {
    release = await collectMavenReleaseFiles(root, version, true);
  } catch (error) {
    if (error instanceof MavenReleaseFileError) {
      throw error;
    }
    throw new MavenPromotionError(MavenPromotionReason.INVALID_ARGUMENTS);
  }

  const credentialBytes = Buffer.from(`${username}:${password}`, "utf8");
  const authorization = `Basic ${credentialBytes.toString("base64")}`;
  credentialBytes.fill(0);
  const headers = Object.freeze({
    Authorization: authorization,
    "User-Agent": "reallyme-jose-release/1",
  });
  for (const packageDefinition of release.packages) {
    await requireAbsent(
      fetchImpl,
      repositoryUrl,
      headers,
      packageDefinition.markerRelativePath,
    );
  }

  const markerPaths = new Set(release.packages.map((value) => value.markerRelativePath));
  const orderedFiles = [
    ...release.files.filter((file) => !markerPaths.has(file.relativePath)),
    ...release.files.filter((file) => markerPaths.has(file.relativePath)),
  ];
  const uploadedFiles = [];
  try {
    for (const file of orderedFiles) {
      await uploadFile(fetchImpl, repositoryUrl, headers, file);
      uploadedFiles.push(file);
    }
    for (const file of orderedFiles) {
      await verifyRemoteFile(fetchImpl, repositoryUrl, headers, file);
    }
  } catch (error) {
    if (!(await rollback(fetchImpl, repositoryUrl, headers, uploadedFiles))) {
      throw new MavenPromotionError(MavenPromotionReason.ROLLBACK_FAILED);
    }
    throw error;
  }
};

const isMain = process.argv[1] !== undefined &&
  import.meta.url === pathToFileURL(process.argv[1]).href;
if (isMain) {
  const [, , root, version] = process.argv;
  if (root === undefined || version === undefined || process.argv.length !== 4) {
    console.error(`Maven release promotion failed: ${MavenPromotionReason.INVALID_ARGUMENTS}`);
    process.exit(1);
  }
  try {
    await promoteMavenRelease({
      password: process.env.REALLYME_MAVEN_PASSWORD,
      repository: process.env.REALLYME_MAVEN_REPOSITORY_URL,
      root,
      username: process.env.REALLYME_MAVEN_USERNAME,
      version,
    });
    console.log("Signed JVM and Android Maven artifacts promoted and byte-verified");
  } catch (error) {
    const reason = error instanceof MavenPromotionError || error instanceof MavenReleaseFileError
      ? error.reason
      : MavenPromotionReason.INVALID_ARGUMENTS;
    console.error(`Maven release promotion failed: ${reason}`);
    process.exit(1);
  }
}
