#!/usr/bin/env node
// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

import { readFileSync, writeFileSync } from "node:fs";
import { posix, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const root = resolve(fileURLToPath(new URL("..", import.meta.url)));
const manifestPath = resolve(root, "Package.swift");
const usage =
  "usage: node scripts/prepare_swift_binary_manifest.mjs <version> <checksum> [--local-artifact-path <relative-path>]";

export class SwiftManifestError extends Error {
  constructor(code) {
    super(code);
    this.name = "SwiftManifestError";
    this.code = code;
  }
}

const fail = (reason) => {
  throw new SwiftManifestError(reason);
};

const replaceAssignment = (source, name, value) => {
  const expression = new RegExp(`^let ${name}\\s*=\\s*"[^"]*"$`, "gmu");
  const matches = [...source.matchAll(expression)];
  if (matches.length !== 1) {
    fail(`invalid-${name}-assignment-count`);
  }
  return source.replace(expression, `let ${name} = "${value}"`);
};

export const prepareManifest = (source, version, checksum, localArtifactPath = "") => {
  if (!/^(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)$/u.test(version)) {
    fail("invalid-version");
  }
  if (!/^[0-9a-f]{64}$/u.test(checksum)) {
    fail("invalid-checksum");
  }
  if (
    typeof localArtifactPath !== "string" ||
    localArtifactPath.startsWith("/") ||
    localArtifactPath.includes("\\") ||
    (localArtifactPath !== "" && !/^[A-Za-z0-9._/-]+$/u.test(localArtifactPath))
  ) {
    fail("invalid-local-artifact-path");
  }
  const normalizedPath = localArtifactPath === "" ? "" : posix.normalize(localArtifactPath);
  if (
    normalizedPath === "." ||
    normalizedPath.startsWith("../") ||
    normalizedPath.includes("/../")
  ) {
    fail("invalid-local-artifact-path");
  }
  let manifest = replaceAssignment(source, "ffiArtifactChecksum", checksum);
  manifest = replaceAssignment(manifest, "ffiArtifactVersion", version);
  return replaceAssignment(manifest, "ffiArtifactLocalPathOverride", normalizedPath);
};

const isMain = process.argv[1] !== undefined && fileURLToPath(import.meta.url) === process.argv[1];
if (isMain) {
  try {
    const [, , version, checksum, ...options] = process.argv;
    if (
      version === undefined ||
      checksum === undefined ||
      (options.length !== 0 && options.length !== 2) ||
      (options.length === 2 && options[0] !== "--local-artifact-path")
    ) {
      fail(usage);
    }
    const localArtifactPath = options.length === 2 ? options[1] : "";
    const manifest = prepareManifest(
      readFileSync(manifestPath, "utf8"),
      version,
      checksum,
      localArtifactPath,
    );
    writeFileSync(manifestPath, manifest, { encoding: "utf8" });
  } catch (error) {
    const reason = error instanceof SwiftManifestError ? error.code : "unexpected-failure";
    console.error(`prepare Swift binary manifest failed: ${reason}`);
    process.exit(1);
  }
}
