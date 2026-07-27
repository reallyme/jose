#!/usr/bin/env node
// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

import { createHash } from "node:crypto";
import { createReadStream, lstatSync, readFileSync, readdirSync } from "node:fs";
import { resolve } from "node:path";

const VERSION_PATTERN = /^(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)$/u;
const MAX_RELEASE_FILE_BYTES = 536_870_912;
const MAX_CHECKSUM_FILE_BYTES = 256;
const CHECKSUMS = Object.freeze([
  Object.freeze({ extension: ".md5", algorithm: "md5", length: 32 }),
  Object.freeze({ extension: ".sha1", algorithm: "sha1", length: 40 }),
  Object.freeze({ extension: ".sha256", algorithm: "sha256", length: 64 }),
  Object.freeze({ extension: ".sha512", algorithm: "sha512", length: 128 }),
]);

export const MavenReleaseFileReason = Object.freeze({
  INVALID_VERSION: "invalid-version",
  INVALID_ROOT: "invalid-root",
  INVALID_INVENTORY: "invalid-inventory",
  INVALID_FILE: "invalid-file",
  INVALID_CHECKSUM: "invalid-checksum",
  READ_FAILED: "read-failed",
});

export class MavenReleaseFileError extends Error {
  constructor(reason) {
    super(reason);
    this.name = "MavenReleaseFileError";
    this.reason = reason;
  }
}

const PACKAGE_DEFINITIONS = Object.freeze([
  Object.freeze({
    directory: "me/really/jose",
    artifact: "jose",
    suffixes: Object.freeze([".jar", "-sources.jar", "-javadoc.jar", ".pom", ".module"]),
  }),
  Object.freeze({
    directory: "me/really/jose-android",
    artifact: "jose-android",
    suffixes: Object.freeze([".aar", "-sources.jar", ".pom", ".module"]),
  }),
]);

const requireDirectory = (path) => {
  let status;
  try {
    status = lstatSync(path);
  } catch {
    throw new MavenReleaseFileError(MavenReleaseFileReason.INVALID_ROOT);
  }
  if (status.isSymbolicLink() || !status.isDirectory()) {
    throw new MavenReleaseFileError(MavenReleaseFileReason.INVALID_ROOT);
  }
};

const requireRegularFile = (path) => {
  let status;
  try {
    status = lstatSync(path);
  } catch {
    throw new MavenReleaseFileError(MavenReleaseFileReason.INVALID_FILE);
  }
  if (
    status.isSymbolicLink() ||
    !status.isFile() ||
    status.size < 1 ||
    status.size > MAX_RELEASE_FILE_BYTES
  ) {
    throw new MavenReleaseFileError(MavenReleaseFileReason.INVALID_FILE);
  }
  return status.size;
};

const digestFile = async (path, algorithm) => {
  const hash = createHash(algorithm);
  try {
    await new Promise((resolveStream, rejectStream) => {
      const stream = createReadStream(path);
      stream.on("data", (chunk) => hash.update(chunk));
      stream.on("error", rejectStream);
      stream.on("end", resolveStream);
    });
  } catch {
    throw new MavenReleaseFileError(MavenReleaseFileReason.READ_FAILED);
  }
  return hash.digest("hex");
};

const requireExactInventory = (directory, expectedNames) => {
  let actualNames;
  try {
    actualNames = readdirSync(directory).sort();
  } catch {
    throw new MavenReleaseFileError(MavenReleaseFileReason.INVALID_INVENTORY);
  }
  const sortedExpected = [...expectedNames].sort();
  if (
    actualNames.length !== sortedExpected.length ||
    actualNames.some((name, index) => name !== sortedExpected[index])
  ) {
    throw new MavenReleaseFileError(MavenReleaseFileReason.INVALID_INVENTORY);
  }
};

export const describeMavenRelease = (version) => {
  if (!VERSION_PATTERN.test(version)) {
    throw new MavenReleaseFileError(MavenReleaseFileReason.INVALID_VERSION);
  }
  return PACKAGE_DEFINITIONS.map((definition) => {
    const versionDirectory = `${definition.directory}/${version}`;
    const baseNames = definition.suffixes.map(
      (suffix) => `${definition.artifact}-${version}${suffix}`,
    );
    return Object.freeze({
      ...definition,
      versionDirectory,
      markerRelativePath: `${versionDirectory}/${definition.artifact}-${version}.pom`,
      baseNames: Object.freeze(baseNames),
    });
  });
};

export const collectMavenReleaseFiles = async (rootArgument, version, requireSignatures) => {
  const root = resolve(rootArgument);
  requireDirectory(root);
  const packages = describeMavenRelease(version);
  const baseFiles = [];
  const files = [];

  for (const packageDefinition of packages) {
    const versionDirectory = resolve(root, packageDefinition.versionDirectory);
    requireDirectory(versionDirectory);
    const signedNames = requireSignatures
      ? packageDefinition.baseNames.map((name) => `${name}.asc`)
      : [];
    const contentNames = [...packageDefinition.baseNames, ...signedNames];
    const expectedNames = contentNames.flatMap((name) => [
      name,
      ...CHECKSUMS.map((checksum) => `${name}${checksum.extension}`),
    ]);
    requireExactInventory(versionDirectory, expectedNames);

    for (const name of contentNames) {
      const absolutePath = resolve(versionDirectory, name);
      const size = requireRegularFile(absolutePath);
      const relativePath = `${packageDefinition.versionDirectory}/${name}`;
      const sha256 = await digestFile(absolutePath, "sha256");
      const file = Object.freeze({ absolutePath, relativePath, sha256, size });
      files.push(file);
      if (!name.endsWith(".asc")) {
        baseFiles.push(file);
      }

      for (const checksum of CHECKSUMS) {
        const checksumName = `${name}${checksum.extension}`;
        const checksumPath = resolve(versionDirectory, checksumName);
        const checksumSize = requireRegularFile(checksumPath);
        if (checksumSize > MAX_CHECKSUM_FILE_BYTES) {
          throw new MavenReleaseFileError(MavenReleaseFileReason.INVALID_CHECKSUM);
        }
        let expected;
        try {
          expected = readFileSync(checksumPath, "ascii").trim();
        } catch {
          throw new MavenReleaseFileError(MavenReleaseFileReason.READ_FAILED);
        }
        if (
          expected.length !== checksum.length ||
          !/^[0-9a-f]+$/u.test(expected) ||
          expected !== await digestFile(absolutePath, checksum.algorithm)
        ) {
          throw new MavenReleaseFileError(MavenReleaseFileReason.INVALID_CHECKSUM);
        }
        files.push(Object.freeze({
          absolutePath: checksumPath,
          relativePath: `${packageDefinition.versionDirectory}/${checksumName}`,
          sha256: await digestFile(checksumPath, "sha256"),
          size: checksumSize,
        }));
      }
    }
  }

  return Object.freeze({
    baseFiles: Object.freeze(baseFiles),
    files: Object.freeze(files.sort((left, right) => left.relativePath.localeCompare(right.relativePath))),
    packages: Object.freeze(packages),
  });
};
