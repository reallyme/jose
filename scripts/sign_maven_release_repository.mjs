#!/usr/bin/env node
// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

import { createHash } from "node:crypto";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { spawnSync } from "node:child_process";
import {
  collectMavenReleaseFiles,
  MavenReleaseFileError,
} from "./collect_maven_release_files.mjs";

const CHECKSUMS = Object.freeze([
  Object.freeze({ extension: ".md5", algorithm: "md5" }),
  Object.freeze({ extension: ".sha1", algorithm: "sha1" }),
  Object.freeze({ extension: ".sha256", algorithm: "sha256" }),
  Object.freeze({ extension: ".sha512", algorithm: "sha512" }),
]);

const SigningReason = Object.freeze({
  INVALID_ARGUMENTS: "invalid-arguments",
  MISSING_CREDENTIALS: "missing-signing-credentials",
  INVALID_CREDENTIALS: "invalid-signing-credentials",
  AGENT_FAILED: "signing-agent-start-failed",
  IMPORT_FAILED: "signing-key-import-failed",
  SIGNING_FAILED: "artifact-signing-failed",
  VERIFY_FAILED: "artifact-signature-verification-failed",
});

class MavenSigningError extends Error {
  constructor(reason) {
    super(reason);
    this.name = "MavenSigningError";
    this.reason = reason;
  }
}

const fail = (reason) => {
  console.error(`Maven release signing failed: ${reason}`);
  process.exit(1);
};

const [, , root, version] = process.argv;
if (root === undefined || version === undefined || process.argv.length !== 4) {
  fail(SigningReason.INVALID_ARGUMENTS);
}

const signingKey = process.env.MAVEN_SIGNING_KEY;
const signingPassword = process.env.MAVEN_SIGNING_PASSWORD;
if (
  typeof signingKey !== "string" ||
  signingKey.trim().length === 0 ||
  typeof signingPassword !== "string" ||
  signingPassword.length === 0
) {
  fail(SigningReason.MISSING_CREDENTIALS);
}
if (signingPassword.includes("\n") || signingPassword.includes("\r")) {
  fail(SigningReason.INVALID_CREDENTIALS);
}

let unsignedRelease;
try {
  unsignedRelease = await collectMavenReleaseFiles(root, version, false);
} catch (error) {
  fail(error instanceof MavenReleaseFileError ? error.reason : SigningReason.INVALID_ARGUMENTS);
}

const keyBytes = Buffer.from(signingKey, "utf8");
const passwordBytes = Buffer.from(`${signingPassword}\n`, "utf8");
const gpgHome = mkdtempSync(join(tmpdir(), "reallyme-jose-maven-signing-"));
const createdFiles = [];
let signingError;

try {
  const agent = spawnSync(
    "gpgconf",
    ["--homedir", gpgHome, "--launch", "gpg-agent"],
    { maxBuffer: 1_048_576, stdio: ["ignore", "ignore", "ignore"] },
  );
  if (agent.error !== undefined || agent.status !== 0) {
    throw new MavenSigningError(SigningReason.AGENT_FAILED);
  }
  const imported = spawnSync(
    "gpg",
    ["--batch", "--no-tty", "--homedir", gpgHome, "--import"],
    { input: keyBytes, maxBuffer: 1_048_576, stdio: ["pipe", "ignore", "ignore"] },
  );
  if (imported.error !== undefined || imported.status !== 0) {
    throw new MavenSigningError(SigningReason.IMPORT_FAILED);
  }

  for (const file of unsignedRelease.baseFiles) {
    const signaturePath = `${file.absolutePath}.asc`;
    const signed = spawnSync(
      "gpg",
      [
        "--batch",
        "--no-tty",
        "--homedir",
        gpgHome,
        "--armor",
        "--detach-sign",
        "--digest-algo",
        "SHA256",
        "--pinentry-mode",
        "loopback",
        "--passphrase-fd",
        "0",
        "--output",
        signaturePath,
        file.absolutePath,
      ],
      { input: passwordBytes, maxBuffer: 1_048_576, stdio: ["pipe", "ignore", "ignore"] },
    );
    if (signed.error !== undefined || signed.status !== 0) {
      throw new MavenSigningError(SigningReason.SIGNING_FAILED);
    }
    createdFiles.push(signaturePath);
    const verified = spawnSync(
      "gpg",
      [
        "--batch",
        "--no-tty",
        "--homedir",
        gpgHome,
        "--verify",
        signaturePath,
        file.absolutePath,
      ],
      { maxBuffer: 1_048_576, stdio: ["ignore", "ignore", "ignore"] },
    );
    if (verified.error !== undefined || verified.status !== 0) {
      throw new MavenSigningError(SigningReason.VERIFY_FAILED);
    }
    const signatureBytes = readFileSync(signaturePath);
    try {
      for (const checksum of CHECKSUMS) {
        const checksumPath = `${signaturePath}${checksum.extension}`;
        writeFileSync(
          checksumPath,
          createHash(checksum.algorithm).update(signatureBytes).digest("hex"),
          { encoding: "ascii", mode: 0o600 },
        );
        createdFiles.push(checksumPath);
      }
    } finally {
      signatureBytes.fill(0);
    }
  }

  await collectMavenReleaseFiles(root, version, true);
  console.log("Maven release repository signed with an isolated temporary keyring");
} catch (error) {
  signingError = error;
  for (const path of createdFiles) {
    rmSync(path, { force: true });
  }
} finally {
  keyBytes.fill(0);
  passwordBytes.fill(0);
  spawnSync(
    "gpgconf",
    ["--homedir", gpgHome, "--kill", "gpg-agent"],
    { maxBuffer: 1_048_576, stdio: ["ignore", "ignore", "ignore"] },
  );
  rmSync(gpgHome, { force: true, recursive: true });
}

if (signingError !== undefined) {
  if (signingError instanceof MavenSigningError || signingError instanceof MavenReleaseFileError) {
    fail(signingError.reason);
  }
  fail(SigningReason.SIGNING_FAILED);
}
