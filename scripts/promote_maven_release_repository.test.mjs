// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { spawnSync } from "node:child_process";
import test from "node:test";
import { fileURLToPath } from "node:url";
import {
  collectMavenReleaseFiles,
  describeMavenRelease,
  MavenReleaseFileError,
  MavenReleaseFileReason,
} from "./collect_maven_release_files.mjs";
import {
  MavenPromotionError,
  MavenPromotionReason,
  promoteMavenRelease,
} from "./promote_maven_release_repository.mjs";

const VERSION = "0.3.0";
const signingScript = fileURLToPath(new URL("./sign_maven_release_repository.mjs", import.meta.url));
const CHECKSUMS = Object.freeze([
  Object.freeze({ extension: ".md5", algorithm: "md5" }),
  Object.freeze({ extension: ".sha1", algorithm: "sha1" }),
  Object.freeze({ extension: ".sha256", algorithm: "sha256" }),
  Object.freeze({ extension: ".sha512", algorithm: "sha512" }),
]);

const writeChecksummed = (directory, name, bytes) => {
  writeFileSync(join(directory, name), bytes);
  for (const checksum of CHECKSUMS) {
    writeFileSync(
      join(directory, `${name}${checksum.extension}`),
      createHash(checksum.algorithm).update(bytes).digest("hex"),
    );
  }
};

const writeRepository = (root, signatures) => {
  for (const packageDefinition of describeMavenRelease(VERSION)) {
    const directory = join(root, packageDefinition.versionDirectory);
    mkdirSync(directory, { recursive: true });
    for (const name of packageDefinition.baseNames) {
      writeChecksummed(directory, name, Buffer.from(`artifact:${name}`, "utf8"));
      if (signatures) {
        writeChecksummed(directory, `${name}.asc`, Buffer.from(`signature:${name}`, "utf8"));
      }
    }
  }
};

const createRemote = ({ failPath } = {}) => {
  const files = new Map();
  let putCount = 0;
  const fetchImpl = async (url, options) => {
    const path = decodeURIComponent(new URL(url).pathname).replace(/^\/releases\//u, "");
    const method = options.method;
    if (method === "GET") {
      const bytes = files.get(path);
      if (bytes === undefined) {
        return new Response(null, { status: 404 });
      }
      return new Response(bytes, {
        headers: { "content-length": String(bytes.length) },
        status: 200,
      });
    }
    if (method === "PUT") {
      putCount += 1;
      if (path === failPath) {
        return new Response(null, { status: 500 });
      }
      if (files.has(path) || options.headers["If-None-Match"] !== "*") {
        return new Response(null, { status: 412 });
      }
      const chunks = [];
      for await (const chunk of options.body) {
        chunks.push(Buffer.from(chunk));
      }
      files.set(path, Buffer.concat(chunks));
      return new Response(null, { status: 201 });
    }
    if (method === "DELETE") {
      files.delete(path);
      return new Response(null, { status: 204 });
    }
    return new Response(null, { status: 405 });
  };
  return { fetchImpl, files, putCount: () => putCount };
};

const promote = (root, remote) => promoteMavenRelease({
  fetchImpl: remote.fetchImpl,
  password: "repository-password",
  repository: "https://packages.example/releases/",
  root,
  username: "release-user",
  version: VERSION,
});

test("promotes both signed packages with conditional writes and verifies every byte", async () => {
  const root = mkdtempSync(join(tmpdir(), "reallyme-maven-promote-"));
  try {
    writeRepository(root, true);
    const release = await collectMavenReleaseFiles(root, VERSION, true);
    const remote = createRemote();

    await promote(root, remote);

    assert.equal(remote.files.size, release.files.length);
    assert.equal(remote.putCount(), release.files.length);
  } finally {
    rmSync(root, { force: true, recursive: true });
  }
});

test("rejects an existing coordinate before uploading any release file", async () => {
  const root = mkdtempSync(join(tmpdir(), "reallyme-maven-existing-"));
  try {
    writeRepository(root, true);
    const remote = createRemote();
    const [jvm] = describeMavenRelease(VERSION);
    remote.files.set(jvm.markerRelativePath, Buffer.from("existing", "utf8"));

    await assert.rejects(
      promote(root, remote),
      (error) =>
        error instanceof MavenPromotionError &&
        error.reason === MavenPromotionReason.VERSION_EXISTS,
    );
    assert.equal(remote.putCount(), 0);
  } finally {
    rmSync(root, { force: true, recursive: true });
  }
});

test("rolls back files created before a later package upload fails", async () => {
  const root = mkdtempSync(join(tmpdir(), "reallyme-maven-rollback-"));
  try {
    writeRepository(root, true);
    const [, android] = describeMavenRelease(VERSION);
    const remote = createRemote({ failPath: android.markerRelativePath });

    await assert.rejects(
      promote(root, remote),
      (error) =>
        error instanceof MavenPromotionError &&
        error.reason === MavenPromotionReason.UPLOAD_FAILED,
    );
    assert.equal(remote.files.size, 0);
  } finally {
    rmSync(root, { force: true, recursive: true });
  }
});

test("rejects a staged repository whose checksum sidecar was altered", async () => {
  const root = mkdtempSync(join(tmpdir(), "reallyme-maven-checksum-"));
  try {
    writeRepository(root, true);
    const [jvm] = describeMavenRelease(VERSION);
    writeFileSync(
      join(root, jvm.versionDirectory, `${jvm.baseNames[0]}.sha256`),
      "0".repeat(64),
    );
    await assert.rejects(
      collectMavenReleaseFiles(root, VERSION, true),
      (error) =>
        error instanceof MavenReleaseFileError &&
        error.reason === MavenReleaseFileReason.INVALID_CHECKSUM,
    );
  } finally {
    rmSync(root, { force: true, recursive: true });
  }
});

test("rejects an oversized checksum sidecar before reading it", async () => {
  const root = mkdtempSync(join(tmpdir(), "reallyme-maven-checksum-size-"));
  try {
    writeRepository(root, true);
    const [jvm] = describeMavenRelease(VERSION);
    writeFileSync(
      join(root, jvm.versionDirectory, `${jvm.baseNames[0]}.sha256`),
      "0".repeat(257),
    );
    await assert.rejects(
      collectMavenReleaseFiles(root, VERSION, true),
      (error) =>
        error instanceof MavenReleaseFileError &&
        error.reason === MavenReleaseFileReason.INVALID_CHECKSUM,
    );
  } finally {
    rmSync(root, { force: true, recursive: true });
  }
});

test("signs every staged publication file with the configured release key", async (context) => {
  const root = mkdtempSync(join(tmpdir(), "reallyme-maven-sign-"));
  const keyHome = join(root, "keyring");
  try {
    const repository = join(root, "repository");
    const passphrase = "release-test-passphrase";
    mkdirSync(keyHome, { recursive: true, mode: 0o700 });
    writeRepository(repository, false);
    const agent = spawnSync(
      "gpgconf",
      ["--homedir", keyHome, "--launch", "gpg-agent"],
      { encoding: "utf8", stdio: ["ignore", "ignore", "pipe"] },
    );
    if (agent.status !== 0 && agent.stderr.includes("No agent running")) {
      context.skip("local GPG agent is unavailable");
      return;
    }
    assert.equal(agent.status, 0, agent.stderr);
    const generated = spawnSync(
      "gpg",
      [
        "--batch",
        "--no-tty",
        "--homedir",
        keyHome,
        "--pinentry-mode",
        "loopback",
        "--passphrase",
        passphrase,
        "--quick-generate-key",
        "ReallyMe Release Test <release-test@really.me>",
        "ed25519",
        "sign",
        "1d",
      ],
      { encoding: "utf8", stdio: ["ignore", "ignore", "pipe"] },
    );
    if (generated.status !== 0 && generated.stderr.includes("No agent running")) {
      context.skip("local GPG agent is unavailable");
      return;
    }
    assert.equal(generated.status, 0, generated.stderr);
    const exported = spawnSync(
      "gpg",
      [
        "--batch",
        "--no-tty",
        "--homedir",
        keyHome,
        "--pinentry-mode",
        "loopback",
        "--passphrase",
        passphrase,
        "--armor",
        "--export-secret-keys",
      ],
      { encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] },
    );
    assert.equal(exported.status, 0, exported.stderr);

    const signed = spawnSync(process.execPath, [signingScript, repository, VERSION], {
      encoding: "utf8",
      env: {
        ...process.env,
        MAVEN_SIGNING_KEY: exported.stdout,
        MAVEN_SIGNING_PASSWORD: passphrase,
      },
      stdio: ["ignore", "pipe", "pipe"],
    });
    assert.equal(signed.status, 0, signed.stderr);

    const release = await collectMavenReleaseFiles(repository, VERSION, true);
    for (const file of release.baseFiles) {
      const verified = spawnSync(
        "gpg",
        ["--batch", "--no-tty", "--homedir", keyHome, "--verify", `${file.absolutePath}.asc`, file.absolutePath],
        { encoding: "utf8", stdio: ["ignore", "ignore", "pipe"] },
      );
      assert.equal(verified.status, 0, verified.stderr);
    }
  } finally {
    spawnSync(
      "gpgconf",
      ["--homedir", keyHome, "--kill", "gpg-agent"],
      { encoding: "utf8", stdio: ["ignore", "ignore", "ignore"] },
    );
    rmSync(root, { force: true, recursive: true });
  }
});
