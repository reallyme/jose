#!/usr/bin/env node
// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import { copyFileSync, constants, lstatSync, mkdirSync, readFileSync, readdirSync, writeFileSync } from "node:fs";
import { join, resolve } from "node:path";
import { setTimeout } from "node:timers/promises";
import { pathToFileURL } from "node:url";

const packages = ["reallyme-jose-proto", "reallyme-jose"];
const versionPattern = /^(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)$/u;
const shaPattern = /^[a-f0-9]{40}$/u;
const digestPattern = /^[a-f0-9]{64}$/u;
const registrySource = "registry+https://github.com/rust-lang/crates.io-index";
const manifestName = "crate-archives.json";
const maxArchiveBytes = 10_000_000;
const maxMetadataBytes = 1_048_576;

class ArchiveReleaseError extends Error {}
const fail = (code) => { throw new ArchiveReleaseError(code); };
const sha256 = (bytes) => createHash("sha256").update(bytes).digest("hex");

function run(command, args, maxBuffer = maxMetadataBytes) {
  try {
    return execFileSync(command, args, { encoding: "utf8", maxBuffer, stdio: ["ignore", "pipe", "ignore"] });
  } catch {
    fail(`${command}-command-failed`);
  }
}

function readRegular(path, limit) {
  const entry = lstatSync(path);
  if (!entry.isFile() || entry.size < 1 || entry.size > limit) fail("invalid-release-file");
  const bytes = readFileSync(path);
  if (entry.size !== bytes.length) fail("release-file-length-changed");
  return bytes;
}

function archiveName(name, version) {
  return `${name}-${version}.crate`;
}

function checkedOutSource(version, sourceSha) {
  if (!versionPattern.test(version ?? "") || !shaPattern.test(sourceSha ?? "")) fail("invalid-release-identity");
  if (run("git", ["rev-parse", "--verify", "HEAD"]).trim() !== sourceSha) fail("source-sha-mismatch");
}

export function registryMetadata(pkg, version, readme) {
  if (pkg.version !== version || (pkg.publish !== null && !pkg.publish?.includes("crates-io")) ||
      pkg.readme !== "README.md" || pkg.license_file !== null || pkg.links !== null) {
    fail("unsupported-crate-publication-config");
  }
  return {
    name: pkg.name,
    vers: version,
    deps: pkg.dependencies.map((dep) => {
      // Cargo omits path for registry dependencies and reports an absolute
      // path for the workspace dependency that packaging normalizes.
      const registryDependency = dep.path === undefined && dep.source === registrySource;
      const workspaceProto = typeof dep.path === "string" && dep.source === null &&
        pkg.name === "reallyme-jose" && dep.name === "reallyme-jose-proto" && dep.req !== "*";
      if (dep.registry !== null || (!workspaceProto && !registryDependency)) {
        fail("unsupported-crate-dependency-source");
      }
      return {
        name: dep.name,
        version_req: dep.req,
        features: dep.features,
        optional: dep.optional,
        default_features: dep.uses_default_features,
        target: dep.target,
        kind: dep.kind ?? "normal",
        registry: null,
        explicit_name_in_toml: dep.rename,
      };
    }),
    features: pkg.features,
    authors: pkg.authors,
    description: pkg.description,
    documentation: pkg.documentation,
    homepage: pkg.homepage,
    readme,
    readme_file: pkg.readme,
    keywords: pkg.keywords,
    categories: pkg.categories,
    license: pkg.license,
    license_file: null,
    repository: pkg.repository,
    badges: {},
    links: null,
    rust_version: pkg.rust_version,
  };
}

function seal(input, output, version, sourceSha) {
  if (output === undefined) fail("missing-artifact-directory");
  const metadata = JSON.parse(run("cargo", ["metadata", "--no-deps", "--locked", "--offline", "--format-version", "1"]));
  const publicPackages = metadata.packages.filter((pkg) =>
    metadata.workspace_members.includes(pkg.id) && pkg.publish?.length !== 0);
  if (publicPackages.length !== packages.length) fail("unexpected-public-crate-inventory");
  const entries = packages.map((name) => {
    const pkg = publicPackages.find((candidate) => candidate.name === name);
    if (pkg === undefined) fail("missing-public-crate");
    const file = archiveName(name, version);
    const path = resolve(input, file);
    const bytes = readRegular(path, maxArchiveBytes);
    const vcs = JSON.parse(run("tar", ["-xOzf", path, `${name}-${version}/.cargo_vcs_info.json`]));
    if (vcs?.git?.sha1 !== sourceSha || (vcs.git.dirty !== undefined && vcs.git.dirty !== false)) {
      fail("archive-source-mismatch");
    }
    const readme = run("tar", ["-xOzf", path, `${name}-${version}/README.md`]);
    return { file, sha256: sha256(bytes), metadata: registryMetadata(pkg, version, readme) };
  });

  mkdirSync(output, { recursive: true });
  if (readdirSync(output).length !== 0) fail("nonempty-artifact-directory");
  for (const { file, sha256: digest } of entries) {
    const destination = join(output, file);
    copyFileSync(join(input, file), destination, constants.COPYFILE_EXCL);
    if (sha256(readRegular(destination, maxArchiveBytes)) !== digest) fail("archive-copy-mismatch");
  }
  writeFileSync(join(output, manifestName), JSON.stringify({ schema: 1, version, sourceSha, entries }) + "\n", { flag: "wx" });
}

export function verifiedArchives(directory, version, sourceSha) {
  const expectedFiles = [manifestName, ...packages.map((name) => archiveName(name, version))];
  const files = readdirSync(directory);
  if (files.length !== expectedFiles.length || files.some((file) => !expectedFiles.includes(file))) {
    fail("unexpected-artifact-inventory");
  }
  const record = JSON.parse(readRegular(join(directory, manifestName), maxMetadataBytes));
  if (record?.schema !== 1 || record.version !== version || record.sourceSha !== sourceSha ||
      !Array.isArray(record.entries) || record.entries.length !== packages.length) {
    fail("artifact-release-identity-mismatch");
  }
  return packages.map((name, index) => {
    const entry = record.entries[index];
    const file = archiveName(name, version);
    if (entry?.file !== file || !digestPattern.test(entry.sha256 ?? "") ||
        entry.metadata?.name !== name || entry.metadata.vers !== version) {
      fail("invalid-archive-manifest-entry");
    }
    const bytes = readRegular(join(directory, file), maxArchiveBytes);
    if (sha256(bytes) !== entry.sha256) fail("archive-digest-mismatch");
    return { ...entry, bytes };
  });
}

export function registryRequestBody(metadata, archive) {
  const json = Buffer.from(JSON.stringify(metadata), "utf8");
  if (json.length > maxMetadataBytes || archive.length === 0 || archive.length > maxArchiveBytes) {
    fail("registry-request-size");
  }
  const jsonLength = Buffer.alloc(4);
  const archiveLength = Buffer.alloc(4);
  jsonLength.writeUInt32LE(json.length);
  archiveLength.writeUInt32LE(archive.length);
  return Buffer.concat([jsonLength, json, archiveLength, archive]);
}

const request = (url, options) => fetch(url, {
  ...options,
  redirect: "error",
  signal: AbortSignal.timeout(30_000),
});

async function registryDigest(name, version) {
  const response = await request(`https://index.crates.io/${name.slice(0, 2)}/${name.slice(2, 4)}/${name}`, {
    cache: "no-store",
    headers: { "Cache-Control": "no-cache" },
  });
  if (response.status === 404) return null;
  if (!response.ok) fail("registry-index-failed");
  for (const line of (await response.text()).split("\n")) {
    if (!line) continue;
    const entry = JSON.parse(line);
    if (entry.vers !== version) continue;
    if (entry.name !== name || entry.yanked !== false || !digestPattern.test(entry.cksum ?? "")) {
      fail("registry-index-invalid-version");
    }
    return entry.cksum;
  }
  return null;
}

export async function publishArchives(archives, token, { digest, upload, pause }) {
  for (const { metadata, bytes, sha256: expected } of archives) {
    const { name, vers: version } = metadata;
    const existing = await digest(name, version);
    if (existing !== null) {
      if (existing !== expected) fail("registry-archive-digest-mismatch");
      continue;
    }

    const body = registryRequestBody(metadata, bytes);
    let status = await upload(body, token);
    for (let retry = 0; status === 429 && retry < 2; retry += 1) {
      await pause(60_000);
      status = await upload(body, token);
    }
    const accepted = status >= 200 && status < 300;
    // An earlier run can complete the upload before the index catches up.
    // Accept a conflict only after the index returns the reviewed checksum.
    if (!accepted && status !== 400 && status !== 409) fail(`registry-upload-http-${status}`);
    let observed = null;
    for (let attempt = 0; attempt < 30 && observed === null; attempt += 1) {
      await pause(2_000);
      observed = await digest(name, version);
    }
    if (observed === null) fail(accepted ? "registry-index-timeout" : `registry-upload-http-${status}`);
    if (observed !== expected) fail("registry-archive-digest-mismatch");
  }
}

export function validateUploadResponse(body) {
  // The Cargo registry reports successful publication with optional warnings.
  // It may also report application errors with an HTTP 2xx status.
  if (body === null || typeof body !== "object" || Array.isArray(body) ||
      Object.hasOwn(body, "errors")) {
    fail("registry-upload-rejected");
  }
}

async function upload(body, token) {
  const response = await request("https://crates.io/api/v1/crates/new", {
    method: "PUT",
    headers: {
      Authorization: token,
      Accept: "application/json",
      "Content-Type": "application/octet-stream",
      "User-Agent": "reallyme-jose-release (https://github.com/reallyme/jose)",
    },
    body,
  });
  const responseBody = await response.json().catch(() => null);
  if (response.ok) validateUploadResponse(responseBody);
  return response.status;
}

async function main(args) {
  const [mode, directory, ...parameters] = args;
  if (!["seal", "verify", "publish"].includes(mode) || !directory ||
      parameters.length !== (mode === "seal" ? 3 : 2)) {
    fail("expected seal SOURCE OUTPUT VERSION SHA, or verify|publish DIRECTORY VERSION SHA");
  }
  const [version, sourceSha] = parameters.slice(-2);
  checkedOutSource(version, sourceSha);
  if (mode === "seal") {
    seal(directory, parameters[0], version, sourceSha);
  } else {
    const archives = verifiedArchives(directory, version, sourceSha);
    if (mode === "publish") {
      const token = process.env.CARGO_REGISTRY_TOKEN;
      if (!token || /[\s\u0000-\u001f]/u.test(token)) fail("missing-or-malformed-registry-token");
      await publishArchives(archives, token, { digest: registryDigest, upload, pause: setTimeout });
    }
  }
}

if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  try {
    await main(process.argv.slice(2));
  } catch (error) {
    const code = error instanceof ArchiveReleaseError ? error.message : "release-archive-io-failed";
    console.error(`crates.io artifact release failed: ${code}`);
    process.exitCode = 1;
  }
}
