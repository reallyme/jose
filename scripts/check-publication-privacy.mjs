// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

import { execFileSync } from "node:child_process";
import { resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { lstatSync, mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

const root = fileURLToPath(new URL("../", import.meta.url));
const python = process.platform === "win32" ? "python" : "python3";
const maximumOutputBytes = 1_048_576;
const releasePayloads = new Set(["", "npm", "swift", "maven", "crates", "native"]);

export class PublicationPrivacyError extends Error {
  constructor() {
    super("publication-privacy-rejected");
    this.name = "PublicationPrivacyError";
    this.code = "publication-privacy-rejected";
  }
}

function check(script, args, input) {
  const temporary = mkdtempSync(join(tmpdir(), "publication-policy-"));
  try {
    execFileSync(python, [resolve(root, "scripts", script), ...args], {
      cwd: root,
      input,
      stdio: ["pipe", "pipe", "pipe"],
      maxBuffer: maximumOutputBytes,
      timeout: 120_000,
      env: { ...process.env, TMPDIR: temporary, TMP: temporary, TEMP: temporary },
    });
  } catch {
    // Diagnostics from archive tools or untrusted filenames must not become
    // publication logs. The standalone check supplies explicit review output.
    throw new PublicationPrivacyError();
  } finally {
    rmSync(temporary, { recursive: true, force: true });
  }
}

export function npmPublicationFiles() {
  try {
    const path = resolve(root, "scripts/publication_payloads.json");
    const status = lstatSync(path);
    if (!status.isFile() || status.isSymbolicLink() || status.size > 16_384) throw new PublicationPrivacyError();
    const value = JSON.parse(readFileSync(path, "utf8"));
    if (value === null || typeof value !== "object" || Object.keys(value).length !== 2 ||
        value.schema !== 1 || !Array.isArray(value.npm) || value.npm.length === 0 ||
        value.npm.some((item) => typeof item !== "string" || item.includes("\\") || item.includes("\0") ||
          item.split("/").some((part) => part === "" || part === "." || part === "..")) ||
        new Set(value.npm).size !== value.npm.length) throw new PublicationPrivacyError();
    return Object.freeze([...value.npm]);
  } catch {
    throw new PublicationPrivacyError();
  }
}

export function assertPublicationPrivacy(path, { prefix = "", releasePayload = "" } = {}) {
  if (typeof path !== "string" || path.length === 0 || typeof prefix !== "string" || !releasePayloads.has(releasePayload)) {
    throw new PublicationPrivacyError();
  }
  const args = [resolve(path)];
  if (prefix !== "") args.push("--prefix", prefix);
  if (releasePayload !== "") args.push("--release-payload", releasePayload);
  check("check_repository_privacy.py", ["index"]);
  check("check_release_privacy.py", args);
}

export function assertPublicationPaths(paths, { prefix = "", releasePayload = "" } = {}) {
  if (!Array.isArray(paths) || paths.some((path) => typeof path !== "string" || path.includes("\0")) ||
      typeof prefix !== "string" || !releasePayloads.has(releasePayload)) {
    throw new PublicationPrivacyError();
  }
  const args = ["--paths-stdin"];
  if (prefix !== "") args.push("--prefix", prefix);
  if (releasePayload !== "") args.push("--release-payload", releasePayload);
  check("check_repository_privacy.py", ["index"]);
  check("check_release_privacy.py", args, Buffer.from(paths.length === 0 ? "" : `${paths.join("\0")}\0`));
}
