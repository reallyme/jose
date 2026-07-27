#!/usr/bin/env node
// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

import { spawnSync } from "node:child_process";
import { appendFileSync } from "node:fs";
import { fileURLToPath } from "node:url";

const SHA_PATTERN = /^[0-9a-f]{40}$/u;
const REPOSITORY_PATTERN = /^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+$/u;
const VERSION_PATTERN = /^(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)$/u;
const POSITIVE_INTEGER_PATTERN = /^[1-9][0-9]*$/u;
const NON_NEGATIVE_INTEGER_PATTERN = /^(?:0|[1-9][0-9]*)$/u;
const MAX_OUTPUT_BYTES = 1_048_576;
const MAX_WAIT_SECONDS = 7_200;
const MAX_POLL_SECONDS = 300;
const PREFLIGHT_TITLES = Object.freeze({
  "crates-package-preflight.yml": "Crates package preflight",
  "swift-package-preflight.yml": "Swift package preflight",
  "kotlin-android-package-preflight.yml": "Kotlin Android package preflight",
  "npm-package-preflight.yml": "npm package preflight",
});

export class ReleaseAttestationError extends Error {
  constructor(code) {
    super(code);
    this.name = "ReleaseAttestationError";
    this.code = code;
  }
}

const fail = (code) => {
  throw new ReleaseAttestationError(code);
};

export const run = (command, arguments_, options = {}) => {
  const capture = options.capture !== false;
  const result = spawnSync(command, arguments_, {
    cwd: options.cwd,
    encoding: "utf8",
    env: options.env,
    maxBuffer: MAX_OUTPUT_BYTES,
    stdio: capture ? ["ignore", "pipe", "ignore"] : ["ignore", "ignore", "ignore"],
  });
  if (result.error !== undefined || result.status !== 0) {
    fail(options.errorCode ?? "command-failed");
  }
  if (!capture) return "";
  if (typeof result.stdout !== "string") fail(options.errorCode ?? "command-failed");
  return result.stdout.trim();
};

const validateRun = (value, releaseSha) => {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    fail("invalid-workflow-run-response");
  }
  const { attempt, conclusion, databaseId, displayTitle, event, headBranch, headSha, status } = value;
  if (
    !Number.isSafeInteger(attempt) ||
    attempt < 1 ||
    !Number.isSafeInteger(databaseId) ||
    databaseId < 1 ||
    typeof displayTitle !== "string" ||
    typeof event !== "string" ||
    typeof headBranch !== "string" ||
    headSha !== releaseSha ||
    typeof status !== "string" ||
    (conclusion !== null && typeof conclusion !== "string")
  ) {
    fail("invalid-workflow-run-response");
  }
  return { attempt, conclusion, databaseId, displayTitle, event, headBranch, status };
};

export const requireLatestSuccessfulRun = (
  rawRuns,
  releaseSha,
  workflow,
  releaseVersion,
) => {
  if (!Array.isArray(rawRuns)) fail("invalid-workflow-run-response");
  const expectedEvent = workflow === "rust-ci.yml" ? "push" : "workflow_dispatch";
  const runs = rawRuns
    .map((value) => validateRun(value, releaseSha))
    .filter((value) => value.event === expectedEvent && value.headBranch === "main")
    .sort((left, right) =>
      left.databaseId === right.databaseId
        ? right.attempt - left.attempt
        : right.databaseId - left.databaseId,
    );
  const latest = runs[0];
  if (latest === undefined) fail(`missing-${workflow}-run`);
  const title = PREFLIGHT_TITLES[workflow];
  if (title !== undefined && latest.displayTitle !== `${title} ${releaseVersion}`) {
    fail("preflight-version-mismatch");
  }
  // A newer queued, failed, or cancelled run invalidates an older success.
  if (latest.status !== "completed" || latest.conclusion !== "success") {
    fail(`latest-${workflow}-run-not-successful`);
  }
  return latest;
};

const parseSeconds = (value, fallback, maximum, code) => {
  if (value === undefined || value === "") return fallback;
  if (!NON_NEGATIVE_INTEGER_PATTERN.test(value)) fail(code);
  const parsed = Number(value);
  if (!Number.isSafeInteger(parsed) || parsed > maximum) fail(code);
  return parsed;
};

const queryRuns = ({ cwd, env, releaseSha, repository, workflow }) => {
  const encoded = run(
    "gh",
    [
      "run", "list", "--repo", repository, "--workflow", workflow, "--commit", releaseSha,
      "--limit", "100", "--json",
      "attempt,conclusion,databaseId,displayTitle,event,headBranch,headSha,status",
    ],
    { cwd, env, errorCode: `query-${workflow}-failed` },
  );
  try {
    return JSON.parse(encoded);
  } catch {
    fail("invalid-workflow-run-response");
  }
};

const waitForSuccessfulRun = (options) => {
  const deadline = Date.now() + options.waitSeconds * 1_000;
  for (;;) {
    try {
      return requireLatestSuccessfulRun(
        queryRuns(options),
        options.releaseSha,
        options.workflow,
        options.releaseVersion,
      );
    } catch (error) {
      const waitable =
        error instanceof ReleaseAttestationError &&
        (error.code === `missing-${options.workflow}-run` ||
          error.code === `latest-${options.workflow}-run-not-successful`);
      if (!waitable || Date.now() >= deadline) throw error;
      const remaining = Math.max(1, Math.ceil((deadline - Date.now()) / 1_000));
      const seconds = Math.min(options.pollSeconds, remaining);
      const waitBuffer = new SharedArrayBuffer(4);
      Atomics.wait(new Int32Array(waitBuffer), 0, 0, seconds * 1_000);
    }
  }
};

export const verifyReleaseAttestation = ({ cwd = process.cwd(), env = process.env } = {}) => {
  const releaseSha = env.RELEASE_SHA;
  const releaseVersion = env.RELEASE_VERSION;
  const repository = env.GITHUB_REPOSITORY;
  const preflightWorkflow = env.RELEASE_ATTESTATION_PREFLIGHT_WORKFLOW;
  if (typeof releaseSha !== "string" || !SHA_PATTERN.test(releaseSha)) fail("invalid-release-sha");
  if (typeof releaseVersion !== "string" || !VERSION_PATTERN.test(releaseVersion)) {
    fail("invalid-release-version");
  }
  if (typeof repository !== "string" || !REPOSITORY_PATTERN.test(repository)) {
    fail("invalid-github-repository");
  }
  if (typeof env.GH_TOKEN !== "string" || env.GH_TOKEN.length === 0) fail("missing-github-token");
  if (typeof preflightWorkflow !== "string" || !Object.hasOwn(PREFLIGHT_TITLES, preflightWorkflow)) {
    fail("unsupported-release-attestation-preflight-workflow");
  }
  const waitSeconds = parseSeconds(
    env.RELEASE_ATTESTATION_WAIT_SECONDS,
    0,
    MAX_WAIT_SECONDS,
    "invalid-release-attestation-wait-seconds",
  );
  const pollSeconds = parseSeconds(
    env.RELEASE_ATTESTATION_POLL_SECONDS,
    20,
    MAX_POLL_SECONDS,
    "invalid-release-attestation-poll-seconds",
  );
  if (run("git", ["rev-parse", "HEAD"], { cwd, env }) !== releaseSha) {
    fail("checkout-does-not-match-release-sha");
  }
  run("git", ["fetch", "--no-tags", "origin", "main"], {
    cwd,
    env,
    capture: false,
    errorCode: "origin-main-fetch-failed",
  });
  if (run("git", ["rev-parse", "origin/main"], { cwd, env }) !== releaseSha) {
    fail("release-sha-is-not-current-main");
  }
  const common = { cwd, env, releaseSha, releaseVersion, repository, waitSeconds, pollSeconds };
  waitForSuccessfulRun({ ...common, workflow: "rust-ci.yml" });
  const preflight = waitForSuccessfulRun({ ...common, workflow: preflightWorkflow });
  const expectedRunId = env.RELEASE_ATTESTATION_PREFLIGHT_RUN_ID;
  if (expectedRunId !== undefined && expectedRunId !== "") {
    if (!POSITIVE_INTEGER_PATTERN.test(expectedRunId) || Number(expectedRunId) !== preflight.databaseId) {
      fail("preflight-run-id-changed");
    }
  }
  return { preflightRunId: preflight.databaseId };
};

const isMain = process.argv[1] !== undefined && fileURLToPath(import.meta.url) === process.argv[1];
if (isMain) {
  try {
    const attestation = verifyReleaseAttestation();
    if (process.env.RELEASE_ATTESTATION_WRITE_GITHUB_OUTPUT === "1") {
      const output = process.env.GITHUB_OUTPUT;
      if (typeof output !== "string" || output.length === 0) fail("missing-github-output");
      appendFileSync(output, `preflight_run_id=${attestation.preflightRunId}\n`, { encoding: "utf8" });
    }
    console.log("release attestation verified for current main and latest required workflow runs");
  } catch (error) {
    const code = error instanceof ReleaseAttestationError ? error.code : "unexpected-failure";
    console.error(`release attestation failed: ${code}`);
    process.exit(1);
  }
}
