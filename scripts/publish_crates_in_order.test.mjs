// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

import assert from "node:assert/strict";
import {
  chmodSync,
  mkdtempSync,
  mkdirSync,
  readFileSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { delimiter, join } from "node:path";
import { spawnSync } from "node:child_process";
import test from "node:test";
import { fileURLToPath } from "node:url";

const publisher = fileURLToPath(new URL("./publish_crates_in_order.mjs", import.meta.url));

const writeFakeWorkspace = (root, publishFailure = "crate version already exists") => {
  const binDirectory = join(root, "bin");
  const targetDirectory = join(root, "target");
  const metadataPath = join(root, "metadata.json");
  const callLogPath = join(root, "cargo-calls.txt");
  mkdirSync(binDirectory, { recursive: true });
  mkdirSync(targetDirectory, { recursive: true });

  const metadata = {
    target_directory: targetDirectory,
    packages: [
      {
        name: "reallyme-jose-proto",
        version: "0.3.0",
        publish: null,
        dependencies: [],
      },
      {
        name: "reallyme-jose",
        version: "0.3.0",
        publish: null,
        dependencies: [
          {
            name: "reallyme-jose-proto",
            package: null,
            source: null,
            path: join(root, "proto"),
            req: "^0.3.0",
          },
        ],
      },
    ],
  };
  writeFileSync(metadataPath, JSON.stringify(metadata), { encoding: "utf8", mode: 0o600 });

  const fakeCargoPath = join(binDirectory, "cargo");
  writeFileSync(
    fakeCargoPath,
    `#!/usr/bin/env node
const fs = require("node:fs");
fs.appendFileSync(process.env.FAKE_CARGO_LOG, process.argv.slice(2).join(" ") + "\\n");
if (process.argv[2] === "metadata") {
  process.stdout.write(fs.readFileSync(process.env.FAKE_CARGO_METADATA, "utf8"));
  process.exit(0);
}
process.stderr.write(process.env.FAKE_CARGO_FAILURE + "\\n");
process.exit(101);
`,
    { encoding: "utf8", mode: 0o700 },
  );
  chmodSync(fakeCargoPath, 0o700);

  return {
    callLogPath,
    environment: {
      ...process.env,
      FAKE_CARGO_LOG: callLogPath,
      FAKE_CARGO_METADATA: metadataPath,
      FAKE_CARGO_FAILURE: publishFailure,
      PATH: `${binDirectory}${delimiter}${process.env.PATH ?? ""}`,
    },
  };
};

const writeFakeInspectWorkspace = (root) => {
  const binDirectory = join(root, "bin");
  const targetDirectory = join(root, "target");
  const metadataPath = join(root, "metadata.json");
  const callLogPath = join(root, "cargo-calls.txt");
  mkdirSync(binDirectory, { recursive: true });
  mkdirSync(targetDirectory, { recursive: true });

  const packages = [
    {
      name: "reallyme-jose-proto",
      version: "0.3.3",
      publish: null,
      dependencies: [],
    },
    {
      name: "reallyme-jose",
      version: "0.3.3",
      publish: null,
      dependencies: [
        {
          name: "reallyme-jose-proto",
          package: null,
          source: null,
          path: join(root, "proto"),
          req: "^0.3.3",
        },
      ],
    },
  ];
  writeFileSync(
    metadataPath,
    JSON.stringify({ target_directory: targetDirectory, packages }),
    { encoding: "utf8", mode: 0o600 },
  );

  const fakeCargoPath = join(binDirectory, "cargo");
  writeFileSync(
    fakeCargoPath,
    `#!/usr/bin/env node
const { execFileSync } = require("node:child_process");
const fs = require("node:fs");
const path = require("node:path");
const args = process.argv.slice(2);
fs.appendFileSync(process.env.FAKE_CARGO_LOG, args.join(" ") + "\\n");
if (args[0] === "metadata") {
  process.stdout.write(fs.readFileSync(process.env.FAKE_CARGO_METADATA, "utf8"));
  process.exit(0);
}
if (args[0] === "package" && args.includes("--workspace")) {
  const metadata = JSON.parse(fs.readFileSync(process.env.FAKE_CARGO_METADATA, "utf8"));
  const packageDirectory = path.join(metadata.target_directory, "package");
  const stagingDirectory = path.join(metadata.target_directory, "fake-package-staging");
  fs.mkdirSync(packageDirectory, { recursive: true });
  fs.mkdirSync(stagingDirectory, { recursive: true });
  for (const pkg of metadata.packages) {
    const directoryName = pkg.name + "-" + pkg.version;
    const crateDirectory = path.join(stagingDirectory, directoryName);
    fs.mkdirSync(crateDirectory, { recursive: true });
    fs.writeFileSync(path.join(crateDirectory, "Cargo.toml"), "[package]\\nname = \\"" + pkg.name + "\\"\\nversion = \\"" + pkg.version + "\\"\\n");
    execFileSync("tar", ["-czf", path.join(packageDirectory, directoryName + ".crate"), "-C", stagingDirectory, directoryName]);
  }
  process.exit(0);
}
if (args[0] === "fetch" || args[0] === "check") {
  process.exit(0);
}
if (args[0] === "publish" && args.includes("reallyme-jose-proto")) {
  process.exit(0);
}
if (args[0] === "publish" && args.includes("reallyme-jose")) {
  const delimiter = String.fromCharCode(96);
  process.stderr.write("failed to select a version for the requirement " + delimiter + "reallyme-jose-proto = \\\"^0.3.3\\\"" + delimiter + "\\n");
  process.exit(101);
}
process.stderr.write("unexpected cargo invocation: " + args.join(" ") + "\\n");
process.exit(1);
`,
    { encoding: "utf8", mode: 0o700 },
  );
  chmodSync(fakeCargoPath, 0o700);

  return {
    callLogPath,
    environment: {
      ...process.env,
      FAKE_CARGO_LOG: callLogPath,
      FAKE_CARGO_METADATA: metadataPath,
      PATH: `${binDirectory}${delimiter}${process.env.PATH ?? ""}`,
    },
  };
};

test("order mode validates and reports the dependency order without packaging", () => {
  const root = mkdtempSync(join(tmpdir(), "reallyme-jose-order-test-"));
  try {
    const workspace = writeFakeWorkspace(root);
    const result = spawnSync(process.execPath, [publisher, "order"], {
      cwd: root,
      encoding: "utf8",
      env: workspace.environment,
      stdio: ["ignore", "pipe", "pipe"],
    });

    assert.equal(result.status, 0, result.stderr);
    assert.match(result.stdout, /reallyme-jose-proto 0[.]3[.]0[\s\S]*reallyme-jose 0[.]3[.]0/u);
    assert.deepEqual(readFileSync(workspace.callLogPath, "utf8").trim().split("\n"), [
      "metadata --locked --format-version 1 --no-deps",
    ]);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test("inspect mode does not re-resolve archive listings through the registry", () => {
  const root = mkdtempSync(join(tmpdir(), "reallyme-jose-inspect-test-"));
  try {
    const workspace = writeFakeInspectWorkspace(root);
    const result = spawnSync(process.execPath, [publisher, "inspect"], {
      cwd: root,
      encoding: "utf8",
      env: workspace.environment,
      stdio: ["ignore", "pipe", "pipe"],
    });

    assert.equal(result.status, 0, result.stderr);
    assert.match(
      result.stdout,
      /reallyme-jose dry-run reached unpublished ordered workspace dependencies: reallyme-jose-proto/u,
    );
    const calls = readFileSync(workspace.callLogPath, "utf8").trim().split("\n");
    assert.ok(calls.includes("package --workspace --no-verify --locked"));
    assert.equal(calls.some((call) => call.startsWith("package -p ")), false);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test("rejects an existing crate instead of continuing with mixed provenance", () => {
  const root = mkdtempSync(join(tmpdir(), "reallyme-jose-publish-test-"));
  try {
    const workspace = writeFakeWorkspace(root);

    const result = spawnSync(process.execPath, [publisher, "publish"], {
      cwd: root,
      encoding: "utf8",
      env: workspace.environment,
      stdio: ["ignore", "pipe", "pipe"],
    });

    assert.equal(result.status, 101);
    assert.match(
      result.stderr,
      /refusing to combine an unverified registry artifact with this release/u,
    );
    assert.doesNotMatch(result.stdout, /continuing/u);
    const publishCalls = readFileSync(workspace.callLogPath, "utf8")
      .split("\n")
      .filter((line) => line.startsWith("publish "));
    assert.equal(publishCalls.length, 1);
    assert.match(publishCalls[0], /reallyme-jose-proto/u);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test("exhausted rate-limit retries fail without publishing dependent crates", () => {
  const root = mkdtempSync(join(tmpdir(), "reallyme-jose-retry-test-"));
  try {
    const workspace = writeFakeWorkspace(root, "too many requests");
    // Bypass only elapsed time in the child; exercise the real retry loop and
    // process exit status without making network requests or waiting minutes.
    const preload = join(root, "skip-wait.cjs");
    writeFileSync(preload, 'Atomics.wait = () => "timed-out";\n');
    const result = spawnSync(process.execPath, ["--require", preload, publisher, "publish"], {
      cwd: root,
      encoding: "utf8",
      env: workspace.environment,
      timeout: 30_000,
    });
    assert.equal(result.error, undefined);
    assert.equal(result.status, 101);
    assert.match(result.stderr, /publish retry limit reached/u);
    const calls = readFileSync(workspace.callLogPath, "utf8").split("\n")
      .filter((line) => line.startsWith("publish "));
    assert.equal(calls.length, 12);
    assert.ok(calls.every((line) => line === "publish -p reallyme-jose-proto --locked"));
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});
