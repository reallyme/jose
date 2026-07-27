// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

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

const writeFakeWorkspace = (root) => {
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
process.stderr.write("crate version already exists\\n");
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
