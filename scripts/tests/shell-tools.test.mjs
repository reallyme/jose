// SPDX-FileCopyrightText: 2026 ReallyMe LLC
//
// SPDX-License-Identifier: MIT OR Apache-2.0

import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { copyFileSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, realpathSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { delimiter, join } from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

const scripts = fileURLToPath(new URL("..", import.meta.url));
const executable = (path, source) => writeFileSync(path, source, { mode: 0o700 });

test("sanitizer runs cannot inherit flags that override their instrumentation", () => {
  const root = mkdtempSync(join(tmpdir(), "jose-sanitizer-test-"));
  try {
    const log = join(root, "calls.jsonl");
    executable(join(root, "cargo"), `#!/usr/bin/env node
const fs = require("node:fs");
fs.appendFileSync(process.env.TEST_CALL_LOG, JSON.stringify({
  flags: process.env.RUSTFLAGS,
  encoded: process.env.CARGO_ENCODED_RUSTFLAGS,
  args: process.argv.slice(2),
}) + "\\n");
`);
    const result = spawnSync("bash", [join(scripts, "test_native_sanitizers.sh")], {
      encoding: "utf8",
      env: {
        ...process.env,
        PATH: `${root}${delimiter}${process.env.PATH ?? ""}`,
        TEST_CALL_LOG: log,
        REALLYME_JOSE_SANITIZER_TARGET: "aarch64-apple-darwin",
        CARGO_ENCODED_RUSTFLAGS: "-Copt-level=0",
      },
    });
    assert.equal(result.status, 0, result.stderr);
    const calls = readFileSync(log, "utf8").trim().split("\n").map(JSON.parse);
    assert.equal(calls.length, 2);
    assert.equal(calls[0].flags, "-Zsanitizer=address");
    assert.equal(calls[1].flags, "-Zub-checks=yes -Zextra-const-ub-checks=yes");
    for (const call of calls) {
      assert.equal(call.encoded, undefined);
      assert.ok(call.args.includes("--locked"));
    }
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

for (const script of ["build_kotlin_native_resource.sh", "build_android_native_resources.sh", "build_swift_xcframework.sh"]) {
  test(`${script} builds its own repository when invoked from another directory`, () => {
    const root = mkdtempSync(join(tmpdir(), "jose-build-test-"));
    try {
      const checkout = join(root, "checkout");
      const scriptDirectory = join(checkout, "scripts");
      const bin = join(root, "bin");
      const ndk = join(root, "ndk");
      const log = join(root, "cargo-cwd");
      mkdirSync(scriptDirectory, { recursive: true });
      mkdirSync(bin);
      mkdirSync(join(ndk, "toolchains/llvm/prebuilt/darwin-x86_64/bin"), { recursive: true });
      mkdirSync(join(checkout, "crates/ffi/include"), { recursive: true });
      writeFileSync(join(checkout, "crates/ffi/include/reallyme_jose.h"), "/* fixture */\n");
      copyFileSync(join(scripts, script), join(scriptDirectory, script));
      executable(join(bin, "uname"), '#!/bin/sh\nif [ "$1" = -s ]; then echo Darwin; else echo arm64; fi\n');
      for (const command of ["rustup", "xcodebuild", "lipo", "swift", "zip"]) {
        executable(join(bin, command), "#!/bin/sh\nexit 0\n");
      }
      // Stop at the build boundary: no real compilation, download, or packaging.
      executable(join(bin, "cargo"), '#!/bin/sh\npwd -P > "$TEST_CALL_LOG"\nexit 77\n');
      const result = spawnSync("bash", [join(scriptDirectory, script)], {
        cwd: root,
        encoding: "utf8",
        env: { ...process.env, PATH: `${bin}${delimiter}${process.env.PATH ?? ""}`, ANDROID_NDK_HOME: ndk, TEST_CALL_LOG: log },
      });
      assert.equal(result.status, 77, result.stderr);
      assert.equal(readFileSync(log, "utf8").trim(), realpathSync(checkout));
    } finally {
      rmSync(root, { recursive: true, force: true });
    }
  });
}

test("Android AVD failure uses private logs and removes its temporary directory", () => {
  const root = mkdtempSync(join(tmpdir(), "jose-android-test-"));
  try {
    const scratch = join(root, "scratch");
    const observed = join(root, "observed.json");
    mkdirSync(scratch);
    const stub = join(root, "stub");
    executable(stub, "#!/bin/sh\nexit 0\n");
    const avdmanager = join(root, "avdmanager");
    executable(avdmanager, `#!/usr/bin/env node
const fs = require("node:fs");
const path = require("node:path");
const entries = fs.readdirSync(process.env.TMPDIR).map(name => {
  const directory = path.join(process.env.TMPDIR, name);
  return { mode: fs.statSync(directory).mode & 0o777, files: fs.readdirSync(directory) };
});
fs.writeFileSync(process.env.TEST_OBSERVED, JSON.stringify(entries));
process.stdout.write("AVD fixture failure\\n");
process.exit(77);
`);
    const result = spawnSync("bash", [join(scripts, "test_android_consumer_r8_runtime.sh")], {
      encoding: "utf8",
      env: {
        ...process.env,
        TMPDIR: scratch,
        TEST_OBSERVED: observed,
        ADB: stub,
        EMULATOR: stub,
        SDKMANAGER: stub,
        AVDMANAGER: avdmanager,
        ANDROID_NDK_HOME: root,
        ANDROID_AVD_HOME: join(root, "avd"),
        REALLYME_JOSE_ANDROID_AVD: "test-fixture",
      },
      timeout: 10_000,
    });
    assert.equal(result.status, 77, result.stderr);
    assert.deepEqual(JSON.parse(readFileSync(observed, "utf8")), [{ mode: 0o700, files: ["avdmanager.log"] }]);
    assert.deepEqual(readdirSync(scratch), []);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});
