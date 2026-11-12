// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { existsSync, mkdirSync, mkdtempSync, readFileSync, renameSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";

const source = readFileSync(new URL("maven-central-bundle.local.sh", import.meta.url), "utf8");
const mainStart = source.indexOf("\nrequire_tool awk\n");
assert.ok(mainStart > 0);

function fixture(t) {
  const root = mkdtempSync(join(tmpdir(), "jose-maven-bundle-"));
  t.after(() => rmSync(root, { recursive: true, force: true }));
  const sdk = join(root, "Android SDK");
  const home = join(root, "home");
  const bin = join(root, "bin");
  const scripts = join(root, "repository with spaces/scripts");
  for (const directory of [scripts, sdk, home, bin]) {
    mkdirSync(directory, { recursive: true });
  }
  const harness = join(scripts, "prepare-ndk.sh");
  // Exercise the real functions before signing, attestation, or compilation.
  // No release credentials, network access, or native toolchains are needed.
  writeFileSync(harness, source.slice(0, mainStart) + [
    "",
    "prepare_android_ndk_home",
    "node -e 'console.log(JSON.stringify({ndk: process.env.ANDROID_NDK_HOME,",
    "sdk: process.env.ANDROID_HOME, legacySdk: process.env.ANDROID_SDK_ROOT}))'",
    "",
  ].join("\n"));
  const manager = join(sdk, "cmdline-tools/latest/bin/sdkmanager");
  mkdirSync(join(sdk, "cmdline-tools/latest/bin"), { recursive: true });
  writeFileSync(manager, [
    "#!/usr/bin/env node",
    'const fs = require("node:fs");',
    'const path = require("node:path");',
    "const args = process.argv.slice(2);",
    'fs.appendFileSync(process.env.SDK_CALLS, JSON.stringify(args) + "\\n");',
    'if (args.includes("--list")) {',
    "  process.stdout.write(fs.readFileSync(process.env.SDK_PACKAGES));",
    "  process.exit(Number(process.env.SDK_LIST_STATUS || 0));",
    "}",
    'if (args.includes("--install")) {',
    "  if (process.env.SDK_INSTALL_STATUS) process.exit(Number(process.env.SDK_INSTALL_STATUS));",
    '  const sdk = args.find(arg => arg.startsWith("--sdk_root=")).slice("--sdk_root=".length);',
    '  const revision = args[args.indexOf("--install") + 1].slice("ndk;".length);',
    "  if (!process.env.SDK_INSTALL_INCOMPLETE) {",
    '    fs.mkdirSync(path.join(sdk, "ndk", revision, "toolchains/llvm/prebuilt"), { recursive: true });',
    "  }",
    '  console.log("installation progress");',
    "  process.exit(0);",
    "}",
    "process.exit(79);",
    "",
  ].join("\n"), { mode: 0o755 });
  const packages = join(root, "packages");
  writeFileSync(packages, [
    "Installed packages:",
    "  Path | Version | Description | Location",
    "  ndk;99.0.999 | 99.0.999 rc1 | NDK preview | ndk/99.0.999",
    "Available Packages:",
    "  Path | Version | Description",
    "  ndk;9.0.999 | 9.0.999 | NDK",
    "  ndk;30.2.9 | 30.2.9 | NDK",
    "  ndk;30.10.8 | 30.10.8 | NDK",
    "  ndk;30.10.10 | 30.10.10 | NDK",
    "  ndk;29.0.14206865 | 29.0.14206865 | NDK",
    "  ndk;31.0.123-beta1 | 31.0.123-beta1 | NDK preview",
    "  ndk;../../outside | ../../outside | invalid",
    "  ndk;31x0x123 | 31x0x123 | invalid",
    "  platforms;android-99 | 99 | Platform",
    "",
  ].join("\n"));
  const calls = join(root, "calls");
  const env = { ...process.env, HOME: home, PATH: bin + ":" + process.env.PATH,
    ANDROID_HOME: sdk, SDK_CALLS: calls, SDK_PACKAGES: packages };
  for (const variable of ["ANDROID_SDK_ROOT", "ANDROID_NDK_HOME", "ANDROID_NDK_VERSION",
    "SDK_LIST_STATUS", "SDK_INSTALL_STATUS", "SDK_INSTALL_INCOMPLETE", "MAVEN_CENTRAL_WORK_DIR"]) {
    delete env[variable];
  }
  return {
    root, sdk, home, bin, manager, packages, env,
    installed(revision) {
      const ndk = join(sdk, "ndk", revision);
      mkdirSync(join(ndk, "toolchains/llvm/prebuilt"), { recursive: true });
      return ndk;
    },
    calls() {
      return existsSync(calls) ? readFileSync(calls, "utf8").trim().split("\n").map(line => JSON.parse(line)) : [];
    },
    run() {
      return spawnSync("bash", [harness], { cwd: root, env, encoding: "utf8", timeout: 10_000 });
    },
  };
}

test("installs the latest stable NDK with numeric revision ordering", t => {
  const f = fixture(t);
  const result = f.run();
  assert.equal(result.status, 0, result.stderr);
  assert.deepEqual(JSON.parse(result.stdout), {
    ndk: join(f.sdk, "ndk/30.10.10"), sdk: f.sdk, legacySdk: f.sdk,
  });
  assert.deepEqual(f.calls(), [
    ["--sdk_root=" + f.sdk, "--list", "--channel=0"],
    ["--sdk_root=" + f.sdk, "--install", "ndk;30.10.10", "--channel=0"],
  ]);
});

test("checks for updates on every run without reinstalling the current NDK", t => {
  const f = fixture(t);
  f.installed("30.10.10");
  for (let attempt = 0; attempt < 2; attempt += 1) {
    const result = f.run();
    assert.equal(result.status, 0, result.stderr);
  }
  assert.equal(f.calls().length, 2);
  assert.ok(f.calls().every(args => args.includes("--list")));
});

test("installs a newer NDK even when an older NDK is installed", t => {
  const f = fixture(t);
  f.installed("29.0.14206865");
  const result = f.run();
  assert.equal(result.status, 0, result.stderr);
  assert.equal(JSON.parse(result.stdout).ndk, join(f.sdk, "ndk/30.10.10"));
  assert.equal(f.calls().length, 2);
});

test("honors an explicit NDK home without invoking sdkmanager", t => {
  const f = fixture(t);
  f.env.ANDROID_NDK_HOME = f.installed("29.0.14206865");
  const result = f.run();
  assert.equal(result.status, 0, result.stderr);
  assert.equal(JSON.parse(result.stdout).ndk, f.env.ANDROID_NDK_HOME);
  assert.deepEqual(f.calls(), []);
});

for (const installed of [false, true]) {
  test("honors an explicit NDK revision, installed=" + installed, t => {
    const f = fixture(t);
    f.env.ANDROID_NDK_VERSION = "29.0.14206865";
    if (installed) f.installed(f.env.ANDROID_NDK_VERSION);
    const result = f.run();
    assert.equal(result.status, 0, result.stderr);
    assert.equal(JSON.parse(result.stdout).ndk, join(f.sdk, "ndk/29.0.14206865"));
    assert.ok(f.calls().every(args => args.includes("--install")));
    assert.equal(f.calls().length, installed ? 0 : 1);
  });
}

test("discovers the SDK through ANDROID_SDK_ROOT", t => {
  const f = fixture(t);
  delete f.env.ANDROID_HOME;
  f.env.ANDROID_SDK_ROOT = f.sdk;
  const result = f.run();
  assert.equal(result.status, 0, result.stderr);
  assert.equal(JSON.parse(result.stdout).sdk, f.sdk);
});

for (const [host, relativeSdk] of [["Darwin", "Library/Android/sdk"], ["Linux", "Android/Sdk"]]) {
  test("discovers the conventional SDK on " + host, t => {
    const f = fixture(t);
    delete f.env.ANDROID_HOME;
    const sdk = join(f.home, relativeSdk);
    mkdirSync(join(sdk, ".."), { recursive: true });
    renameSync(f.sdk, sdk);
    writeFileSync(join(f.bin, "uname"), "#!/usr/bin/env bash\nprintf '%s\\n' '" + host + "'\n", { mode: 0o755 });
    const result = f.run();
    assert.equal(result.status, 0, result.stderr);
    assert.equal(JSON.parse(result.stdout).sdk, sdk);
  });
}

test("uses sdkmanager on PATH when the SDK has no latest command-line tools", t => {
  const f = fixture(t);
  renameSync(f.manager, join(f.bin, "sdkmanager"));
  const result = f.run();
  assert.equal(result.status, 0, result.stderr);
  assert.equal(f.calls().length, 2);
});

test("reports missing command-line tools without using another installed SDK", t => {
  const f = fixture(t);
  rmSync(f.manager);
  symlinkSync("/bin/bash", join(f.bin, "bash"));
  f.env.PATH = f.bin;
  const result = f.run();
  assert.equal(result.status, 1, result.stderr);
  assert.match(result.stderr, /install Android SDK Command-line Tools/);
  assert.deepEqual(f.calls(), []);
});

for (const [name, configure, message] of [
  ["query failure", f => { f.env.SDK_LIST_STATUS = "1"; }, /could not query Android NDK packages/],
  ["installation failure", f => { f.env.SDK_INSTALL_STATUS = "1"; }, /Android NDK installation failed/],
  ["incomplete installation", f => { f.env.SDK_INSTALL_INCOMPLETE = "1"; }, /missing required directory/],
  ["no stable NDK", f => { writeFileSync(f.packages, "ndk;31.0.123 | 31.0.123 beta1 | Preview\n"); },
    /contains no stable NDK revision/],
  ["invalid revision override", f => { f.env.ANDROID_NDK_VERSION = "../../outside"; },
    /must be a numeric major.minor.build revision/],
  ["invalid NDK home", f => { f.env.ANDROID_NDK_HOME = join(f.root, "missing"); },
    /missing required directory/],
  ["invalid SDK root", f => { f.env.ANDROID_HOME = join(f.root, "missing"); },
    /missing required directory/],
]) {
  test("fails closed on " + name, t => {
    const f = fixture(t);
    configure(f);
    const result = f.run();
    assert.equal(result.status, 1, result.stderr);
    assert.match(result.stderr, message);
    assert.equal(result.stdout, "");
    if (name === "query failure" || name === "no stable NDK") assert.equal(f.calls().length, 1);
    if (name.startsWith("invalid")) assert.deepEqual(f.calls(), []);
  });
}
