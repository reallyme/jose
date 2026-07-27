// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

import { lstatSync, readdirSync, readFileSync, realpathSync } from "node:fs";
import { createHash } from "node:crypto";
import { extname, isAbsolute, relative, resolve, sep } from "node:path";
import { fileURLToPath } from "node:url";
import { spawnSync } from "node:child_process";

// This module is intentionally written as a standalone, vendorable release
// readiness core. Sister repositories should copy it byte-for-byte or consume a
// pinned upstream revision so release-critical checks do not drift silently.
export const RELEASE_READINESS_CORE_CONTRACT_VERSION = 8;

const DEFAULT_FAILURE_PREFIX = "release readiness check failed";

const scrubProtoCommentsAndStrings = (source) => {
  let output = "";
  let state = "normal";
  for (let index = 0; index < source.length; index += 1) {
    const character = source[index];
    const next = source[index + 1];
    if (state === "normal") {
      if (character === "/" && next === "/") {
        output += "  ";
        index += 1;
        state = "line-comment";
      } else if (character === "/" && next === "*") {
        output += "  ";
        index += 1;
        state = "block-comment";
      } else if (character === '"' || character === "'") {
        output += " ";
        state = character === '"' ? "double-quoted-string" : "single-quoted-string";
      } else {
        output += character;
      }
      continue;
    }
    if (state === "line-comment") {
      if (character === "\n") {
        output += "\n";
        state = "normal";
      } else {
        output += " ";
      }
      continue;
    }
    if (state === "block-comment") {
      if (character === "*" && next === "/") {
        output += "  ";
        index += 1;
        state = "normal";
      } else {
        output += character === "\n" ? "\n" : " ";
      }
      continue;
    }
    if (character === "\\" && next !== undefined) {
      output += next === "\n" ? " \n" : "  ";
      index += 1;
    } else if (
      (state === "double-quoted-string" && character === '"') ||
      (state === "single-quoted-string" && character === "'")
    ) {
      output += " ";
      state = "normal";
    } else {
      output += character === "\n" ? "\n" : " ";
    }
  }
  return output;
};

const scrubJavaScriptCommentsAndStrings = (source) => {
  let output = "";
  let state = "normal";
  for (let index = 0; index < source.length; index += 1) {
    const character = source[index];
    const next = source[index + 1];
    if (state === "normal") {
      if (character === "/" && next === "/") {
        output += "  ";
        index += 1;
        state = "line-comment";
      } else if (character === "/" && next === "*") {
        output += "  ";
        index += 1;
        state = "block-comment";
      } else if (character === '"' || character === "'" || character === "`") {
        output += " ";
        state =
          character === '"'
            ? "double-quoted-string"
            : character === "'"
              ? "single-quoted-string"
              : "template-string";
      } else {
        output += character;
      }
      continue;
    }
    if (state === "line-comment") {
      if (character === "\n") {
        output += "\n";
        state = "normal";
      } else {
        output += " ";
      }
      continue;
    }
    if (state === "block-comment") {
      if (character === "*" && next === "/") {
        output += "  ";
        index += 1;
        state = "normal";
      } else {
        output += character === "\n" ? "\n" : " ";
      }
      continue;
    }
    if (character === "\\" && next !== undefined) {
      output += next === "\n" ? " \n" : "  ";
      index += 1;
    } else if (
      (state === "double-quoted-string" && character === '"') ||
      (state === "single-quoted-string" && character === "'") ||
      (state === "template-string" && character === "`")
    ) {
      output += " ";
      state = "normal";
    } else {
      output += character === "\n" ? "\n" : " ";
    }
  }
  return output;
};

export function createReleaseReadinessContext(options) {
  const {
    scriptUrl,
    repoRoot = "..",
    requireTrackedFiles = false,
    failurePrefix = DEFAULT_FAILURE_PREFIX,
  } = options ?? {};

  if (typeof scriptUrl !== "string" || scriptUrl.length === 0) {
    console.error(`${failurePrefix}: scriptUrl is required`);
    process.exit(1);
  }

  let root;
  try {
    // Canonicalize the repository root so containment checks remain stable when
    // the caller reached the worktree through an operating-system path alias
    // such as /tmp versus /private/tmp.
    root = realpathSync(resolve(fileURLToPath(new URL(repoRoot, scriptUrl))));
  } catch {
    console.error(`${failurePrefix}: repository root is missing or inaccessible`);
    process.exit(1);
  }
  let trackedFiles = null;

  const fail = (message) => {
    console.error(`${failurePrefix}: ${message}`);
    process.exit(1);
  };

  const resolveRepositoryPath = (path, description = "path") => {
    if (
      typeof path !== "string" ||
      path.length === 0 ||
      path.includes("\0") ||
      isAbsolute(path)
    ) {
      fail(`${description} must be a non-empty repository-relative path`);
    }
    const absolute = resolve(root, path);
    const repositoryRelative = relative(root, absolute);
    if (
      repositoryRelative === ".." ||
      repositoryRelative.startsWith(`..${sep}`) ||
      isAbsolute(repositoryRelative)
    ) {
      fail(`${description} escapes the repository root`);
    }
    return absolute;
  };

  const assertCanonicalPathInsideRepository = (absolute, description) => {
    let canonical;
    try {
      canonical = realpathSync(absolute);
    } catch {
      fail(`${description} is missing or inaccessible`);
    }
    const repositoryRelative = relative(root, canonical);
    if (
      repositoryRelative === ".." ||
      repositoryRelative.startsWith(`..${sep}`) ||
      isAbsolute(repositoryRelative)
    ) {
      fail(`${description} resolves outside the repository root`);
    }
    return canonical;
  };

  const assertRegularFile = (path) => {
    const absolute = resolveRepositoryPath(path);
    let status;
    try {
      status = lstatSync(absolute);
    } catch {
      fail(`${path} is missing from the worktree`);
    }
    if (status.isSymbolicLink()) {
      fail(`${path} must not be a symbolic link`);
    }
    if (!status.isFile()) {
      fail(`${path} is not a regular file`);
    }
    return assertCanonicalPathInsideRepository(absolute, path);
  };

  const assertRepositoryDirectory = (path, description = path) => {
    const absolute = resolveRepositoryPath(path, description);
    let status;
    try {
      status = lstatSync(absolute);
    } catch {
      fail(`${description} is missing from the worktree`);
    }
    if (status.isSymbolicLink()) {
      fail(`${description} must not be a symbolic link`);
    }
    if (!status.isDirectory()) {
      fail(`${description} is not a directory`);
    }
    return assertCanonicalPathInsideRepository(absolute, description);
  };

  const run = (command, args, runOptions = {}) => {
    if (typeof command !== "string" || command.length === 0) {
      fail("release readiness command must be a non-empty string");
    }
    if (!Array.isArray(args) || args.some((arg) => typeof arg !== "string")) {
      fail(`${command} arguments must be an array of strings`);
    }
    const cwd =
      runOptions.cwd === undefined
        ? root
        : assertRepositoryDirectory(
            runOptions.cwd,
            `${command} working directory`,
          );
    const result = spawnSync(command, args, {
      cwd,
      encoding: "utf8",
      stdio: runOptions.capture ? "pipe" : "inherit",
      env: runOptions.env ?? process.env,
    });
    if (result.error) {
      fail(`${[command, ...args].join(" ")} failed to start: ${result.error.message}`);
    }
    if (result.status !== 0) {
      if (runOptions.capture) {
        process.stdout.write(result.stdout ?? "");
        process.stderr.write(result.stderr ?? "");
      }
      process.exit(result.status ?? 1);
    }
    return result;
  };

  const loadTrackedFiles = () => {
    if (trackedFiles !== null) {
      return trackedFiles;
    }
    const result = spawnSync("git", ["ls-files", "-z"], {
      cwd: root,
      encoding: "utf8",
      stdio: "pipe",
    });
    if (result.error) {
      fail(`git ls-files -z failed to start: ${result.error.message}`);
    }
    if (result.status !== 0) {
      process.stdout.write(result.stdout ?? "");
      process.stderr.write(result.stderr ?? "");
      process.exit(result.status ?? 1);
    }
    trackedFiles = new Set(result.stdout.split("\0").filter(Boolean));
    return trackedFiles;
  };

  const requireTracked = (path) => {
    resolveRepositoryPath(path);
    if (!loadTrackedFiles().has(path)) {
      fail(`${path} is not tracked by Git`);
    }
  };

  if (requireTrackedFiles) {
    const corePath = relative(root, fileURLToPath(import.meta.url)).replaceAll("\\", "/");
    requireTracked(corePath);
  }

  const readText = (path) => {
    if (requireTrackedFiles) {
      requireTracked(path);
    }
    return readFileSync(assertRegularFile(path), "utf8");
  };

  const readJson = (path) => {
    try {
      return JSON.parse(readText(path));
    } catch {
      fail(`${path} is not valid JSON`);
    }
  };

  const fingerprintFile = (path) =>
    createHash("sha256").update(readFileSync(assertRegularFile(path))).digest("hex");

  const listFiles = (path) => {
    resolveRepositoryPath(path);
    const directory = assertRepositoryDirectory(path);
    const prefix = `${path}/`;
    if (requireTrackedFiles) {
      const files = [...loadTrackedFiles()].filter((file) => file.startsWith(prefix));
      if (files.length === 0) {
        fail(`${path} has no tracked files`);
      }
      return files;
    }

    const files = [];
    const visit = (current) => {
      for (const entry of readdirSync(current).sort()) {
        const absolute = resolve(current, entry);
        const status = lstatSync(absolute);
        if (status.isSymbolicLink()) {
          fail(`${relative(root, absolute)} must not be a symbolic link`);
        }
        if (status.isDirectory()) {
          visit(absolute);
        } else if (status.isFile()) {
          files.push(relative(root, absolute));
        } else {
          fail(`${relative(root, absolute)} is not a regular file`);
        }
      }
    };
    visit(directory);
    return files;
  };

  const loadUntrackedFiles = () => {
    const result = spawnSync(
      "git",
      ["ls-files", "--others", "--exclude-standard", "-z"],
      {
        cwd: root,
        encoding: "utf8",
        stdio: "pipe",
      },
    );
    if (result.error) {
      fail(`git ls-files --others --exclude-standard -z failed to start: ${result.error.message}`);
    }
    if (result.status !== 0) {
      process.stdout.write(result.stdout ?? "");
      process.stderr.write(result.stderr ?? "");
      process.exit(result.status ?? 1);
    }
    return result.stdout.split("\0").filter(Boolean);
  };

  const assertContains = (path, needle) => {
    if (!readText(path).includes(needle)) {
      fail(`${path} does not contain ${needle}`);
    }
  };

  const assertNotContains = (path, needle) => {
    if (readText(path).includes(needle)) {
      fail(`${path} must not contain ${needle}`);
    }
  };

  const assertMinOccurrences = (path, needle, expectedMin) => {
    const count = readText(path).split(needle).length - 1;
    if (count < expectedMin) {
      fail(`${path} contains ${needle} ${count} time(s), expected at least ${expectedMin}`);
    }
  };

  const assertTextPolicy = (policy) => {
    const files = policy?.files ?? [];
    if (!Array.isArray(files) || files.length === 0) {
      fail("text policy requires at least one file policy");
    }

    for (const filePolicy of files) {
      const {
        path,
        required = [],
        forbidden = [],
        minimumOccurrences = [],
        requiredMatches = [],
        forbiddenMatches = [],
      } = filePolicy ?? {};
      if (typeof path !== "string" || path.length === 0) {
        fail("text file policy requires a path");
      }
      for (const [policyName, needles] of [
        ["required", required],
        ["forbidden", forbidden],
      ]) {
        if (
          !Array.isArray(needles) ||
          needles.some((needle) => typeof needle !== "string")
        ) {
          fail(`${path} ${policyName} text policy must be an array of strings`);
        }
      }
      if (!Array.isArray(minimumOccurrences)) {
        fail(`${path} minimum-occurrence policy must be an array`);
      }
      if (!Array.isArray(requiredMatches) || !Array.isArray(forbiddenMatches)) {
        fail(`${path} regular-expression policies must be arrays`);
      }
      for (const needle of required) {
        assertContains(path, needle);
      }
      for (const needle of forbidden) {
        assertNotContains(path, needle);
      }
      for (const occurrence of minimumOccurrences) {
        const { needle, count } = occurrence ?? {};
        if (typeof needle !== "string" || !Number.isSafeInteger(count) || count < 0) {
          fail(`${path} has an invalid minimum-occurrence policy`);
        }
        assertMinOccurrences(path, needle, count);
      }
      for (const matchPolicy of requiredMatches) {
        const { pattern, description } = matchPolicy ?? {};
        requireMatch(path, pattern, description);
      }
      for (const matchPolicy of forbiddenMatches) {
        const { pattern, description } = matchPolicy ?? {};
        assertNotMatches(path, pattern, description);
      }
    }
  };

  const clonePattern = (pattern) => {
    if (!(pattern instanceof RegExp)) {
      fail("release readiness match assertions require a RegExp");
    }
    return new RegExp(pattern.source, pattern.flags);
  };

  const requireMatch = (path, pattern, description) => {
    // Clone caller-provided expressions so global or sticky regex state cannot
    // make a repeated release check depend on an earlier invocation.
    const match = clonePattern(pattern).exec(readText(path));
    if (match === null) {
      fail(`${path} does not contain ${description}`);
    }
    return match;
  };

  const assertNotMatches = (path, pattern, description) => {
    // Keep this assertion deterministic when a shared expression uses `g` or `y`.
    if (clonePattern(pattern).test(readText(path))) {
      fail(`${path} must not contain ${description}`);
    }
  };

  const assertLockPackageVersion = (lock, name, version, source = null) => {
    const blocks = lock.match(/\[\[package\]\]\n[\s\S]*?(?=\n\[\[package\]\]|\n*$)/g) ?? [];
    const block = blocks.find(
      (candidate) =>
        candidate.includes(`name = "${name}"\n`) && candidate.includes(`version = "${version}"\n`),
    );
    if (block === undefined) {
      fail(`Cargo.lock does not pin ${name} ${version}`);
    }
    if (source !== null && !block.includes(`source = "${source}"\n`)) {
      fail(`Cargo.lock ${name} ${version} does not use ${source}`);
    }
  };

  const runNodeCheck = (scriptPath, args = []) => {
    const result = spawnSync(process.execPath, [scriptPath, ...args], {
      cwd: root,
      encoding: "utf8",
      stdio: "pipe",
    });
    if (result.error) {
      fail(`${[scriptPath, ...args].join(" ")} failed to start: ${result.error.message}`);
    }
    if (result.status !== 0) {
      const output = `${result.stdout ?? ""}${result.stderr ?? ""}`.trim();
      const command = [scriptPath, ...args].join(" ");
      fail(`${command} failed${output.length === 0 ? "" : `:\n${output}`}`);
    }
  };

  const packageList = (packageName) => {
    const args = ["package", "--list", "-p", packageName];
    if (process.env.GITHUB_ACTIONS !== "true") {
      args.push("--allow-dirty");
    }
    return run("cargo", args, { capture: true }).stdout.split(/\r?\n/u).filter(Boolean);
  };

  const assertPackageFiles = (packageName, requiredFiles) => {
    const files = new Set(packageList(packageName));
    for (const file of requiredFiles) {
      if (!files.has(file)) {
        fail(`${packageName} package is missing ${file}`);
      }
    }
  };

  const runCommands = (commands) => {
    if (!Array.isArray(commands) || commands.length === 0) {
      fail("command policy requires at least one command");
    }
    for (const entry of commands) {
      if (!Array.isArray(entry) || entry.length < 2 || entry.length > 3) {
        fail("command policy entries must be [command, args, options?] tuples");
      }
      const [command, args, options] = entry;
      if (
        options !== undefined &&
        (options === null || typeof options !== "object" || Array.isArray(options))
      ) {
        fail("command policy options must be an object");
      }
      run(command, args, options ?? {});
    }
  };

  const assertCargoMetadataDocument = (metadata, policy) => {
    const packages = policy?.packages ?? [];
    if (
      metadata === null ||
      typeof metadata !== "object" ||
      !Array.isArray(metadata.packages)
    ) {
      fail("cargo metadata did not return a packages array");
    }
    if (!Array.isArray(packages) || packages.length === 0) {
      fail("cargo metadata policy requires at least one package");
    }

    const packagesByName = new Map();
    for (const cargoPackage of metadata.packages) {
      if (
        cargoPackage !== null &&
        typeof cargoPackage === "object" &&
        typeof cargoPackage.name === "string"
      ) {
        if (packagesByName.has(cargoPackage.name)) {
          fail(`cargo metadata contains duplicate package ${cargoPackage.name}`);
        }
        packagesByName.set(cargoPackage.name, cargoPackage);
      }
    }

    for (const packagePolicy of packages) {
      const {
        name,
        version,
        publish = "any",
        dependencies = [],
        packageFiles = [],
      } = packagePolicy ?? {};
      if (typeof name !== "string" || name.length === 0) {
        fail("cargo metadata package policy requires a name");
      }
      const cargoPackage = packagesByName.get(name);
      if (cargoPackage === undefined) {
        fail(`cargo metadata did not expose ${name}`);
      }
      if (version !== undefined && cargoPackage.version !== version) {
        fail(`${name} metadata version is ${cargoPackage.version}, expected ${version}`);
      }
      const isPublishable =
        cargoPackage.publish === null ||
        (Array.isArray(cargoPackage.publish) && cargoPackage.publish.length > 0);
      if (publish === "public" && !isPublishable) {
        fail(`${name} must be publishable`);
      }
      if (publish === "private" && isPublishable) {
        fail(`${name} must set publish = false`);
      }
      if (!["any", "public", "private"].includes(publish)) {
        fail(`${name} has an invalid publish policy`);
      }
      if (!Array.isArray(cargoPackage.dependencies)) {
        fail(`${name} metadata dependencies are malformed`);
      }
      if (!Array.isArray(dependencies)) {
        fail(`${name} dependency policy must be an array`);
      }
      if (
        !Array.isArray(packageFiles) ||
        packageFiles.some((file) => typeof file !== "string" || file.length === 0)
      ) {
        fail(`${name} package file policy must be an array of non-empty strings`);
      }

      for (const dependencyPolicy of dependencies) {
        const {
          name: dependencyName,
          requirement,
          source = "any",
          defaultFeatures,
          optional,
          features,
          kind,
          target,
          rename,
        } = dependencyPolicy ?? {};
        if (typeof dependencyName !== "string" || dependencyName.length === 0) {
          fail(`${name} dependency policy requires a name`);
        }
        const candidates = cargoPackage.dependencies.filter(
          (candidate) =>
            candidate.name === dependencyName &&
            (kind === undefined || candidate.kind === kind) &&
            (target === undefined || candidate.target === target) &&
            (rename === undefined || candidate.rename === rename),
        );
        if (candidates.length === 0) {
          fail(`${name} is missing ${dependencyName}`);
        }
        if (candidates.length > 1) {
          fail(
            `${name} dependency ${dependencyName} is ambiguous; specify kind, target, or rename`,
          );
        }
        const [dependency] = candidates;
        if (requirement !== undefined && dependency.req !== requirement) {
          fail(
            `${name} dependency ${dependencyName} requirement is ${dependency.req}, expected ${requirement}`,
          );
        }
        if (
          source === "registry" &&
          (typeof dependency.source !== "string" ||
            !dependency.source.startsWith("registry+"))
        ) {
          fail(`${name} dependency ${dependencyName} must resolve from a registry`);
        }
        if (source === "path" && dependency.source !== null) {
          fail(`${name} dependency ${dependencyName} must resolve from a path`);
        }
        if (!["any", "registry", "path"].includes(source)) {
          fail(`${name} dependency ${dependencyName} has an invalid source policy`);
        }
        if (
          defaultFeatures !== undefined &&
          dependency.uses_default_features !== defaultFeatures
        ) {
          fail(
            `${name} dependency ${dependencyName} default-features policy does not match`,
          );
        }
        if (optional !== undefined && dependency.optional !== optional) {
          fail(`${name} dependency ${dependencyName} optional policy does not match`);
        }
        if (features !== undefined) {
          if (!Array.isArray(features) || features.some((feature) => typeof feature !== "string")) {
            fail(`${name} dependency ${dependencyName} features policy is invalid`);
          }
          const actualFeatures = new Set(dependency.features ?? []);
          for (const feature of features) {
            if (!actualFeatures.has(feature)) {
              fail(`${name} dependency ${dependencyName} is missing feature ${feature}`);
            }
          }
        }
      }

      if (packageFiles.length > 0) {
        assertPackageFiles(name, packageFiles);
      }
    }

    return packagesByName;
  };

  const assertCargoMetadataPolicy = (policy) => {
    const metadataArgs = policy?.metadataArgs ?? [
      "metadata",
      "--format-version",
      "1",
      "--no-deps",
    ];
    const metadataResult = run("cargo", metadataArgs, { capture: true });
    let metadata;
    try {
      metadata = JSON.parse(metadataResult.stdout);
    } catch {
      fail("cargo metadata returned malformed JSON");
    }
    return assertCargoMetadataDocument(metadata, policy);
  };

  const assertCargoWorkspacePolicy = (policy = {}) => {
    const {
      requireWorkspaceLints = true,
      requirePublishInclude = true,
      validatePublishablePathDependencies = true,
    } = policy;
    const metadataResult = run(
      "cargo",
      ["metadata", "--format-version", "1", "--no-deps"],
      { capture: true },
    );
    let metadata;
    try {
      metadata = JSON.parse(metadataResult.stdout);
    } catch {
      fail("cargo metadata returned malformed JSON");
    }
    if (
      !Array.isArray(metadata.packages) ||
      !Array.isArray(metadata.workspace_members)
    ) {
      fail("cargo workspace metadata is malformed");
    }

    const workspaceIds = new Set(metadata.workspace_members);
    const workspacePackages = metadata.packages.filter((cargoPackage) =>
      workspaceIds.has(cargoPackage.id),
    );
    const publishableByName = new Map();
    const parseSemver = (version) => {
      const match = /^(\d+)\.(\d+)\.(\d+)$/u.exec(version);
      if (match === null) {
        return null;
      }
      return match.slice(1).map((part) => Number.parseInt(part, 10));
    };
    const caretIncludes = (requirement, version) => {
      if (!requirement.startsWith("^")) {
        return requirement === version || requirement === `=${version}`;
      }
      const minimum = parseSemver(requirement.slice(1));
      const actual = parseSemver(version);
      if (minimum === null || actual === null || actual[0] !== minimum[0]) {
        return false;
      }
      if (minimum[0] === 0 && actual[1] !== minimum[1]) {
        return false;
      }
      return (
        actual[1] > minimum[1] ||
        (actual[1] === minimum[1] && actual[2] >= minimum[2])
      );
    };
    for (const cargoPackage of workspacePackages) {
      const manifestPath = relative(root, cargoPackage.manifest_path).replaceAll("\\", "/");
      const manifest = readText(manifestPath);
      if (
        requireWorkspaceLints &&
        !/\[lints\]\s+workspace\s*=\s*true\b/u.test(manifest)
      ) {
        fail(`${manifestPath} must inherit workspace lints`);
      }
      const publishable =
        cargoPackage.publish === null ||
        (Array.isArray(cargoPackage.publish) && cargoPackage.publish.length > 0);
      if (publishable) {
        publishableByName.set(cargoPackage.name, cargoPackage);
        if (
          requirePublishInclude &&
          !/^include\s*=\s*\[/mu.test(manifest)
        ) {
          fail(`${manifestPath} publishable package must use an include allowlist`);
        }
      }
    }

    if (validatePublishablePathDependencies) {
      for (const cargoPackage of publishableByName.values()) {
        for (const dependency of cargoPackage.dependencies ?? []) {
          if (dependency.source !== null || typeof dependency.path !== "string") {
            continue;
          }
          const dependencyName = dependency.name;
          const target = publishableByName.get(dependencyName);
          if (target === undefined) {
            continue;
          }
          if (!caretIncludes(dependency.req, target.version)) {
            fail(
              `${cargoPackage.name} publishable path dependency ${dependencyName} ${dependency.req} does not match ${target.version}`,
            );
          }
        }
      }
    }
  };

  const assertSpdxHeaders = (policy = {}) => {
    const {
      extensions = [".md", ".mjs", ".proto", ".py", ".rs", ".sh", ".toml", ".yaml", ".yml"],
      names = [".gitignore"],
      excludedPrefixes = [],
      copyright =
        "SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved",
      license = "SPDX-License-Identifier: Apache-2.0",
    } = policy;
    for (const [policyName, values] of [
      ["extensions", extensions],
      ["names", names],
      ["excluded prefixes", excludedPrefixes],
    ]) {
      if (!Array.isArray(values) || values.some((value) => typeof value !== "string")) {
        fail(`SPDX ${policyName} policy must be an array of strings`);
      }
    }
    const extensionSet = new Set(extensions);
    const nameSet = new Set(names);
    for (const path of loadTrackedFiles()) {
      if (excludedPrefixes.some((prefix) => pathIsInside(path, prefix))) {
        continue;
      }
      const fileName = path.slice(path.lastIndexOf("/") + 1);
      if (!nameSet.has(fileName) && !extensionSet.has(extname(fileName))) {
        continue;
      }
      const text = readText(path);
      if (!text.includes(copyright)) {
        fail(`${path} is missing the ReallyMe SPDX copyright header`);
      }
      if (!text.includes(license)) {
        fail(`${path} is missing the Apache-2.0 SPDX license header`);
      }
    }
  };

  const snapshotDirectory = (path) => {
    const directory = assertRepositoryDirectory(path);
    const snapshot = new Map();
    const visit = (current) => {
      let entries;
      try {
        entries = readdirSync(current).sort();
      } catch {
        fail(`${relative(root, current)} is missing or inaccessible`);
      }
      for (const entry of entries) {
        const absolute = resolve(current, entry);
        const status = lstatSync(absolute);
        if (status.isSymbolicLink()) {
          fail(`${relative(root, absolute)} must not be a symbolic link`);
        }
        if (status.isDirectory()) {
          visit(absolute);
        } else if (status.isFile()) {
          const file = relative(directory, absolute);
          snapshot.set(file, fingerprintFile(`${path}/${file}`));
        } else {
          fail(`${relative(root, absolute)} is not a regular file`);
        }
      }
    };
    visit(directory);

    if (requireTrackedFiles) {
      const prefix = `${path}/`;
      const tracked = new Set(
        listFiles(path).map((file) => file.slice(prefix.length)),
      );
      for (const file of snapshot.keys()) {
        if (!tracked.has(file)) {
          fail(`${path}/${file} is not tracked by Git`);
        }
      }
      for (const file of tracked) {
        if (!snapshot.has(file)) {
          fail(`${path}/${file} is tracked by Git but missing from the worktree`);
        }
      }
    }

    return snapshot;
  };

  const assertSnapshotsEqual = (path, before, after) => {
    if (before.size !== after.size) {
      fail(`${path} changed file count after regeneration`);
    }

    for (const [file, contents] of before) {
      const regenerated = after.get(file);
      if (regenerated === undefined || contents !== regenerated) {
        fail(`${path}/${file} is stale; run the protobuf generation and hardening steps`);
      }
    }
  };

  const pathIsInside = (path, directory) =>
    path === directory || path.startsWith(`${directory}/`);

  const snapshotRepositoryFilesOutside = (excludedPaths) => {
    const excluded = excludedPaths.map((path) => {
      resolveRepositoryPath(path);
      return path.replace(/\/+$/u, "");
    });
    const files = new Set([...loadTrackedFiles(), ...loadUntrackedFiles()]);
    const snapshot = new Map();
    for (const file of files) {
      if (excluded.some((path) => pathIsInside(file, path))) {
        continue;
      }
      snapshot.set(file, fingerprintFile(file));
    }
    return snapshot;
  };

  const assertRepositorySnapshotsEqual = (before, after) => {
    if (before.size !== after.size) {
      fail("protobuf regeneration changed files outside the declared generated paths");
    }
    for (const [file, contents] of before) {
      const regenerated = after.get(file);
      if (regenerated === undefined || contents !== regenerated) {
        fail(`protobuf regeneration modified ${file} outside the declared generated paths`);
      }
    }
  };

  const validateGeneratedArtifactsPolicy = (regeneration) => {
    const generatedPaths = regeneration?.generatedPaths ?? [];
    const commands = regeneration?.commands ?? [];
    if (!Array.isArray(generatedPaths) || generatedPaths.length === 0) {
      fail("generated artifact freshness check requires at least one generated path");
    }
    if (generatedPaths.some((path) => typeof path !== "string" || path.length === 0)) {
      fail("generated artifact paths must be non-empty strings");
    }
    if (!Array.isArray(commands) || commands.length === 0) {
      fail("generated artifact freshness check requires at least one regeneration command");
    }
    const normalizedPaths = generatedPaths.map((path) =>
      relative(root, assertRepositoryDirectory(path, "generated artifact path")).replaceAll(
        "\\",
        "/",
      ),
    );
    if (normalizedPaths.some((path) => path.length === 0 || path === ".")) {
      fail("generated artifact paths must not include the repository root");
    }
    for (const [index, path] of normalizedPaths.entries()) {
      if (
        normalizedPaths.some(
          (candidate, candidateIndex) =>
            candidateIndex !== index && pathIsInside(path, candidate),
        )
      ) {
        fail("generated artifact paths must not overlap");
      }
    }
    for (const entry of commands) {
      if (!Array.isArray(entry) || entry.length < 2 || entry.length > 3) {
        fail("regeneration commands must be [command, args, options?] tuples");
      }
      const [command, args] = entry;
      if (
        typeof command !== "string" ||
        command.length === 0 ||
        !Array.isArray(args) ||
        args.some((arg) => typeof arg !== "string")
      ) {
        fail("regeneration commands require a command and string arguments");
      }
      const options = entry[2];
      if (
        options !== undefined &&
        (options === null || typeof options !== "object" || Array.isArray(options))
      ) {
        fail("regeneration command options must be an object");
      }
    }
    return { generatedPaths: normalizedPaths, commands };
  };

  const assertGeneratedArtifactsFresh = (regeneration) => {
    const { generatedPaths, commands } = validateGeneratedArtifactsPolicy(regeneration);

    const snapshotsBefore = new Map(
      generatedPaths.map((path) => [path, snapshotDirectory(path)]),
    );
    const repositoryBefore = requireTrackedFiles
      ? snapshotRepositoryFilesOutside(generatedPaths)
      : null;
    runCommands(commands);
    for (const path of generatedPaths) {
      assertSnapshotsEqual(path, snapshotsBefore.get(path), snapshotDirectory(path));
    }
    if (repositoryBefore !== null) {
      assertRepositorySnapshotsEqual(
        repositoryBefore,
        snapshotRepositoryFilesOutside(generatedPaths),
      );
    }
  };

  const assertGeneratedProtoHardeningPolicy = (policy) => {
    const {
      hardeningScript,
      protoSchema,
      generatedRust,
      generatedView,
      protoCargo,
      workflow,
      workflowStepName,
      workflowStepRun,
      requiredScriptNeedles = [],
      forbiddenScriptNeedles = [],
      requiredGeneratedNeedles = [],
      forbiddenGeneratedNeedles = [],
      requiredViewNeedles = [],
      requiredCargoNeedles = [],
      scalarFieldClassifications = [],
      additionalGeneratedPolicies = [],
      requireIdempotence = true,
      requireStrictJson = true,
      requireUnknownFieldZeroization = true,
    } = policy ?? {};

    if (typeof hardeningScript !== "string" || hardeningScript.length === 0) {
      fail("generated proto hardening policy requires a hardeningScript path");
    }
    if (typeof generatedRust !== "string" || generatedRust.length === 0) {
      fail("generated proto hardening policy requires a generatedRust path");
    }
    if (typeof protoSchema !== "string" || protoSchema.length === 0) {
      fail("generated proto hardening policy requires a protoSchema path");
    }
    for (const [policyName, needles] of [
      ["required script", requiredScriptNeedles],
      ["forbidden script", forbiddenScriptNeedles],
      ["required generated", requiredGeneratedNeedles],
      ["forbidden generated", forbiddenGeneratedNeedles],
      ["required view", requiredViewNeedles],
      ["required Cargo", requiredCargoNeedles],
    ]) {
      if (
        !Array.isArray(needles) ||
        needles.some((needle) => typeof needle !== "string")
      ) {
        fail(`generated proto ${policyName} policy must be an array of strings`);
      }
    }
    if (requiredScriptNeedles.length === 0) {
      fail("generated proto hardening policy requires script invariants");
    }
    if (typeof requireIdempotence !== "boolean") {
      fail("generated proto hardening idempotence policy must be a boolean");
    }
    if (requiredGeneratedNeedles.length === 0) {
      fail("generated proto hardening policy requires generated-code invariants");
    }
    if (forbiddenGeneratedNeedles.length === 0) {
      fail("generated proto hardening policy requires forbidden generated-code invariants");
    }
    if (!Array.isArray(scalarFieldClassifications)) {
      fail("generated proto scalar field classifications must be an array");
    }
    if (scalarFieldClassifications.length === 0) {
      fail("generated proto hardening policy requires scalar field classifications");
    }
    const normalizedScalarFieldClassifications = scalarFieldClassifications.map((entry) => {
      if (
        entry !== null &&
        typeof entry === "object" &&
        !Array.isArray(entry) &&
        typeof entry.message === "string" &&
        /^[A-Za-z_][A-Za-z0-9_]*$/u.test(entry.message) &&
        typeof entry.field === "string" &&
        /^[A-Za-z_][A-Za-z0-9_]*$/u.test(entry.field) &&
        (entry.kind === "bytes" || entry.kind === "string") &&
        (entry.sensitivity === "sensitive" || entry.sensitivity === "public") &&
        Object.keys(entry).every((key) =>
          ["message", "field", "kind", "sensitivity"].includes(key),
        )
      ) {
        return {
          field: entry.field,
          kind: entry.kind,
          message: entry.message,
          sensitivity: entry.sensitivity,
        };
      }
      fail(
        "generated proto scalar classifications require { message, field, kind, sensitivity } objects",
      );
    });
    const classificationKeys = new Set();
    for (const entry of normalizedScalarFieldClassifications) {
      const key = `${entry.message}.${entry.field}:${entry.kind}`;
      if (classificationKeys.has(key)) {
        fail(`generated proto scalar classification is duplicated for ${key}`);
      }
      classificationKeys.add(key);
    }
    const protoText = scrubProtoCommentsAndStrings(readText(protoSchema));
    const scalarSchemaKeys = new Set();
    const messagePattern = /^\s*message\s+([A-Za-z_][A-Za-z0-9_]*)\s*\{/gmu;
    for (const messageMatch of protoText.matchAll(messagePattern)) {
      const openIndex = messageMatch.index + messageMatch[0].lastIndexOf("{");
      let depth = 0;
      let closeIndex = -1;
      for (let index = openIndex; index < protoText.length; index += 1) {
        if (protoText[index] === "{") {
          depth += 1;
        } else if (protoText[index] === "}") {
          depth -= 1;
          if (depth === 0) {
            closeIndex = index;
            break;
          }
        }
      }
      if (closeIndex === -1) {
        fail(`${protoSchema} has an unterminated message ${messageMatch[1]}`);
      }
      const body = protoText.slice(openIndex + 1, closeIndex);
      if (/^\s+message\s+[A-Za-z_][A-Za-z0-9_]*\s*\{/mu.test(body)) {
        fail(
          `${protoSchema} nested messages require an explicit scalar-classifier extension`,
        );
      }
      if (/\bmap\s*<[^>]*(?:bytes|string)[^>]*>/u.test(body)) {
        fail(
          `${protoSchema} maps with bytes/string members require an explicit scalar-classifier extension`,
        );
      }
      for (const fieldMatch of body.matchAll(
        /(?:^|[;{}])\s*(?:(?:optional|required|repeated)\s+)?(bytes|string)\s+([A-Za-z_][A-Za-z0-9_]*)\s*=\s*\d+(?:\s*\[[^\]]*\])?\s*(?=;)/gmu,
      )) {
        scalarSchemaKeys.add(`${messageMatch[1]}.${fieldMatch[2]}:${fieldMatch[1]}`);
      }
    }
    for (const key of scalarSchemaKeys) {
      if (!classificationKeys.has(key)) {
        fail(`${protoSchema} has unclassified protobuf scalar field ${key}`);
      }
    }
    for (const key of classificationKeys) {
      if (!scalarSchemaKeys.has(key)) {
        fail(`generated proto scalar classification is stale for ${key}`);
      }
    }
    const sensitiveScalarFields = normalizedScalarFieldClassifications.filter(
      (entry) => entry.sensitivity === "sensitive",
    );
    if (sensitiveScalarFields.length === 0) {
      fail("generated proto hardening policy requires at least one sensitive scalar field");
    }
    if (!Array.isArray(additionalGeneratedPolicies)) {
      fail("additional generated hardening policies must be an array");
    }
    for (const [policyName, value] of [
      ["generated view", generatedView],
      ["proto Cargo", protoCargo],
      ["workflow", workflow],
      ["workflow step name", workflowStepName],
      ["workflow step run", workflowStepRun],
    ]) {
      if (value !== undefined && typeof value !== "string") {
        fail(`generated proto ${policyName} policy must be a string`);
      }
    }
    if (
      typeof generatedView === "string" &&
      generatedView.length !== 0 &&
      requiredViewNeedles.length === 0
    ) {
      fail("generated proto hardening policy requires generated view invariants");
    }
    if (
      typeof protoCargo === "string" &&
      protoCargo.length !== 0 &&
      requiredCargoNeedles.length === 0
    ) {
      fail("generated proto hardening policy requires proto Cargo invariants");
    }
    const workflowValues = [workflow, workflowStepName, workflowStepRun];
    const configuredWorkflowValues = workflowValues.filter(
      (value) => typeof value === "string" && value.length !== 0,
    );
    if (
      configuredWorkflowValues.length !== 0 &&
      configuredWorkflowValues.length !== workflowValues.length
    ) {
      fail("generated proto workflow policy must configure path, step name, and run command");
    }

    for (const needle of requiredScriptNeedles) {
      assertContains(hardeningScript, needle);
    }
    if (requireIdempotence) {
      assertContains(hardeningScript, '"--check-idempotent"');
    }
    for (const needle of forbiddenScriptNeedles) {
      assertNotContains(hardeningScript, needle);
    }
    const generatedRustText = readText(generatedRust);
    const messageRegion = (message) => {
      const startNeedle = `pub struct ${message} {`;
      const start = generatedRustText.indexOf(startNeedle);
      if (start === -1) {
        fail(`${generatedRust} does not define generated message ${message}`);
      }
      const remainder = generatedRustText.slice(start + startNeedle.length);
      const nextMessage = /^pub struct [A-Z][A-Za-z0-9]* \{/gmu.exec(remainder);
      const end =
        nextMessage === null
          ? generatedRustText.length
          : start + startNeedle.length + nextMessage.index;
      return generatedRustText.slice(start, end);
    };
    for (const { field, kind, message } of sensitiveScalarFields) {
      const scope = messageRegion(message);
      for (const needle of [
        `.field("${field}", &"<redacted>")`,
        `::zeroize::Zeroize::zeroize(&mut self.${field});`,
        kind === "bytes"
          ? `${field}: ::zeroize::Zeroizing<::buffa::alloc::vec::Vec<u8>>`
          : `${field}: ::zeroize::Zeroizing<::buffa::alloc::string::String>`,
      ]) {
        if (!scope.includes(needle)) {
          fail(`${generatedRust} message ${message} does not contain ${needle}`);
        }
      }
      if (scope.includes(`.field("${field}", &self.${field})`)) {
        fail(`${generatedRust} message ${message} must not expose ${field} in generated Debug output`);
      }
      // Buffa's generated message storage remains Vec<u8>. Sensitive
      // ProtoJSON decoding must stage bytes in a zeroizing temporary, while
      // generated clear and Drop paths wipe the final generated field owner.
    }
    if (requireStrictJson) {
      assertContains(generatedRust, "#[serde(default, deny_unknown_fields)]");
    }
    if (requireUnknownFieldZeroization) {
      for (const needle of [
        "::buffa::UnknownFieldData::LengthDelimited(bytes)",
        "::buffa::UnknownFieldData::Group(fields)",
        "__reallyme_zeroize_unknown_fields(fields);",
      ]) {
        assertContains(hardeningScript, needle);
      }
      assertContains(generatedRust, "fn __reallyme_zeroize_unknown_fields(");
      assertContains(
        generatedRust,
        "::buffa::UnknownFieldData::LengthDelimited(bytes)",
      );
      assertContains(
        generatedRust,
        "::buffa::UnknownFieldData::Group(fields)",
      );
      assertContains(
        generatedRust,
        "__reallyme_zeroize_unknown_fields(fields);",
      );
      assertContains(
        generatedRust,
        "__reallyme_zeroize_unknown_fields(&mut self.__buffa_unknown_fields);",
      );
    }
    for (const needle of requiredGeneratedNeedles) {
      assertContains(generatedRust, needle);
    }
    for (const needle of forbiddenGeneratedNeedles) {
      assertNotContains(generatedRust, needle);
    }
    if (typeof generatedView === "string" && generatedView.length !== 0) {
      for (const needle of requiredViewNeedles) {
        assertContains(generatedView, needle);
      }
    }
    if (typeof protoCargo === "string" && protoCargo.length !== 0) {
      for (const needle of requiredCargoNeedles) {
        assertContains(protoCargo, needle);
      }
    }
    for (const generatedPolicy of additionalGeneratedPolicies) {
      assertTextPolicy({ files: [generatedPolicy] });
    }
    if (
      typeof workflow === "string" &&
      workflow.length !== 0 &&
      typeof workflowStepName === "string" &&
      workflowStepName.length !== 0 &&
      typeof workflowStepRun === "string" &&
      workflowStepRun.length !== 0
    ) {
      assertWorkflowRunStep(workflow, workflowStepName, workflowStepRun);
    }
  };

  const assertReallyMeProtobufReleasePolicy = (policy) => {
    const {
      workflow = ".github/workflows/protobuf-ci.yml",
      corePath = "scripts/release-readiness/core.mjs",
      bufVersion = "1.71.0",
      buffaVersion = "0.8.1",
      installBufStepName = "Install buf",
      installBufUses = null,
      installBufRun = null,
      installBuffaStepName = "Install pinned Buffa generators",
      lintStepName = "Lint protobuf schema",
      generateStepName = "Regenerate protobuf artifacts",
      hardeningPolicy,
      generatedFreshnessMode = false,
      generatedFreshness,
      generatedFreshnessStepName = "Check release readiness generated freshness",
      generatedFreshnessStepRun = "node scripts/check_release_readiness.mjs --generated-freshness",
      workflowMode = "explicit",
    } = policy ?? {};

    assertContains(workflow, `BUFFA_VERSION: ${buffaVersion}`);
    assertContains(workflow, `BUF_VERSION: ${bufVersion}`);
    assertContains(workflow, corePath);
    validateGeneratedArtifactsPolicy(generatedFreshness);

    if (installBufUses !== null) {
      assertWorkflowUsesStep(workflow, installBufStepName, installBufUses);
    }
    if (installBufRun !== null) {
      assertWorkflowRunStep(workflow, installBufStepName, installBufRun);
    }
    assertWorkflowRunStep(
      workflow,
      installBuffaStepName,
      `cargo install protoc-gen-buffa --version "$BUFFA_VERSION" --locked
cargo install protoc-gen-buffa-packaging --version "$BUFFA_VERSION" --locked`,
    );
    assertWorkflowRunStep(workflow, generatedFreshnessStepName, generatedFreshnessStepRun);

    if (workflowMode === "explicit") {
      assertWorkflowRunStep(workflow, lintStepName, "buf lint");
      assertWorkflowRunStep(workflow, generateStepName, "buf generate");
    } else if (workflowMode === "delegated") {
      const duplicateCommands = extractWorkflowSteps(workflow).filter(
        (step) =>
          step.name !== generatedFreshnessStepName &&
          typeof step.run === "string" &&
          /(?:^|\n)\s*buf\s+(?:lint|generate)\b/u.test(step.run),
      );
      if (duplicateCommands.length > 0) {
        fail(
          `${workflow} duplicates protobuf generation outside ${generatedFreshnessStepName}`,
        );
      }
    } else {
      fail(`unsupported protobuf workflow mode ${workflowMode}`);
    }

    assertGeneratedProtoHardeningPolicy(hardeningPolicy);

    if (generatedFreshnessMode) {
      assertGeneratedArtifactsFresh(generatedFreshness);
    }
  };

  const assertReallyMeVendoredCorePolicy = (policy = {}) => {
    const {
      scriptPath = "scripts/check_release_readiness.mjs",
      corePath = "scripts/release-readiness/core.mjs",
      contractVersion = RELEASE_READINESS_CORE_CONTRACT_VERSION,
    } = policy;

    requireTracked(scriptPath);
    requireTracked(corePath);
    const executableCore = scrubJavaScriptCommentsAndStrings(readText(corePath));
    const requireCoreDeclaration = (name) => {
      const declaration = new RegExp(
        `\\b(?:const|function)\\s+${escapeRegExp(name)}\\b`,
        "u",
      );
      if (!declaration.test(executableCore)) {
        fail(`${corePath} must define ${name}`);
      }
    };
    const requireCoreExport = (name) => {
      const exportPattern = new RegExp(`\\b${escapeRegExp(name)}\\s*,`, "u");
      if (!exportPattern.test(executableCore)) {
        fail(`${corePath} must export ${name}`);
      }
    };

    assertContains(corePath, `RELEASE_READINESS_CORE_CONTRACT_VERSION = ${contractVersion}`);
    for (const name of [
      "assertGeneratedArtifactsFresh",
      "assertGeneratedProtoHardeningPolicy",
      "assertReallyMeProtobufReleasePolicy",
      "assertReallyMeVendoredCorePolicy",
      "assertReallyMeRustProtoRepositoryPolicy",
      "assertCargoMetadataPolicy",
      "assertCargoWorkspacePolicy",
      "assertTextPolicy",
      "assertSpdxHeaders",
      "assertWorkflowActionsPinned",
      "assertWorkflowPolicy",
      "runCommands",
      "assertProtoContract",
      "assertReallyMeProtoBoundaryContract",
      "assertReallyMeOperationBoundaryContract",
      "assertWorkflowRunStep",
      "assertWorkflowUsesStep",
    ]) {
      requireCoreDeclaration(name);
      requireCoreExport(name);
    }
    for (const identifier of [
      "scalarFieldClassifications",
      "messagePattern",
      "scalarSchemaKeys",
    ]) {
      if (!new RegExp(`\\b${escapeRegExp(identifier)}\\b`, "u").test(executableCore)) {
        fail(`${corePath} must enforce ${identifier}`);
      }
    }
  };

  const escapeRegExp = (value) => value.replace(/[.*+?^${}()|[\]\\]/gu, "\\$&");

  const assertNodeWorkflowJobsPinNode = (workflowOptions = {}) => {
    const workflowDirectoryPath = workflowOptions.workflowDirectory ?? ".github/workflows";
    const workflowDirectory = assertRepositoryDirectory(
      workflowDirectoryPath,
      "workflow directory",
    );
    const nodeVersion = workflowOptions.nodeVersion ?? "24";
    const nodeToolCommands = workflowOptions.nodeToolCommands ?? [
      "node",
      "npm",
      "npx",
      "pnpm",
      "yarn",
      "corepack",
      "bun",
    ];
    if (
      !Array.isArray(nodeToolCommands) ||
      nodeToolCommands.some(
        (command) => typeof command !== "string" || !/^[A-Za-z0-9_-]+$/u.test(command),
      )
    ) {
      fail("Node workflow tool policy must be an array of command names");
    }
    const nodeToolPattern = new RegExp(
      `\\b(?:${nodeToolCommands.map(escapeRegExp).join("|")})\\b`,
      "u",
    );
    for (const workflowFile of readdirSync(workflowDirectory).filter((name) => /\.ya?ml$/u.test(name))) {
      const workflowPath = `${workflowDirectoryPath}/${workflowFile}`;
      const workflow = readText(workflowPath);
      const jobsOffset = workflow.indexOf("\njobs:\n");
      if (jobsOffset === -1) {
        continue;
      }
      const jobs = workflow.slice(jobsOffset + 1);
      const jobHeaders = [...jobs.matchAll(/^  ([a-zA-Z0-9_-]+):\s*$/gm)];
      for (const [index, header] of jobHeaders.entries()) {
        const nextHeader = jobHeaders[index + 1];
        const job = jobs.slice(header.index, nextHeader?.index ?? jobs.length);
        const activeJob = job
          .split("\n")
          .filter((line) => !line.trimStart().startsWith("#"))
          .join("\n");
        if (!nodeToolPattern.test(activeJob)) {
          continue;
        }
        if (!/^\s*uses:\s*actions\/setup-node@[^\s#]+(?:\s+#.*)?$/m.test(activeJob)) {
          fail(`${workflowPath} job ${header[1]} uses Node tooling without actions/setup-node`);
        }
        const pinnedNodeVersion = activeJob.split("\n").some((line) => {
          const match = /^\s*node-version:\s*(.+?)\s*$/u.exec(line);
          return match !== null && unquoteWorkflowScalar(match[1]) === nodeVersion;
        });
        if (!pinnedNodeVersion) {
          fail(`${workflowPath} job ${header[1]} must pin Node ${nodeVersion}`);
        }
      }
    }
  };

  const normalizeWorkflowRunCommand = (command) =>
    command
      .replace(/\r\n/gu, "\n")
      .split("\n")
      .map((line) => line.trimEnd())
      .join("\n")
      .trim();

  const stripWorkflowInlineComment = (value) => {
    let quote = null;
    for (let index = 0; index < value.length; index += 1) {
      const character = value[index];
      if (quote !== null) {
        if (character === quote && value[index - 1] !== "\\") {
          quote = null;
        }
        continue;
      }
      if (character === '"' || character === "'") {
        quote = character;
        continue;
      }
      if (character === "#" && (index === 0 || /\s/u.test(value[index - 1]))) {
        return value.slice(0, index);
      }
    }
    return value;
  };

  const unquoteWorkflowScalar = (value) => {
    const trimmed = stripWorkflowInlineComment(value).trim();
    if (
      (trimmed.startsWith('"') && trimmed.endsWith('"')) ||
      (trimmed.startsWith("'") && trimmed.endsWith("'"))
    ) {
      return trimmed.slice(1, -1);
    }
    return trimmed;
  };

  const countLeadingSpaces = (line) => {
    const match = /^ */u.exec(line);
    return match?.[0].length ?? 0;
  };

  const extractWorkflowStepsFromLines = (path, lines, start, end, jobName = null) => {
    const steps = [];
    for (let index = start; index < end; index += 1) {
      const nameMatch = /^(\s*)-\s+name:\s*(.+?)\s*$/u.exec(lines[index]);
      if (nameMatch === null) {
        continue;
      }

      const stepIndent = nameMatch[1].length;
      const name = unquoteWorkflowScalar(nameMatch[2]);
      let end = lines.length;
      for (let cursor = index + 1; cursor < lines.length; cursor += 1) {
        const candidate = lines[cursor];
        if (countLeadingSpaces(candidate) === stepIndent && /^\s*-\s+/u.test(candidate)) {
          end = cursor;
          break;
        }
      }

      let run = null;
      let uses = null;
      for (let cursor = index + 1; cursor < end; cursor += 1) {
        const runMatch = /^(\s*)run:\s*(.*)\s*$/u.exec(lines[cursor]);
        if (runMatch !== null) {
          if (run !== null) {
            fail(`${path} step ${name} defines run more than once`);
          }
          const runIndent = runMatch[1].length;
          const marker = runMatch[2].trim();
          if (marker === ">") {
            fail(`${path} step ${name} uses an unsupported folded run scalar`);
          }
          if (marker === "|") {
            const blockLines = [];
            for (let blockCursor = cursor + 1; blockCursor < end; blockCursor += 1) {
              const blockLine = lines[blockCursor];
              if (blockLine.trim().length !== 0 && countLeadingSpaces(blockLine) <= runIndent) {
                break;
              }
              blockLines.push(blockLine);
            }
            const nonBlankIndents = blockLines
              .filter((line) => line.trim().length !== 0)
              .map((line) => countLeadingSpaces(line));
            const blockIndent =
              nonBlankIndents.length === 0 ? runIndent + 2 : Math.min(...nonBlankIndents);
            run = blockLines.map((line) => line.slice(Math.min(blockIndent, line.length))).join("\n");
          } else {
            run = unquoteWorkflowScalar(marker);
          }
        }

        const usesMatch = /^\s*uses:\s*(.+?)\s*$/u.exec(lines[cursor]);
        if (usesMatch !== null) {
          if (uses !== null) {
            fail(`${path} step ${name} defines uses more than once`);
          }
          uses = unquoteWorkflowScalar(usesMatch[1]);
        }
      }

      steps.push({ job: jobName, name, run, uses });
    }
    return steps;
  };

  const extractWorkflowJobs = (path) => {
    const lines = readText(path).replace(/\r\n/gu, "\n").split("\n");
    const jobsLine = lines.findIndex((line) => /^jobs:\s*$/u.test(line));
    if (jobsLine === -1) {
      return [];
    }
    const headers = [];
    for (let index = jobsLine + 1; index < lines.length; index += 1) {
      const match = /^  ([A-Za-z0-9_-]+):\s*$/u.exec(lines[index]);
      if (match !== null) {
        headers.push({ name: match[1], index });
      }
    }
    return headers.map((header, index) => ({
      name: header.name,
      start: header.index,
      end: headers[index + 1]?.index ?? lines.length,
      lines,
    }));
  };

  const parseWorkflowPermissionBlock = (path, lines, headerIndex, headerIndent, label) => {
    const permissions = new Map();
    for (let index = headerIndex + 1; index < lines.length; index += 1) {
      const line = lines[index];
      const trimmed = line.trim();
      if (trimmed.length === 0 || trimmed.startsWith("#")) {
        continue;
      }
      const indent = countLeadingSpaces(line);
      if (indent <= headerIndent) {
        break;
      }
      const match = /^\s*([A-Za-z0-9_-]+):\s*(read|write|none)\s*(?:#.*)?$/u.exec(line);
      if (indent !== headerIndent + 2 || match === null) {
        fail(`${path} ${label} permissions must be a flat explicit mapping`);
      }
      if (permissions.has(match[1])) {
        fail(`${path} ${label} permission ${match[1]} is defined more than once`);
      }
      permissions.set(match[1], match[2]);
    }
    if (permissions.size === 0) {
      fail(`${path} ${label} permissions mapping must not be empty`);
    }
    return permissions;
  };

  const validateExpectedPermissions = (path, label, value) => {
    if (
      value === null ||
      typeof value !== "object" ||
      Array.isArray(value) ||
      Object.entries(value).some(
        ([scope, access]) =>
          !/^[A-Za-z0-9_-]+$/u.test(scope) ||
          !["read", "write", "none"].includes(access),
      )
    ) {
      fail(`${path} ${label} expected permissions must be an explicit mapping`);
    }
    return new Map(Object.entries(value));
  };

  const assertPermissionMapsEqual = (path, label, actual, expected) => {
    if (
      actual.size !== expected.size ||
      [...expected].some(([scope, access]) => actual.get(scope) !== access)
    ) {
      fail(`${path} ${label} permissions changed`);
    }
  };

  const assertWorkflowPermissionsPolicy = (policy) => {
    const { path, workflow, jobs = {} } = policy ?? {};
    if (typeof path !== "string" || path.length === 0) {
      fail("workflow permissions policy requires a path");
    }
    const expectedWorkflow = validateExpectedPermissions(path, "workflow", workflow);
    if (jobs === null || typeof jobs !== "object" || Array.isArray(jobs)) {
      fail(`${path} expected job permissions must be an explicit mapping`);
    }

    const lines = readText(path).replace(/\r\n/gu, "\n").split("\n");
    const workflowHeaders = lines
      .map((line, index) => ({ index, matches: /^permissions:\s*$/u.test(line) }))
      .filter((entry) => entry.matches);
    if (workflowHeaders.length !== 1) {
      fail(`${path} must define exactly one top-level permissions mapping`);
    }
    const actualWorkflow = parseWorkflowPermissionBlock(
      path,
      lines,
      workflowHeaders[0].index,
      0,
      "workflow",
    );
    assertPermissionMapsEqual(path, "workflow", actualWorkflow, expectedWorkflow);

    const actualJobs = new Map();
    for (const job of extractWorkflowJobs(path)) {
      const headers = [];
      for (let index = job.start + 1; index < job.end; index += 1) {
        if (/^ {4}permissions:\s+\S/u.test(lines[index])) {
          fail(`${path} job ${job.name} permissions must be a flat explicit mapping`);
        }
        if (/^ {4}permissions:\s*$/u.test(lines[index])) {
          headers.push(index);
        }
      }
      if (headers.length > 1) {
        fail(`${path} job ${job.name} defines permissions more than once`);
      }
      if (headers.length === 1) {
        actualJobs.set(
          job.name,
          parseWorkflowPermissionBlock(path, lines, headers[0], 4, `job ${job.name}`),
        );
      }
    }

    const expectedJobs = new Map();
    for (const [jobName, permissions] of Object.entries(jobs)) {
      if (!/^[A-Za-z0-9_-]+$/u.test(jobName)) {
        fail(`${path} expected job permission name is invalid`);
      }
      expectedJobs.set(
        jobName,
        validateExpectedPermissions(path, `job ${jobName}`, permissions),
      );
    }
    if (
      actualJobs.size !== expectedJobs.size ||
      [...actualJobs.keys()].some((jobName) => !expectedJobs.has(jobName))
    ) {
      fail(`${path} jobs with explicit permissions changed`);
    }
    for (const [jobName, expected] of expectedJobs) {
      const actual = actualJobs.get(jobName);
      if (actual === undefined) {
        fail(`${path} job ${jobName} is missing explicit permissions`);
      }
      assertPermissionMapsEqual(path, `job ${jobName}`, actual, expected);
    }
  };

  const extractWorkflowSteps = (path) => {
    const jobs = extractWorkflowJobs(path);
    if (jobs.length === 0) {
      const lines = readText(path).replace(/\r\n/gu, "\n").split("\n");
      return extractWorkflowStepsFromLines(path, lines, 0, lines.length);
    }
    return jobs.flatMap((job) =>
      extractWorkflowStepsFromLines(path, job.lines, job.start, job.end, job.name),
    );
  };

  const findWorkflowStep = (path, stepName) => {
    if (typeof stepName !== "string" || stepName.length === 0) {
      fail(`${path} workflow step policy requires a step name`);
    }
    const steps = extractWorkflowSteps(path).filter(
      (candidate) => candidate.name === stepName,
    );
    if (steps.length === 0) {
      fail(`${path} is missing workflow step ${stepName}`);
    }
    if (steps.length > 1) {
      fail(`${path} defines workflow step ${stepName} more than once`);
    }
    return steps[0];
  };

  const assertWorkflowRunStep = (path, stepName, expectedRun) => {
    if (typeof expectedRun !== "string" || expectedRun.length === 0) {
      fail(`${path} step ${stepName} requires an expected run command`);
    }
    const step = findWorkflowStep(path, stepName);
    if (step.run === null) {
      fail(`${path} step ${stepName} does not define a run command`);
    }
    const actual = normalizeWorkflowRunCommand(step.run);
    const expected = normalizeWorkflowRunCommand(expectedRun);
    if (actual !== expected) {
      fail(`${path} step ${stepName} run command changed`);
    }
  };

  const assertWorkflowUsesStep = (path, stepName, expectedUses) => {
    if (typeof expectedUses !== "string" || expectedUses.length === 0) {
      fail(`${path} step ${stepName} requires an expected action`);
    }
    const step = findWorkflowStep(path, stepName);
    const expected = unquoteWorkflowScalar(expectedUses);
    if (step.uses !== expected) {
      fail(`${path} step ${stepName} must use ${expected}`);
    }
  };

  const assertWorkflowPolicy = (policy) => {
    const {
      path,
      required = [],
      forbidden = [],
      runSteps = [],
      usesSteps = [],
    } = policy ?? {};
    if (typeof path !== "string" || path.length === 0) {
      fail("workflow policy requires a path");
    }
    for (const [policyName, values] of [
      ["required", required],
      ["forbidden", forbidden],
    ]) {
      if (
        !Array.isArray(values) ||
        values.some((value) => typeof value !== "string")
      ) {
        fail(`${path} workflow ${policyName} policy must be an array of strings`);
      }
    }
    if (!Array.isArray(runSteps) || !Array.isArray(usesSteps)) {
      fail(`${path} workflow step policies must be arrays`);
    }
    for (const needle of required) {
      assertContains(path, needle);
    }
    for (const needle of forbidden) {
      assertNotContains(path, needle);
    }
    for (const step of runSteps) {
      assertWorkflowRunStep(path, step?.name, step?.run);
    }
    for (const step of usesSteps) {
      assertWorkflowUsesStep(path, step?.name, step?.uses);
    }
  };

  const assertWorkflowActionsPinned = (workflowOptions = {}) => {
    const workflowDirectoryPath = workflowOptions.workflowDirectory ?? ".github/workflows";
    const workflowDirectory = assertRepositoryDirectory(
      workflowDirectoryPath,
      "workflow directory",
    );
    const allowedNonShaUsesPolicy = workflowOptions.allowedNonShaUses ?? [];
    if (
      !Array.isArray(allowedNonShaUsesPolicy) ||
      allowedNonShaUsesPolicy.some((uses) => typeof uses !== "string")
    ) {
      fail("allowed non-SHA workflow actions must be an array of strings");
    }
    const allowedNonShaUses = new Set(allowedNonShaUsesPolicy);
    const allowLocalActions = workflowOptions.allowLocalActions ?? true;
    const allowDockerActions = workflowOptions.allowDockerActions ?? false;
    if (typeof allowLocalActions !== "boolean" || typeof allowDockerActions !== "boolean") {
      fail("workflow action allow policies must be booleans");
    }
    const fullCommitUse =
      /^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+(?:\/[A-Za-z0-9_./-]+)?@[0-9a-f]{40}$/u;

    for (const workflowFile of readdirSync(workflowDirectory).filter((name) => /\.ya?ml$/u.test(name))) {
      const workflowPath = `${workflowDirectoryPath}/${workflowFile}`;
      const lines = readText(workflowPath).replace(/\r\n/gu, "\n").split("\n");
      for (const [index, line] of lines.entries()) {
        const match = /^\s*(?:-\s+)?uses:\s*(.+?)\s*$/u.exec(line);
        if (match === null) {
          continue;
        }
        const uses = unquoteWorkflowScalar(match[1]);
        if (
          allowedNonShaUses.has(uses)
        ) {
          continue;
        }
        if (uses.startsWith("./")) {
          if (!allowLocalActions) {
            fail(`${workflowPath}:${index + 1} local action ${uses} is not allowed`);
          }
          resolveRepositoryPath(uses.slice(2), "local workflow action");
          continue;
        }
        if (uses.startsWith("docker://")) {
          if (!allowDockerActions) {
            fail(`${workflowPath}:${index + 1} Docker action ${uses} is not allowed`);
          }
          if (!/^docker:\/\/[^@\s]+@sha256:[0-9a-f]{64}$/u.test(uses)) {
            fail(
              `${workflowPath}:${index + 1} Docker action ${uses} is not pinned to a sha256 digest`,
            );
          }
          continue;
        }
        if (!fullCommitUse.test(uses)) {
          fail(`${workflowPath}:${index + 1} action ${uses} is not pinned to a full commit SHA`);
        }
      }
    }
  };

  const extractWorkflowRunCommands = (path) => {
    const lines = readText(path).replace(/\r\n/gu, "\n").split("\n");
    const commands = [];
    for (let index = 0; index < lines.length; index += 1) {
      const runMatch = /^(\s*)(?:-\s+)?run:\s*(.*)\s*$/u.exec(lines[index]);
      if (runMatch === null) {
        continue;
      }
      const runIndent = runMatch[1].length;
      const marker = runMatch[2].trim();
      if (marker === ">") {
        fail(`${path} uses an unsupported folded run scalar`);
      }
      if (marker === "|") {
        const blockLines = [];
        for (let blockCursor = index + 1; blockCursor < lines.length; blockCursor += 1) {
          const blockLine = lines[blockCursor];
          if (blockLine.trim().length !== 0 && countLeadingSpaces(blockLine) <= runIndent) {
            break;
          }
          blockLines.push(blockLine);
        }
        const nonBlankIndents = blockLines
          .filter((line) => line.trim().length !== 0)
          .map((line) => countLeadingSpaces(line));
        const blockIndent =
          nonBlankIndents.length === 0 ? runIndent + 2 : Math.min(...nonBlankIndents);
        commands.push(
          blockLines.map((line) => line.slice(Math.min(blockIndent, line.length))).join("\n"),
        );
      } else {
        commands.push(unquoteWorkflowScalar(marker));
      }
    }
    return commands;
  };

  const assertCargoFuzzWorkflowPolicy = (policy) => {
    const {
      workflow = ".github/workflows/fuzz.yml",
      version,
      gitSource,
      minimumInstallations = 2,
      requiredInstallSteps = [],
    } = policy ?? {};
    if (typeof workflow !== "string" || workflow.length === 0) {
      fail("cargo-fuzz workflow policy requires a workflow path");
    }
    const configuredSources = [
      Object.prototype.hasOwnProperty.call(policy ?? {}, "version"),
      Object.prototype.hasOwnProperty.call(policy ?? {}, "gitSource"),
    ].filter(Boolean).length;
    if (configuredSources !== 1) {
      fail("cargo-fuzz workflow policy requires exactly one exact version or Git revision");
    }
    const hasVersion = Object.prototype.hasOwnProperty.call(policy ?? {}, "version");
    if (hasVersion && (typeof version !== "string" || !/^\d+\.\d+\.\d+$/u.test(version))) {
      fail("cargo-fuzz workflow policy requires an exact semantic version");
    }
    const hasGitSource = Object.prototype.hasOwnProperty.call(policy ?? {}, "gitSource");
    if (
      hasGitSource &&
      (gitSource === null ||
        typeof gitSource !== "object" ||
        Array.isArray(gitSource) ||
        typeof gitSource.url !== "string" ||
        !/^https:\/\/github\.com\/[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+\.git$/u.test(gitSource.url) ||
        typeof gitSource.revision !== "string" ||
        !/^[0-9a-f]{40}$/u.test(gitSource.revision))
    ) {
      fail("cargo-fuzz workflow policy requires an exact GitHub repository URL and revision");
    }
    if (!Number.isSafeInteger(minimumInstallations) || minimumInstallations < 1) {
      fail("cargo-fuzz workflow policy requires a positive installation count");
    }
    if (
      !Array.isArray(requiredInstallSteps) ||
      requiredInstallSteps.some(
        (step) =>
          step === null ||
          typeof step !== "object" ||
          Array.isArray(step) ||
          typeof step.name !== "string" ||
          step.name.length === 0 ||
          (step.job !== undefined &&
            (typeof step.job !== "string" || step.job.length === 0)),
      )
    ) {
      fail("cargo-fuzz required install steps must be named workflow steps");
    }

    const text = readText(workflow).replace(/\r\n/gu, "\n");
    const workflowRuns = extractWorkflowSteps(workflow)
      .filter((step) => step.run !== null)
      .map((step) => ({ ...step, command: normalizeWorkflowRunCommand(step.run) }));
    const allInstallCommands = extractWorkflowRunCommands(workflow).filter(
      (command) =>
        /^cargo\s+install(?:\s|$)/mu.test(normalizeWorkflowRunCommand(command)) &&
        /(?:^|\s)cargo-fuzz(?:\s|$)/u.test(normalizeWorkflowRunCommand(command)),
    );
    const installSteps = workflowRuns.filter((step) =>
      /^cargo\s+install(?:\s|$)/mu.test(step.command) &&
      /(?:^|\s)cargo-fuzz(?:\s|$)/u.test(step.command),
    );
    if (installSteps.length !== allInstallCommands.length) {
      fail(`${workflow} cargo-fuzz installation must be in a named workflow step`);
    }
    if (installSteps.length < minimumInstallations) {
      fail(
        `${workflow} must install cargo-fuzz at least ${minimumInstallations} times`,
      );
    }
    const environmentVersion = hasVersion
      ? new RegExp(
          `^\\s*CARGO_FUZZ_VERSION:\\s*["']?${version.replaceAll(".", "\\.")}["']?\\s*$`,
          "mu",
        )
      : null;
    for (const expected of requiredInstallSteps) {
      const matches = installSteps.filter(
        (step) =>
          step.name === expected.name &&
          (expected.job === undefined || step.job === expected.job),
      );
      if (matches.length === 0) {
        const location =
          expected.job === undefined
            ? expected.name
            : `${expected.job}/${expected.name}`;
        fail(`${workflow} is missing cargo-fuzz install step ${location}`);
      }
      if (matches.length > 1) {
        const location =
          expected.job === undefined
            ? expected.name
            : `${expected.job}/${expected.name}`;
        fail(`${workflow} defines cargo-fuzz install step ${location} more than once`);
      }
    }
    for (const step of installSteps) {
      const command = normalizeWorkflowRunCommand(step.run);
      if (!/(?:^|\s)--locked(?:\s|$)/u.test(command)) {
        fail(`${workflow} cargo-fuzz installation must use --locked`);
      }
      if (hasGitSource) {
        const expected =
          `cargo install --git ${gitSource.url} --rev ${gitSource.revision} --locked cargo-fuzz`;
        if (command !== expected) {
          fail(`${workflow} cargo-fuzz installation must use the configured exact Git revision`);
        }
        continue;
      }
      const usesLiteralVersion = new RegExp(
        `(?:^|\\s)--version\\s+${version.replaceAll(".", "\\.")}(?:\\s|$)`,
        "u",
      ).test(command);
      const usesEnvironmentVersion =
        command.includes('--version "$CARGO_FUZZ_VERSION"') ||
        command.includes("--version '$CARGO_FUZZ_VERSION'") ||
        command.includes("--version $CARGO_FUZZ_VERSION");
      if (
        !usesLiteralVersion &&
        !(usesEnvironmentVersion && environmentVersion !== null && environmentVersion.test(text))
      ) {
        fail(
          `${workflow} cargo-fuzz installation must pin version ${version}`,
        );
      }
    }
  };

  const assertReallyMeRustProtoRepositoryPolicy = (policy) => {
    if (policy === null || typeof policy !== "object" || Array.isArray(policy)) {
      fail("ReallyMe Rust protobuf repository policy must be an object");
    }
    const {
      generatedFreshnessMode,
      vendoredCore = {},
      workflowActions = {},
      nodeWorkflows = {},
      cargoFuzz,
      cargoWorkspace = {},
      spdx = {},
      protobufBoundary,
      protobufRelease,
      cargoMetadata,
      text,
      workflows = [],
    } = policy;
    if (typeof generatedFreshnessMode !== "boolean") {
      fail("ReallyMe Rust protobuf repository policy requires generatedFreshnessMode");
    }
    for (const [name, value] of [
      ["vendoredCore", vendoredCore],
      ["workflowActions", workflowActions],
      ["nodeWorkflows", nodeWorkflows],
      ["cargoFuzz", cargoFuzz],
      ["cargoWorkspace", cargoWorkspace],
      ["spdx", spdx],
      ["protobufBoundary", protobufBoundary],
      ["protobufRelease", protobufRelease],
    ]) {
      if (value === null || typeof value !== "object" || Array.isArray(value)) {
        fail(`ReallyMe Rust protobuf repository policy ${name} must be an object`);
      }
    }
    if (
      cargoMetadata !== undefined &&
      (cargoMetadata === null ||
        typeof cargoMetadata !== "object" ||
        Array.isArray(cargoMetadata))
    ) {
      fail("ReallyMe Rust protobuf repository policy cargoMetadata must be an object");
    }
    if (
      text !== undefined &&
      (text === null || typeof text !== "object" || Array.isArray(text))
    ) {
      fail("ReallyMe Rust protobuf repository policy text must be an object");
    }
    if (
      !Array.isArray(workflows) ||
      workflows.some(
        (workflow) =>
          workflow === null ||
          typeof workflow !== "object" ||
          Array.isArray(workflow),
      )
    ) {
      fail("ReallyMe Rust protobuf repository workflows must be an array of objects");
    }
    if (
      Object.prototype.hasOwnProperty.call(
        protobufRelease,
        "generatedFreshnessMode",
      )
    ) {
      fail(
        "generatedFreshnessMode must be configured once at the repository-policy level",
      );
    }

    assertReallyMeVendoredCorePolicy(vendoredCore);
    assertWorkflowActionsPinned(workflowActions);
    assertNodeWorkflowJobsPinNode(nodeWorkflows);
    assertCargoFuzzWorkflowPolicy(cargoFuzz);
    assertCargoWorkspacePolicy(cargoWorkspace);
    assertSpdxHeaders(spdx);
    assertReallyMeOperationBoundaryContract(protobufBoundary);
    assertReallyMeProtobufReleasePolicy({
      ...protobufRelease,
      generatedFreshnessMode,
    });
    if (cargoMetadata !== undefined) {
      assertCargoMetadataPolicy(cargoMetadata);
    }
    if (text !== undefined) {
      assertTextPolicy(text);
    }
    for (const workflow of workflows) {
      assertWorkflowPolicy(workflow);
    }
  };

  const stripProtoLineComments = (text) =>
    text
      .split("\n")
      .map((line) => {
        const commentStart = line.indexOf("//");
        return commentStart === -1 ? line : line.slice(0, commentStart);
      })
      .join("\n");

  const extractProtoBlocks = (protoText, keyword) => {
    const blocks = [];
    const declarationPattern = new RegExp(`\\b${keyword}\\s+([A-Za-z_][A-Za-z0-9_]*)\\s*\\{`, "g");
    let match = declarationPattern.exec(protoText);
    while (match !== null) {
      let depth = 1;
      let cursor = declarationPattern.lastIndex;
      while (cursor < protoText.length && depth > 0) {
        const char = protoText[cursor];
        if (char === "{") {
          depth += 1;
        } else if (char === "}") {
          depth -= 1;
        }
        cursor += 1;
      }
      if (depth !== 0) {
        fail(`proto ${keyword} ${match[1]} has unbalanced braces`);
      }
      blocks.push({
        name: match[1],
        body: protoText.slice(declarationPattern.lastIndex, cursor - 1),
      });
      declarationPattern.lastIndex = cursor;
      match = declarationPattern.exec(protoText);
    }
    return blocks;
  };

  const parseProtoReservations = (path, ownerKind, ownerName, body) => {
    const numberRanges = [];
    const names = new Set();
    for (const declaration of body.matchAll(/\breserved\s+([^;]+);/gu)) {
      for (const rawEntry of declaration[1].split(",")) {
        const entry = rawEntry.trim();
        const nameMatch = /^"([A-Za-z_][A-Za-z0-9_]*)"$/u.exec(entry);
        if (nameMatch !== null) {
          if (names.has(nameMatch[1])) {
            fail(`${path} ${ownerKind} ${ownerName} reserves name ${nameMatch[1]} more than once`);
          }
          names.add(nameMatch[1]);
          continue;
        }
        const rangeMatch = /^(-?\d+)(?:\s+to\s+(-?\d+|max))?$/u.exec(entry);
        if (rangeMatch === null) {
          fail(`${path} ${ownerKind} ${ownerName} has unsupported reservation ${entry}`);
        }
        const start = Number.parseInt(rangeMatch[1], 10);
        const end =
          rangeMatch[2] === undefined
            ? start
            : rangeMatch[2] === "max"
              ? ownerKind === "message"
                ? 536_870_911
                : 2_147_483_647
              : Number.parseInt(rangeMatch[2], 10);
        if (!Number.isSafeInteger(start) || !Number.isSafeInteger(end) || start > end) {
          fail(`${path} ${ownerKind} ${ownerName} has invalid reservation ${entry}`);
        }
        if (
          numberRanges.some(
            ([existingStart, existingEnd]) =>
              start <= existingEnd && end >= existingStart,
          )
        ) {
          fail(`${path} ${ownerKind} ${ownerName} has overlapping reserved number ranges`);
        }
        numberRanges.push([start, end]);
      }
    }
    return { numberRanges, names };
  };

  const isReservedProtoNumber = (number, reservations) =>
    reservations.numberRanges.some(([start, end]) => number >= start && number <= end);

  const assertProtoContract = (path) => {
    const proto = stripProtoLineComments(readText(path));

    for (const block of extractProtoBlocks(proto, "enum")) {
      const reservations = parseProtoReservations(path, "enum", block.name, block.body);
      const names = new Set();
      const numbers = new Set();
      const values = [
        ...block.body.matchAll(
          /^\s*([A-Z][A-Z0-9_]*)\s*=\s*(-?\d+)\s*(?:\[[^\]]*\])?\s*;/gmu,
        ),
      ].map((match) => ({
        name: match[1],
        number: Number.parseInt(match[2], 10),
      }));
      if (values.length === 0) {
        fail(`${path} enum ${block.name} must define at least one value`);
      }
      if (values[0].number !== 0 || !values[0].name.endsWith("_UNSPECIFIED")) {
        fail(`${path} enum ${block.name} must start with an UNSPECIFIED value at zero`);
      }
      for (const value of values) {
        if (
          !Number.isSafeInteger(value.number) ||
          value.number < -2_147_483_648 ||
          value.number > 2_147_483_647
        ) {
          fail(`${path} enum ${block.name} value ${value.name} is outside int32 range`);
        }
        if (names.has(value.name)) {
          fail(`${path} enum ${block.name} defines name ${value.name} more than once`);
        }
        if (numbers.has(value.number)) {
          fail(`${path} enum ${block.name} reuses number ${value.number}`);
        }
        if (reservations.names.has(value.name)) {
          fail(`${path} enum ${block.name} reuses reserved name ${value.name}`);
        }
        if (isReservedProtoNumber(value.number, reservations)) {
          fail(`${path} enum ${block.name} reuses reserved number ${value.number}`);
        }
        names.add(value.name);
        numbers.add(value.number);
      }
    }

    for (const block of extractProtoBlocks(proto, "message")) {
      const reservations = parseProtoReservations(path, "message", block.name, block.body);
      const names = new Set();
      const numbers = new Set();
      const fields = [
        ...block.body.matchAll(
          /^\s*(?:optional\s+|repeated\s+)?(?:map\s*<[^>]+>|[A-Za-z_][A-Za-z0-9_.]*)\s+([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(\d+)\s*(?:\[[^\]]*\])?\s*;/gmu,
        ),
      ].map((match) => ({
        name: match[1],
        number: Number.parseInt(match[2], 10),
      }));
      for (const field of fields) {
        if (
          !Number.isSafeInteger(field.number) ||
          field.number < 1 ||
          field.number > 536_870_911 ||
          (field.number >= 19_000 && field.number <= 19_999)
        ) {
          fail(`${path} message ${block.name} field ${field.name} has invalid number ${field.number}`);
        }
        if (names.has(field.name)) {
          fail(`${path} message ${block.name} defines field ${field.name} more than once`);
        }
        if (numbers.has(field.number)) {
          fail(`${path} message ${block.name} reuses field number ${field.number}`);
        }
        if (reservations.names.has(field.name)) {
          fail(`${path} message ${block.name} reuses reserved name ${field.name}`);
        }
        if (isReservedProtoNumber(field.number, reservations)) {
          fail(`${path} message ${block.name} reuses reserved field number ${field.number}`);
        }
        names.add(field.name);
        numbers.add(field.number);
      }
    }
  };

  const assertReallyMeProtoBoundaryContract = (policy) => {
    const {
      protoPath,
      operationRequest,
      resultEnvelope,
      resultStatus,
      payloadField = "payload",
      protoReadme,
      protoCargo,
      wirePath,
      codecPath = wirePath,
      bufGen = "buf.gen.yaml",
      processProtoNeedle = "pub fn process_proto(",
      processProtoJsonNeedle = "pub fn process_proto_json(",
      binaryEnvelopeNeedle = "encode_proto_result_envelope",
      requiredCodecNeedles = [],
      forbiddenCodecNeedles = [],
      sdkAdapters = [],
    } = policy ?? {};
    for (const [name, value] of Object.entries({
      protoPath,
      protoReadme,
      protoCargo,
      wirePath,
      codecPath,
    })) {
      if (typeof value !== "string" || value.length === 0) {
        fail(`protobuf boundary policy ${name} must be a non-empty string`);
      }
    }
    if (
      !Array.isArray(requiredCodecNeedles) ||
      requiredCodecNeedles.some((needle) => typeof needle !== "string" || needle.length === 0) ||
      !Array.isArray(forbiddenCodecNeedles) ||
      forbiddenCodecNeedles.some((needle) => typeof needle !== "string" || needle.length === 0)
    ) {
      fail("protobuf boundary codec needles must be arrays of non-empty strings");
    }
    if (
      !Array.isArray(sdkAdapters) ||
      sdkAdapters.some(
        (adapter) =>
          adapter === null ||
          typeof adapter !== "object" ||
          Array.isArray(adapter),
      )
    ) {
      fail("protobuf boundary policy sdkAdapters must be an array of objects");
    }
    for (const [name, value] of Object.entries({
      operationRequest,
      resultEnvelope,
      resultStatus,
    })) {
      if (
        typeof value !== "string" ||
        !/^[A-Za-z_][A-Za-z0-9_]*$/u.test(value)
      ) {
        fail(`protobuf boundary policy ${name} must be a protobuf identifier`);
      }
    }

    assertProtoContract(protoPath);
    const proto = stripProtoLineComments(readText(protoPath));
    if (extractProtoBlocks(proto, "service").length !== 0) {
      fail(`${protoPath} must define messages only and no protobuf service`);
    }
    const operationBlock = extractProtoBlocks(proto, "message").find(
      (block) => block.name === operationRequest,
    );
    if (operationBlock === undefined || !/\boneof\s+operation\s*\{/u.test(operationBlock.body)) {
      fail(`${protoPath} ${operationRequest} must define oneof operation`);
    }
    const envelopeBlock = extractProtoBlocks(proto, "message").find(
      (block) => block.name === resultEnvelope,
    );
    if (envelopeBlock === undefined) {
      fail(`${protoPath} must define message ${resultEnvelope}`);
    }
    if (
      !new RegExp(`^\\s*${resultStatus}\\s+status\\s*=\\s*1\\s*;`, "mu").test(
        envelopeBlock.body,
      ) ||
      !new RegExp(`^\\s*bytes\\s+${payloadField}\\s*=\\s*2\\s*;`, "mu").test(
        envelopeBlock.body,
      )
    ) {
      fail(
        `${protoPath} ${resultEnvelope} must contain status = 1 and bytes ${payloadField} = 2`,
      );
    }
    if (
      !extractProtoBlocks(proto, "enum").some((block) => block.name === resultStatus)
    ) {
      fail(`${protoPath} must define enum ${resultStatus}`);
    }

    assertContains(
      protoReadme,
      "This crate defines messages only; it intentionally declares no protobuf service.",
    );
    assertContains(
      protoReadme,
      "JSON is a generated ProtoJSON request convenience. Results remain a binary protobuf result envelope.",
    );
    assertContains(bufGen, "local: protoc-gen-buffa");
    assertContains(bufGen, "views=true");
    assertContains(bufGen, "json=true");
    assertContains(protoCargo, '"buffa/json"');
    assertContains(protoCargo, "zeroize");
    assertContains(wirePath, operationRequest);
    assertContains(wirePath, resultEnvelope);
    assertContains(wirePath, "Zeroizing<Vec<u8>>");
    assertContains(wirePath, processProtoNeedle);
    assertContains(wirePath, processProtoJsonNeedle);
    assertContains(codecPath, "DecodeOptions::new()");
    assertContains(codecPath, binaryEnvelopeNeedle);
    for (const needle of requiredCodecNeedles) {
      assertContains(codecPath, needle);
    }
    for (const needle of forbiddenCodecNeedles) {
      assertNotContains(codecPath, needle);
    }
    assertNotContains(wirePath, "pub fn process_json(");
    assertNotContains(wirePath, "pub fn process_proto_with_operation");
    assertNotContains(wirePath, "pub fn process_proto_operation");

    for (const [index, adapter] of sdkAdapters.entries()) {
      const {
        path,
        processProtoNeedle: adapterProcessProtoNeedle,
        processProtoJsonNeedle: adapterProcessProtoJsonNeedle,
        binaryEnvelopeNeedle: adapterBinaryEnvelopeNeedle = resultEnvelope,
        requiredNeedles = [],
        forbiddenNeedles = [],
      } = adapter;
      for (const [name, value] of Object.entries({
        path,
        processProtoNeedle: adapterProcessProtoNeedle,
        processProtoJsonNeedle: adapterProcessProtoJsonNeedle,
        binaryEnvelopeNeedle: adapterBinaryEnvelopeNeedle,
      })) {
        if (typeof value !== "string" || value.length === 0) {
          fail(
            `protobuf boundary sdkAdapters[${index}].${name} must be a non-empty string`,
          );
        }
      }
      for (const [name, needles] of Object.entries({
        requiredNeedles,
        forbiddenNeedles,
      })) {
        if (
          !Array.isArray(needles) ||
          needles.some(
            (needle) => typeof needle !== "string" || needle.length === 0,
          )
        ) {
          fail(
            `protobuf boundary sdkAdapters[${index}].${name} must be an array of non-empty strings`,
          );
        }
      }
      assertContains(path, adapterProcessProtoNeedle);
      assertContains(path, adapterProcessProtoJsonNeedle);
      assertContains(path, adapterBinaryEnvelopeNeedle);
      for (const needle of requiredNeedles) {
        assertContains(path, needle);
      }
      for (const needle of forbiddenNeedles) {
        assertNotContains(path, needle);
      }
    }
  };

  const assertReallyMeOperationBoundaryContract = (policy) => {
    const {
      protoPath,
      operationRequest,
      operationResponse,
      operationResult = "CodecOperationResult",
      errorMessage = "CodecError",
      protoReadme,
      protoCargo,
      wirePath,
      codecPath = wirePath,
      bufGen = "buf.gen.yaml",
      processOperationNeedle = "pub fn process_operation_response(",
      processOperationJsonNeedle = "pub fn process_operation_response_json(",
      binaryResponseNeedle = "CodecOperationResponse",
      requiredCodecNeedles = [],
      forbiddenCodecNeedles = [],
      sdkAdapters = [],
      allowServices = true,
    } = policy ?? {};
    for (const [name, value] of Object.entries({
      protoPath,
      protoReadme,
      protoCargo,
      wirePath,
      codecPath,
    })) {
      if (typeof value !== "string" || value.length === 0) {
        fail(`operation boundary policy ${name} must be a non-empty string`);
      }
    }
    if (
      !Array.isArray(requiredCodecNeedles) ||
      requiredCodecNeedles.some((needle) => typeof needle !== "string" || needle.length === 0) ||
      !Array.isArray(forbiddenCodecNeedles) ||
      forbiddenCodecNeedles.some((needle) => typeof needle !== "string" || needle.length === 0)
    ) {
      fail("operation boundary codec needles must be arrays of non-empty strings");
    }
    if (
      !Array.isArray(sdkAdapters) ||
      sdkAdapters.some(
        (adapter) =>
          adapter === null ||
          typeof adapter !== "object" ||
          Array.isArray(adapter),
      )
    ) {
      fail("operation boundary policy sdkAdapters must be an array of objects");
    }
    if (typeof allowServices !== "boolean") {
      fail("operation boundary policy allowServices must be a boolean");
    }
    for (const [name, value] of Object.entries({
      operationRequest,
      operationResponse,
      operationResult,
      errorMessage,
    })) {
      if (
        typeof value !== "string" ||
        !/^[A-Za-z_][A-Za-z0-9_]*$/u.test(value)
      ) {
        fail(`operation boundary policy ${name} must be a protobuf identifier`);
      }
    }

    assertProtoContract(protoPath);
    const proto = stripProtoLineComments(readText(protoPath));
    if (!allowServices && extractProtoBlocks(proto, "service").length !== 0) {
      fail(`${protoPath} must define messages only and no protobuf service`);
    }
    const operationBlock = extractProtoBlocks(proto, "message").find(
      (block) => block.name === operationRequest,
    );
    if (operationBlock === undefined || !/\boneof\s+operation\s*\{/u.test(operationBlock.body)) {
      fail(`${protoPath} ${operationRequest} must define oneof operation`);
    }
    const responseBlock = extractProtoBlocks(proto, "message").find(
      (block) => block.name === operationResponse,
    );
    if (
      responseBlock === undefined ||
      !/\boneof\s+outcome\s*\{/u.test(responseBlock.body) ||
      !new RegExp(`^\\s*${operationResult}\\s+result\\s*=\\s*1\\s*;`, "mu").test(
        responseBlock.body,
      ) ||
      !new RegExp(`^\\s*${errorMessage}\\s+error\\s*=\\s*2\\s*;`, "mu").test(
        responseBlock.body,
      )
    ) {
      fail(`${protoPath} ${operationResponse} must contain a generated result/error outcome oneof`);
    }
    const resultBlock = extractProtoBlocks(proto, "message").find(
      (block) => block.name === operationResult,
    );
    if (resultBlock === undefined || !/\boneof\s+result\s*\{/u.test(resultBlock.body)) {
      fail(`${protoPath} ${operationResult} must define oneof result`);
    }

    assertContains(
      protoReadme,
      "JSON is a generated ProtoJSON request convenience. Results remain one fully",
    );
    assertContains(bufGen, "local: protoc-gen-buffa");
    assertContains(bufGen, "views=true");
    assertContains(bufGen, "json=true");
    assertContains(protoCargo, '"buffa/json"');
    assertContains(protoCargo, "zeroize");
    assertContains(wirePath, operationRequest);
    assertContains(wirePath, operationResponse);
    assertContains(wirePath, "Zeroizing<Vec<u8>>");
    assertContains(wirePath, processOperationNeedle);
    assertContains(wirePath, processOperationJsonNeedle);
    assertContains(codecPath, "DecodeOptions::new()");
    assertContains(codecPath, binaryResponseNeedle);
    for (const needle of requiredCodecNeedles) {
      assertContains(codecPath, needle);
    }
    for (const needle of forbiddenCodecNeedles) {
      assertNotContains(codecPath, needle);
    }
    assertNotContains(wirePath, "pub fn process_json(");
    assertNotContains(wirePath, "pub fn process_proto_with_operation");
    assertNotContains(wirePath, "pub fn process_proto_operation");
    assertNotContains(wirePath, "CodecProtoResultEnvelope");

    for (const [index, adapter] of sdkAdapters.entries()) {
      const {
        path,
        processOperationNeedle: adapterProcessOperationNeedle,
        processOperationJsonNeedle: adapterProcessOperationJsonNeedle,
        binaryResponseNeedle: adapterBinaryResponseNeedle = operationResponse,
        requiredNeedles = [],
        forbiddenNeedles = [],
      } = adapter;
      for (const [name, value] of Object.entries({
        path,
        processOperationNeedle: adapterProcessOperationNeedle,
        processOperationJsonNeedle: adapterProcessOperationJsonNeedle,
        binaryResponseNeedle: adapterBinaryResponseNeedle,
      })) {
        if (typeof value !== "string" || value.length === 0) {
          fail(
            `operation boundary sdkAdapters[${index}].${name} must be a non-empty string`,
          );
        }
      }
      for (const [name, needles] of Object.entries({
        requiredNeedles,
        forbiddenNeedles,
      })) {
        if (
          !Array.isArray(needles) ||
          needles.some(
            (needle) => typeof needle !== "string" || needle.length === 0,
          )
        ) {
          fail(
            `operation boundary sdkAdapters[${index}].${name} must be an array of non-empty strings`,
          );
        }
      }
      assertContains(path, adapterProcessOperationNeedle);
      assertContains(path, adapterProcessOperationJsonNeedle);
      assertContains(path, adapterBinaryResponseNeedle);
      for (const needle of requiredNeedles) {
        assertContains(path, needle);
      }
      for (const needle of forbiddenNeedles) {
        assertNotContains(path, needle);
      }
    }
  };

  return {
    root,
    fail,
    readText,
    readJson,
    listFiles,
    requireTracked,
    loadTrackedFiles,
    assertContains,
    assertNotContains,
    assertMinOccurrences,
    assertTextPolicy,
    requireMatch,
    assertNotMatches,
    assertLockPackageVersion,
    run,
    runCommands,
    runNodeCheck,
    packageList,
    assertPackageFiles,
    assertCargoMetadataDocument,
    assertCargoMetadataPolicy,
    assertCargoWorkspacePolicy,
    snapshotDirectory,
    assertSnapshotsEqual,
    validateGeneratedArtifactsPolicy,
    assertGeneratedArtifactsFresh,
    assertGeneratedProtoHardeningPolicy,
    assertReallyMeProtobufReleasePolicy,
    assertReallyMeVendoredCorePolicy,
    assertNodeWorkflowJobsPinNode,
    assertWorkflowActionsPinned,
    assertWorkflowPermissionsPolicy,
    assertCargoFuzzWorkflowPolicy,
    assertReallyMeRustProtoRepositoryPolicy,
    normalizeWorkflowRunCommand,
    extractWorkflowSteps,
    assertWorkflowRunStep,
    assertWorkflowUsesStep,
    assertWorkflowPolicy,
    stripProtoLineComments,
    extractProtoBlocks,
    assertProtoContract,
    assertReallyMeProtoBoundaryContract,
    assertReallyMeOperationBoundaryContract,
    assertSpdxHeaders,
  };
}
