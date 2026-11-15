#!/usr/bin/env node
// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

import { readFileSync, readdirSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { schemaMessages } from "./read-proto-schema.mjs";

const root = new URL("..", import.meta.url);
// URL pathnames retain a leading slash before Windows drive letters. Convert
// through Node's platform-aware boundary before composing filesystem paths.
const rootPath = fileURLToPath(root);
const javaDirectory = join(rootPath, "gen/java/me/really/jose/v1");
const kotlinDirectory = join(rootPath, "gen/kotlin/me/really/jose/v1");
const supportedArguments = new Set(["--check-idempotent"]);
const argumentsSeen = new Set();
const schema = schemaMessages(readFileSync(join(rootPath, "crates/proto/proto/reallyme/jose/v1/jose.proto"), "utf8"));
const schemaByName = new Map(schema.map((message) => [message.name, message]));
const hardenedMessages = new Set();

function fail(message) {
  console.error(`generated JOSE JVM hardening failed: ${message}`);
  process.exit(1);
}

for (const argument of process.argv.slice(2)) {
  if (!supportedArguments.has(argument) || argumentsSeen.has(argument)) {
    fail(`unsupported or duplicate argument ${argument}`);
  }
  argumentsSeen.add(argument);
}

function generatedPaths() {
  return [
    ...readdirSync(javaDirectory)
      .filter((name) => name.endsWith(".java"))
      .map((name) => join(javaDirectory, name)),
    ...readdirSync(kotlinDirectory)
      .filter((name) => name.endsWith(".kt"))
      .map((name) => join(kotlinDirectory, name)),
  ];
}

const before = argumentsSeen.has("--check-idempotent")
  ? new Map(generatedPaths().map((path) => [path, readFileSync(path)]))
  : null;

for (const path of generatedPaths()) {
  let source = readFileSync(path, "utf8");
  if (path.endsWith(".java")) {
    const messageClassCount = [...source.matchAll(
      /\bclass\s+[A-Z][A-Za-z0-9]*\s+extends\s+com\.google\.protobuf\.GeneratedMessageLite\s*</gu,
    )].length;
    // The redaction below is per file. Reject a generator change that adds
    // nested messages until every generated message gets its own redaction.
    if (messageClassCount > 1) {
      fail(`nested generated messages require individual hardening in ${path}`);
    }
    const declaration = /public\s+final\s+class\s+([A-Z][A-Za-z0-9]*)\s+extends/u.exec(source);
    if ((declaration === null) !== (messageClassCount === 0)) {
      fail(`generated message declaration mismatch in ${path}`);
    }
    if (declaration !== null) {
      const messageName = declaration[1];
      const message = schemaByName.get(messageName);
      if (message === undefined || hardenedMessages.has(messageName)) fail("generated JVM message differs from schema inventory");
      hardenedMessages.add(messageName);
      const title = (value) => value.split("_").map((part) => part[0].toUpperCase() + part.slice(1)).join("");
      const nested = [...message.body.matchAll(/^\s*(?:(optional|repeated)\s+)?(\w+)\s+(\w+)\s*=/gmu)]
        .filter(([, , type]) => schemaByName.has(type))
        .map(([, cardinality, , field]) => cardinality === "repeated"
          ? `get${title(field)}List().stream().anyMatch(value -> value.reallyMeHasUnknownFieldsForValidation())`
          : `(has${title(field)}() && get${title(field)}().reallyMeHasUnknownFieldsForValidation())`);
      const predicate = `  public boolean reallyMeHasUnknownFieldsForValidation() {\n` +
        `    return unknownFields != com.google.protobuf.UnknownFieldSetLite.getDefaultInstance()` +
        nested.map((check) => `\n        || ${check}`).join("") + `;\n  }`;
      const constructor = `  private ${messageName}()`;
      const constructorIndex = source.indexOf(constructor);
      if (constructorIndex < 0) {
        fail(`unable to locate constructor for ${messageName}`);
      }
      if (!source.includes("reallyMeHasUnknownFieldsForValidation")) {
        const hardening = `  // Security post-processing: generated Lite messages otherwise expose\n` +
          `  // neither unknown-field presence nor a safe redacted debug representation.\n` +
          `${predicate}\n\n` +
          `  @java.lang.Override\n` +
          `  public java.lang.String toString() {\n` +
          `    return \"${messageName}{<redacted>}\";\n` +
          `  }\n\n` +
          `  @java.lang.Override\n` +
          `  public int hashCode() {\n` +
          `    return 0x524d;\n` +
          `  }\n\n`;
        source = `${source.slice(0, constructorIndex)}${hardening}${source.slice(constructorIndex)}`;
      }
      source = source.replace(/  public boolean reallyMeHasUnknownFieldsForValidation\(\) \{[\s\S]*?\n  \}/u, predicate);
      const predicateCount = source.split("public boolean reallyMeHasUnknownFieldsForValidation()").length - 1;
      const redactionCount = source.split(`${messageName}{<redacted>}`).length - 1;
      if (predicateCount !== 1 || redactionCount !== 1) {
        fail(`invalid hardening count for ${messageName}`);
      }
    }
  }
  source = source.replace(/[ \t]+$/gmu, "").replace(/\n+$/u, "\n");
  writeFileSync(path, source);
}
if (hardenedMessages.size !== schemaByName.size) fail("schema JVM message is missing from generation");

if (before !== null) {
  for (const [path, expected] of before) {
    if (!expected.equals(readFileSync(path))) {
      fail("generated JVM hardening is not idempotent");
    }
  }
}
