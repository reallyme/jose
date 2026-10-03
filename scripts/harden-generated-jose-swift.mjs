#!/usr/bin/env node
// SPDX-FileCopyrightText: 2026 ReallyMe LLC
//
// SPDX-License-Identifier: MIT OR Apache-2.0

import { readFileSync, writeFileSync } from "node:fs";
import { fileURLToPath } from "node:url";

const path = fileURLToPath(new URL("../gen/swift/reallyme/jose/v1/jose.pb.swift", import.meta.url));
const marker = "// Generated JOSE message reflection redaction.";
const checkIdempotent = process.argv.length === 3 && process.argv[2] === "--check-idempotent";
if (process.argv.length > 3 || (process.argv.length === 3 && !checkIdempotent)) {
  throw new Error("unsupported Swift hardening argument");
}

const before = readFileSync(path, "utf8");
const names = [...before.matchAll(/^public nonisolated struct (ReallyMeProtoJose[A-Za-z0-9_]+): Sendable \{$/gmu)]
  .map((match) => match[1]);
if (names.length < 30 || new Set(names).size !== names.length) {
  throw new Error("generated Swift message inventory changed unexpectedly");
}

// SwiftProtobuf's default debugDescription serializes fields, while dump()
// reflects stored properties. Keep those incidental diagnostics redacted for
// every message. Explicit JSON/text serialization still belongs to callers.
const hardening = `${marker}\n${names.map((name) =>
  `nonisolated extension ${name}: Swift.CustomReflectable {\n` +
  `  public var debugDescription: String { "${name}(<redacted>)" }\n` +
  `  public var customMirror: Mirror {\n` +
  `    Mirror(self, children: [("value", "<redacted>")])\n` +
  `  }\n` +
  `}\n`,
).join("\n")}`;
const markerIndex = before.indexOf(marker);
const generated = markerIndex < 0 ? before.trimEnd() : before.slice(0, markerIndex).trimEnd();
const after = `${generated}\n\n${hardening}`;
if (checkIdempotent && before !== after) {
  throw new Error("generated Swift hardening is not idempotent");
}
if (!checkIdempotent) {
  writeFileSync(path, after);
}
