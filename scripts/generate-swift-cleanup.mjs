// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

import { schemaMessages } from "./read-proto-schema.mjs";

const directory = "packages/swift/Sources/ReallyMeJOSE/";
const camel = (value) => value.toLowerCase().replace(/_([a-z0-9])/gu, (_match, letter) => letter.toUpperCase());
const title = (value) => value[0].toUpperCase() + value.slice(1);

function moduleFor(name) {
  if (name === "JoseOperationRequest" || name === "JoseOperationResponse") return "ClearOperationMemory.swift";
  if (name.startsWith("JoseJws")) return "ClearJwsMemory.swift";
  if (name.startsWith("JoseJwt")) return "ClearJwtMemory.swift";
  if (name.startsWith("JoseJwe")) return "ClearJweMemory.swift";
  return "ContractMemory.swift";
}

export function swiftCleanup(schema, header) {
  const messages = schemaMessages(schema);
  // References cross the output modules. Resolve message ownership against the
  // whole schema so moving an overload never removes a nested cleanup call.
  const messageNames = new Set(messages.map(({ name }) => name));
  const modules = new Map([
    ["ContractMemory.swift", []],
    ["ClearOperationMemory.swift", []],
    ["ClearJwsMemory.swift", []],
    ["ClearJwtMemory.swift", []],
    ["ClearJweMemory.swift", []],
  ]);
  for (const { name, body } of messages) {
    const oneof = /oneof\s+(\w+)\s*\{([\s\S]*?)\}/u.exec(body);
    const ordinary = oneof === null ? body : body.replace(oneof[0], "");
    const statements = [];
    for (const [, cardinality, type, field] of ordinary.matchAll(/^\s*(?:(optional|repeated)\s+)?(\w+)\s+(\w+)\s*=/gmu)) {
      const property = camel(field);
      if (type === "bytes") statements.push(`  ReallyMeJOSEMemory.clearOwned(&message.${property})`);
      if (messageNames.has(type)) {
        if (cardinality === "repeated") statements.push(`  for index in message.${property}.indices { clearSensitiveFields(&message.${property}[index]) }`);
        else {
          const statement = `  if message.has${title(property)} { clearSensitiveFields(&message.${property}) }`;
          statements.push(statement.length <= 100 ? statement : `  if message.has${title(property)} {\n    clearSensitiveFields(&message.${property})\n  }`);
        }
      }
    }
    if (oneof !== null) {
      statements.push(`  switch message.${camel(oneof[1])} {`);
      for (const [, type, field] of oneof[2].matchAll(/^\s*(\w+)\s+(\w+)\s*=/gmu)) {
        statements.push(`  case .${camel(field)}: ${messageNames.has(type) ? `clearSensitiveFields(&message.${camel(field)})` : "break"}`);
      }
      statements.push("  case nil: break", "  }");
    }
    statements.push(`  message = ReallyMeProto${name}()`);
    modules.get(moduleFor(name)).push(`func clearSensitiveFields(_ message: inout ReallyMeProto${name}) {\n${statements.join("\n")}\n}\n`);
  }
  return new Map([...modules].map(([name, functions]) => [
    directory + name,
    header + "import ReallyMeJOSEProto\n\n" + functions.join("\n"),
  ]));
}
