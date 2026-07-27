#!/usr/bin/env node
// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

import { readFileSync, writeFileSync } from "node:fs";
import { resolve } from "node:path";
import { fileURLToPath } from "node:url";

const root = resolve(fileURLToPath(new URL("..", import.meta.url)));
const protoPath = resolve(
  root,
  "crates/proto/proto/reallyme/jose/v1/jose.proto",
);
const generatedPath = resolve(
  root,
  "crates/proto/src/generated/buffa/reallyme.jose.v1.jose.rs",
);
const generatedViewPath = resolve(
  root,
  "crates/proto/src/generated/buffa/reallyme.jose.v1.jose.__view.rs",
);
const generatedModulePath = resolve(
  root,
  "crates/proto/src/generated/buffa/mod.rs",
);
const supportedArguments = new Set(["--check-idempotent"]);
const suppliedArguments = new Set();

const sensitiveStringFieldNames = new Map([
  ["JoseCompactResult", ["compact"]],
  ["JoseJwsVerifyRequest", ["compact"]],
  ["JoseJwtDecodeUnsignedRequest", ["compact"]],
  ["JoseJwtSignRequest", ["typ"]],
  ["JoseJwtVerifyRequest", ["compact"]],
  [
    "JoseJwtTemporalValidationPolicy",
    ["expected_audience", "expected_issuer", "expected_subject"],
  ],
  ["JoseJweEncryptRequest", ["kid", "typ", "cty"]],
  ["JoseJweDecryptRequest", ["compact"]],
  ["JoseExpectedString", ["value"]],
]);
const sensitiveOneofOwnerNames = [
  "JoseOperationRequest",
  "JoseOperationResponse",
  "JoseJwsSignResponse",
  "JoseJwsVerifyResponse",
  "JoseJwtEncodeUnsignedResponse",
  "JoseJwtDecodeUnsignedResponse",
  "JoseJwtSignResponse",
  "JoseJwtVerifyResponse",
  "JoseJweEncryptResponse",
  "JoseJweDecryptResponse",
];
const byteFieldNames = new Map();
let currentMessage = null;
let currentFields = [];
let depth = 0;
for (const line of readFileSync(protoPath, "utf8").split("\n")) {
  const message = line.match(/^\s*message\s+(\w+)\s*\{/u);
  if (message && currentMessage === null) {
    currentMessage = message[1];
    currentFields = [];
    depth = (line.match(/\{/gu) ?? []).length - (line.match(/\}/gu) ?? []).length;
    if (depth === 0) {
      currentMessage = null;
    }
    continue;
  }

  if (currentMessage === null) {
    continue;
  }

  const field = line.match(/^\s*bytes\s+(\w+)\s*=/u);
  if (field) {
    currentFields.push(field[1]);
  }
  depth += (line.match(/\{/gu) ?? []).length - (line.match(/\}/gu) ?? []).length;
  if (depth === 0) {
    if (currentFields.length > 0) {
      byteFieldNames.set(currentMessage, currentFields);
    }
    currentMessage = null;
    currentFields = [];
  }
}

function fail(message) {
  console.error(`generated JOSE proto hardening failed: ${message}`);
  process.exit(1);
}

for (const argument of process.argv.slice(2)) {
  if (!supportedArguments.has(argument)) {
    fail(`unsupported argument ${argument}`);
  }
  if (suppliedArguments.has(argument)) {
    fail(`argument ${argument} was specified more than once`);
  }
  suppliedArguments.add(argument);
}
const checkIdempotent = suppliedArguments.has("--check-idempotent");

function findMatchingBrace(source, openIndex) {
  let depth = 0;
  for (let index = openIndex; index < source.length; index += 1) {
    const char = source[index];
    if (char === "{") {
      depth += 1;
    } else if (char === "}") {
      depth -= 1;
      if (depth === 0) {
        return index;
      }
    }
  }
  fail(`missing matching brace after byte offset ${openIndex}`);
}

function replaceInStructDebug(source, messageName, fields) {
  const implMarker = `impl ::core::fmt::Debug for ${messageName} {`;
  const start = source.indexOf(implMarker);
  if (start < 0) {
    fail(`missing Debug impl for ${messageName}`);
  }
  const open = source.indexOf("{", start);
  const end = findMatchingBrace(source, open);
  let impl = source.slice(start, end + 1);
  for (const fieldName of fields) {
    impl = impl.replaceAll(
      `.field("${fieldName}", &self.${fieldName})`,
      `.field("${fieldName}", &"<redacted>")`,
    );
  }
  return `${source.slice(0, start)}${impl}${source.slice(end + 1)}`;
}

function replaceClearCalls(source, messageName, fields) {
  const messageMarker = `pub struct ${messageName} {`;
  const messageStart = source.indexOf(messageMarker);
  if (messageStart < 0) {
    fail(`missing struct ${messageName}`);
  }
  const clearMarker = "fn clear(&mut self) {";
  const clearStart = source.indexOf(clearMarker, messageStart);
  if (clearStart < 0) {
    fail(`missing clear() for ${messageName}`);
  }
  const open = source.indexOf("{", clearStart);
  const end = findMatchingBrace(source, open);
  let clear = source.slice(clearStart, end + 1);
  for (const fieldName of fields) {
    clear = clear.replaceAll(
      `self.${fieldName}.clear();`,
      `::zeroize::Zeroize::zeroize(&mut self.${fieldName});`,
    );
  }
  return `${source.slice(0, clearStart)}${clear}${source.slice(end + 1)}`;
}

function extractSerdeValue(attrs, key) {
  const match = attrs.match(new RegExp(`${key} = "([^"]+)"`, "u"));
  return match?.[1] ?? null;
}

function extractSerdeAliases(attrs) {
  return [...attrs.matchAll(/alias = "([^"]+)"/gu)].map((match) => match[1]);
}

function parseStructFields(body) {
  const fields = [];
  const lines = body.split("\n");
  let serdeAttr = "";
  let collectingSerde = false;
  let serdeLines = [];
  let collectingField = null;

  function angleDepth(text) {
    let total = 0;
    for (const char of text) {
      if (char === "<") {
        total += 1;
      } else if (char === ">") {
        total -= 1;
      }
    }
    return total;
  }

  function completeType(typeParts) {
    const type = typeParts.join(" ").replace(/,$/u, "").replace(/\s+/gu, " ");
    return type.endsWith(",") || angleDepth(type) === 0;
  }

  for (const line of lines) {
    const trimmed = line.trim();
    if (trimmed.startsWith("#[serde(")) {
      collectingSerde = true;
      serdeLines = [trimmed];
      if (trimmed.endsWith(")]")) {
        collectingSerde = false;
        serdeAttr = serdeLines.join(" ");
      }
      continue;
    }

    if (collectingSerde) {
      serdeLines.push(trimmed);
      if (trimmed.endsWith(")]")) {
        collectingSerde = false;
        serdeAttr = serdeLines.join(" ");
      }
      continue;
    }

    if (collectingField !== null) {
      collectingField.typeParts.push(trimmed);
      if (trimmed.endsWith(",") && completeType(collectingField.typeParts)) {
        const type = collectingField.typeParts
          .join(" ")
          .replace(/,$/u, "")
          .replace(/\s+/gu, " ");
        fields.push({
          name: collectingField.name,
          type,
          jsonName: extractSerdeValue(serdeAttr, "rename") ?? collectingField.name,
          aliases: extractSerdeAliases(serdeAttr),
        });
        collectingField = null;
        serdeAttr = "";
      }
      continue;
    }

    const field = line.match(/^\s+pub\s+(\w+):\s+(.+)$/u);
    if (!field) {
      continue;
    }
    const [, name, typeStart] = field;
    if (typeStart.trim().endsWith(",") && completeType([typeStart.trim()])) {
      fields.push({
        name,
        type: typeStart.trim().replace(/,$/u, ""),
        jsonName: extractSerdeValue(serdeAttr, "rename") ?? name,
        aliases: extractSerdeAliases(serdeAttr),
      });
      serdeAttr = "";
    } else {
      collectingField = { name, typeParts: [typeStart.trim()] };
    }
  }

  return fields;
}

function serdeAttrForWireField(field) {
  const parts = [`rename = "${field.jsonName}"`];
  for (const alias of field.aliases) {
    parts.push(`alias = "${alias}"`);
  }

  if (field.type === "::buffa::alloc::vec::Vec<u8>") {
    parts.push('deserialize_with = "deserialize_zeroizing_bytes"');
  } else if (field.type === "::buffa::alloc::string::String") {
    parts.push('deserialize_with = "deserialize_zeroizing_string"');
  } else if (field.type.startsWith("::buffa::EnumValue<")) {
    parts.push('with = "::buffa::json_helpers::proto_enum"');
  } else if (
    field.type.startsWith("::buffa::MessageField<") ||
    field.type === "bool" ||
    field.type === "u64"
  ) {
    // These generated field shapes use serde's default representation.
  } else {
    fail(`unsupported generated field type ${field.type} on ${field.name}`);
  }

  return `            #[serde(${parts.join(", ")})]`;
}

function wireType(field) {
  if (field.type === "::buffa::alloc::vec::Vec<u8>") {
    return "::zeroize::Zeroizing<::buffa::alloc::vec::Vec<u8>>";
  }
  if (field.type === "::buffa::alloc::string::String") {
    return "::zeroize::Zeroizing<::buffa::alloc::string::String>";
  }
  return field.type;
}

function assignmentForField(field) {
  if (
    field.type === "::buffa::alloc::vec::Vec<u8>" ||
    field.type === "::buffa::alloc::string::String"
  ) {
    return `            ${field.name}: ::core::mem::take(&mut *wire.${field.name}),`;
  }
  return `            ${field.name}: wire.${field.name},`;
}

function deserializeImpl(messageName, fields) {
  const hasSensitiveString = fields.some(
    (field) => field.type === "::buffa::alloc::string::String",
  );
  const wireFields = fields
    .filter((field) => field.name !== "__buffa_unknown_fields")
    .map(
      (field) => `${serdeAttrForWireField(field)}
            ${field.name}: ${wireType(field)},`,
    )
    .join("\n");
  const assignments = fields
    .filter((field) => field.name !== "__buffa_unknown_fields")
    .map(assignmentForField)
    .join("\n");

  return `impl<'de> ::serde::Deserialize<'de> for ${messageName} {
    fn deserialize<D>(deserializer: D) -> ::core::result::Result<Self, D::Error>
    where
        D: ::serde::Deserializer<'de>,
    {
        fn deserialize_zeroizing_bytes<'de, D>(
            deserializer: D,
        ) -> ::core::result::Result<::zeroize::Zeroizing<::buffa::alloc::vec::Vec<u8>>, D::Error>
        where
            D: ::serde::Deserializer<'de>,
        {
            ::buffa::json_helpers::bytes::deserialize(deserializer)
                .map(::zeroize::Zeroizing::new)
        }

${hasSensitiveString ? `        fn deserialize_zeroizing_string<'de, D>(
            deserializer: D,
        ) -> ::core::result::Result<::zeroize::Zeroizing<::buffa::alloc::string::String>, D::Error>
        where
            D: ::serde::Deserializer<'de>,
        {
            <::buffa::alloc::string::String as ::serde::Deserialize>::deserialize(deserializer)
                .map(::zeroize::Zeroizing::new)
        }

` : ""}        #[derive(Default, ::serde::Deserialize)]
        #[serde(default, deny_unknown_fields)]
        struct Wire {
${wireFields}
        }

        let mut wire = Wire::deserialize(deserializer)?;
        Ok(Self {
${assignments}
            __buffa_unknown_fields: Default::default(),
        })
    }
}
`;
}

function dropImpl(messageName, fields) {
  const zeroizeLines = fields
    .filter(
      (field) =>
        field.type === "::buffa::alloc::vec::Vec<u8>" ||
        field.type === "::buffa::alloc::string::String",
    )
    .map((field) => `        ::zeroize::Zeroize::zeroize(&mut self.${field.name});`)
    .join("\n");

  return `impl ::core::ops::Drop for ${messageName} {
    fn drop(&mut self) {
${zeroizeLines}
        __reallyme_zeroize_unknown_fields(&mut self.__buffa_unknown_fields);
    }
}
`;
}

function hardenSensitiveOwnerDrop(source, messageName) {
  const drop = dropImpl(messageName, []);
  if (source.includes(drop)) {
    return source;
  }
  if (source.includes(`impl ::core::ops::Drop for ${messageName} {`)) {
    fail(`${messageName} contains an unexpected partial Drop hardening`);
  }
  const implMarker = `impl ${messageName} {`;
  const implIndex = source.indexOf(implMarker);
  if (implIndex < 0) {
    fail(`missing generated inherent impl for ${messageName}`);
  }
  return `${source.slice(0, implIndex)}${drop}${source.slice(implIndex)}`;
}

function replaceImplBlock(source, marker, replacement, startIndex) {
  const implStart = source.indexOf(marker, startIndex);
  if (implStart < 0) {
    fail(`missing generated impl block ${marker}`);
  }
  const open = source.indexOf("{", implStart);
  const end = findMatchingBrace(source, open);
  let after = end + 1;
  if (source[after] === "\n") {
    after += 1;
  }
  return `${source.slice(0, implStart)}${replacement}${source.slice(after)}`;
}

function hardenOwnedRust() {
  let source = readFileSync(generatedPath, "utf8");
  const generatedHeader = `// @generated by buffa-codegen. DO NOT EDIT.
// source: reallyme/jose/v1/jose.proto
`;
  const unknownFieldZeroizeHelpers = `
fn __reallyme_zeroize_unknown_fields(fields: &mut ::buffa::UnknownFields) {
    for mut field in ::core::mem::take(fields) {
        __reallyme_zeroize_unknown_field_data(&mut field.data);
    }
}

fn __reallyme_zeroize_unknown_field_data(data: &mut ::buffa::UnknownFieldData) {
    match data {
        ::buffa::UnknownFieldData::LengthDelimited(bytes) => {
            ::zeroize::Zeroize::zeroize(bytes);
        }
        ::buffa::UnknownFieldData::Group(fields) => {
            __reallyme_zeroize_unknown_fields(fields);
        }
        ::buffa::UnknownFieldData::Varint(_)
        | ::buffa::UnknownFieldData::Fixed64(_)
        | ::buffa::UnknownFieldData::Fixed32(_) => {}
    }
}
`;
  if (!source.includes(generatedHeader)) {
    fail(`${generatedPath} is missing the generated header`);
  }
  if (!source.includes("__reallyme_zeroize_unknown_fields")) {
    source = source.replace(
      generatedHeader,
      `${generatedHeader}${unknownFieldZeroizeHelpers}`,
    );
  }
  const sensitiveMessageNames = new Set([
    ...byteFieldNames.keys(),
    ...sensitiveStringFieldNames.keys(),
  ]);
  for (const messageName of sensitiveMessageNames) {
    const fields = [
      ...(byteFieldNames.get(messageName) ?? []),
      ...(sensitiveStringFieldNames.get(messageName) ?? []),
    ];
    const structMarker = `pub struct ${messageName} {`;
    const structStart = source.indexOf(structMarker);
    if (structStart < 0) {
      fail(`missing generated Rust message ${messageName}`);
    }
    const structOpen = source.indexOf("{", structStart);
    const structEnd = findMatchingBrace(source, structOpen);
    const parsedFields = parseStructFields(source.slice(structOpen + 1, structEnd));
    const serdeDerive = "#[derive(::serde::Serialize, ::serde::Deserialize)]";
    const serdePrefix = source.slice(0, structStart);
    const serdeDeriveIndex = serdePrefix.lastIndexOf(serdeDerive);
    const hardenedSerdeDerive = "#[derive(::serde::Serialize)]";
    const structHeader = source.slice(Math.max(0, structStart - 512), structStart);
    const hasDrop = source.includes(`impl ::core::ops::Drop for ${messageName} {`);
    const hasDeserialize = source.includes(
      `impl<'de> ::serde::Deserialize<'de> for ${messageName} {`,
    );
    const alreadyHardened =
      structHeader.includes(hardenedSerdeDerive) && hasDrop && hasDeserialize;
    if (!alreadyHardened && (hasDrop || hasDeserialize)) {
      fail(`${messageName} is only partially hardened`);
    }
    if (!alreadyHardened) {
      if (serdeDeriveIndex < 0) {
        fail(`${messageName} is missing generated serde Deserialize derive`);
      }
      source =
        source.slice(0, serdeDeriveIndex) +
        hardenedSerdeDerive +
        source.slice(serdeDeriveIndex + serdeDerive.length);
    }

    source = replaceInStructDebug(source, messageName, fields);
    source = replaceClearCalls(source, messageName, fields);

    const implMarker = `impl ${messageName} {`;
    const implIndex = source.indexOf(implMarker, source.indexOf(structMarker));
    if (implIndex < 0) {
      fail(`missing generated inherent impl for ${messageName}`);
    }
    const hardenedDropImpl = dropImpl(messageName, parsedFields);
    const hardenedDeserializeImpl = deserializeImpl(messageName, parsedFields);
    if (!alreadyHardened) {
      const inserted = `${hardenedDropImpl}${hardenedDeserializeImpl}`;
      source = `${source.slice(0, implIndex)}${inserted}${source.slice(implIndex)}`;
    } else {
      source = replaceImplBlock(
        source,
        `impl ::core::ops::Drop for ${messageName} {`,
        hardenedDropImpl,
        structStart,
      );
      source = replaceImplBlock(
        source,
        `impl<'de> ::serde::Deserialize<'de> for ${messageName} {`,
        hardenedDeserializeImpl,
        structStart,
      );
    }
  }
  // These oneof owners transitively own requests or results containing keys,
  // claims, compact tokens, or plaintext. Child drops wipe declared fields;
  // every owner must separately wipe retained length-delimited unknown fields.
  for (const messageName of sensitiveOneofOwnerNames) {
    source = hardenSensitiveOwnerDrop(source, messageName);
  }
  source = source.replaceAll(
    "        self.__buffa_unknown_fields.clear();",
    "        __reallyme_zeroize_unknown_fields(&mut self.__buffa_unknown_fields);",
  );
  source = source.replaceAll(
    "#[serde(default)]",
    "#[serde(default, deny_unknown_fields)]",
  );
  const ignoredUnknownField = `                        _ => {
                            map.next_value::<serde::de::IgnoredAny>()?;
                        }`;
  const ignoredUnknownFieldCount =
    source.split(ignoredUnknownField).length - 1;
  const strictUnknownField = `                        _ => {
                            return Err(serde::de::Error::custom("unknown field"));
                        }`;
  const strictUnknownFieldCount = source.split(strictUnknownField).length - 1;
  const expectedOneofUnknownFieldBranches =
    readFileSync(protoPath, "utf8").match(/^\s*oneof\s+\w+\s*\{/gmu)?.length ?? 0;
  if (
    ignoredUnknownFieldCount !== expectedOneofUnknownFieldBranches &&
    !(
      ignoredUnknownFieldCount === 0 &&
      strictUnknownFieldCount === expectedOneofUnknownFieldBranches
    )
  ) {
    fail(
      `${generatedPath} expected ${expectedOneofUnknownFieldBranches} generated oneof unknown-field branches, found ${ignoredUnknownFieldCount}`,
    );
  }
  source = source.replaceAll(ignoredUnknownField, strictUnknownField);
  // Buffa's enum visitors otherwise reflect attacker-controlled numeric values
  // into allocated error strings. Fixed diagnostics keep boundary failures
  // deterministic and avoid carrying untrusted input into logs.
  source = source.replaceAll(
    `::serde::de::Error::custom(
                            ::buffa::alloc::format!("enum value {v} out of i32 range"),
                        )`,
    `::serde::de::Error::custom("enum value out of i32 range")`,
  );
  source = source.replaceAll(
    `::serde::de::Error::custom(
                            ::buffa::alloc::format!("unknown enum value {v32}"),
                        )`,
    `::serde::de::Error::custom("unknown enum value")`,
  );
  if (source.includes("::buffa::alloc::format!(")) {
    fail(`${generatedPath} still contains formatted ProtoJSON errors`);
  }
  writeFileSync(generatedPath, source);
}

function extractViewFields(source, structStart, structEnd) {
  return [...source.slice(structStart, structEnd).matchAll(/^\s+pub\s+(\w+):/gmu)]
    .map((field) => field[1])
    .filter((fieldName) => fieldName !== "__buffa_unknown_fields");
}

function hardenViewRust() {
  let source = readFileSync(generatedViewPath, "utf8");
  for (const [messageName, sensitiveFields] of byteFieldNames.entries()) {
    const viewName = `${messageName}View`;
    source = source.replace(
      `#[derive(Clone, Debug, Default)]\npub struct ${viewName}<'a> {`,
      `#[derive(Clone, Default)]\npub struct ${viewName}<'a> {`,
    );
    if (!source.includes(`impl<'a> ::core::fmt::Debug for ${viewName}<'a>`)) {
      const structStart = source.indexOf(`pub struct ${viewName}<'a> {`);
      if (structStart < 0) {
        fail(`missing view struct ${viewName}`);
      }
      const structEnd = source.indexOf("\n}", structStart);
      if (structEnd < 0) {
        fail(`missing end of view struct ${viewName}`);
      }
      const debugFields = extractViewFields(source, structStart, structEnd)
        .map((fieldName) => {
          const value = sensitiveFields.includes(fieldName)
            ? '"<redacted>"'
            : `self.${fieldName}`;
          return `            .field("${fieldName}", &${value})`;
        })
        .join("\n");
      const debugImpl = `\nimpl<'a> ::core::fmt::Debug for ${viewName}<'a> {
    fn fmt(&self, f: &mut ::core::fmt::Formatter<'_>) -> ::core::fmt::Result {
        f.debug_struct("${viewName}")
${debugFields}
            .finish()
    }
}
`;
      source = `${source.slice(0, structEnd + 2)}${debugImpl}${source.slice(structEnd + 2)}`;
    }

    const ownedViewName = `${messageName}OwnedView`;
    source = source.replace(
      `#[derive(Clone, Debug)]\npub struct ${ownedViewName}(`,
      `#[derive(Clone)]\npub struct ${ownedViewName}(`,
    );
    if (!source.includes(`impl ::core::fmt::Debug for ${ownedViewName} {`)) {
      const ownedImpl = `impl ${ownedViewName} {`;
      const ownedImplIndex = source.indexOf(ownedImpl);
      if (ownedImplIndex < 0) {
        fail(`missing owned view impl ${ownedViewName}`);
      }
      const ownedDebugImpl = `impl ::core::fmt::Debug for ${ownedViewName} {
    fn fmt(&self, f: &mut ::core::fmt::Formatter<'_>) -> ::core::fmt::Result {
        f.write_str("${ownedViewName}(<redacted>)")
    }
}
`;
      source =
        source.slice(0, ownedImplIndex) +
        ownedDebugImpl +
        source.slice(ownedImplIndex);
    }
  }
  writeFileSync(generatedViewPath, source);
}

function normalizeGeneratedModuleRust() {
  let source = readFileSync(generatedModulePath, "utf8");
  const expectedAllowAttributeCount = 4;
  const allowAttributeCount =
    source.match(/^[\t ]*#!?\[allow\(/gmu)?.length ?? 0;
  if (allowAttributeCount !== expectedAllowAttributeCount) {
    fail(
      `${generatedModulePath} expected ${expectedAllowAttributeCount} generated allow attributes, found ${allowAttributeCount}`,
    );
  }

  // Buffa 0.9.1 emits its module-tree allow attributes on one long line.
  // Canonical expansion keeps checked-in generation compatible with the
  // repository-wide rustfmt gate without weakening that gate for generated
  // code or depending on an implicit formatter invocation.
  source = source.replace(
    /^([\t ]*)(#!?\[allow\()([^\n)]+)(\)\])$/gmu,
    (_match, indentation, prefix, body, suffix) => {
      const items = body.split(", ");
      if (items.some((item) => item.length === 0)) {
        fail(`${generatedModulePath} contains an invalid compact allow attribute`);
      }
      const formattedItems = items
        .map((item, index) => {
          const separator = index === items.length - 1 ? "" : ",";
          return `${indentation}    ${item}${separator}`;
        })
        .join("\n");
      return `${indentation}${prefix}\n${formattedItems}\n${indentation}${suffix}`;
    },
  );
  writeFileSync(generatedModulePath, source);
}

const generatedPaths = [generatedPath, generatedViewPath, generatedModulePath];
const idempotencyBefore = checkIdempotent
  ? new Map(generatedPaths.map((path) => [path, readFileSync(path)]))
  : null;

hardenOwnedRust();
hardenViewRust();
normalizeGeneratedModuleRust();

if (idempotencyBefore !== null) {
  for (const [path, before] of idempotencyBefore) {
    if (!before.equals(readFileSync(path))) {
      fail("generated JOSE protobuf hardening is not idempotent");
    }
  }
}
