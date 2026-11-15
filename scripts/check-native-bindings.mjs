// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

const functionDeclaration = "^pub\\s+(?:(?:const|async|unsafe)\\s+)*(?:extern\\s+\"[^\"]+\"\\s+)?fn\\s+";
const identityPattern = "([a-z0-9_/]+\\.rs)#(\\w+)";
const withoutComments = (source) => source.replace(/\/\*[\s\S]*?\*\/|\/\/[^\n]*/gu, "");

export function assertNativeBindings({ schema, messages, enumNames, sources, failures, errorTests, failureBindings }) {
  const code = new Map([...sources].map(([path, source]) => [path, withoutComments(source)]));
  const bindings = (kind) => [...schema.matchAll(new RegExp(`// Rust ${kind}: ${identityPattern}`, "gu"))];
  const identities = (matches) => new Set(matches.map((match) => `${match[1]}#${match[2]}`));
  const adapters = identities(bindings("adapter"));
  const capabilities = identities(bindings("capability"));
  const views = identities(bindings("view"));
  const constants = new Map([...schema.matchAll(new RegExp(`// Rust constant: ${identityPattern} = (\\w+)`, "gu"))]
    .map((match) => [`${match[1]}#${match[2]}`, match[3]]));
  const fieldAliases = new Map([...schema.matchAll(new RegExp(`// Rust field: ${identityPattern}\\.(\\w+) = (\\w+)`, "gu"))]
    .map((match) => [`${match[1]}#${match[2]}.${match[3]}`, match[4]]));
  for (const identity of adapters) {
    const [path, name] = identity.split("#");
    if (!new RegExp(`${functionDeclaration}${name}\\b`, "mu").test(code.get(path) ?? "")) {
      throw new TypeError("schema adapter does not exist");
    }
  }
  for (const identity of [...capabilities, ...views]) {
    const [path, name] = identity.split("#");
    const source = code.get(path) ?? "";
    const declared = new RegExp(`^pub (?:struct|enum|trait|type) ${name}\\b`, "mu").test(source);
    const reexported = [...source.matchAll(/^pub use ([\s\S]*?);/gmu)]
      .some((match) => new RegExp(`\\b${name}\\b`, "u").test(match[1]));
    if (!declared && !reexported) throw new TypeError("schema native value or capability does not exist");
  }
  for (const [identity, value] of constants) {
    const [path, name] = identity.split("#");
    const definition = new RegExp(`^pub const ${name}\\s*:[^;=]+=(.*?);`, "msu").exec(code.get(path) ?? "");
    if (definition?.[1].replace(/\s+/gu, "") !== `reallyme_jose_proto::generated::contract_values::${value}` ||
        !new RegExp(`JOSE_(?:CONTRACT|JWT_POLICY)_LIMIT_${value}\\s*=`, "u").test(schema)) {
      throw new TypeError("public native limit must derive exactly from its schema constant");
    }
  }

  const schemaFields = new Map(messages.map(({ name, body }) => [name,
    new Set([...body.matchAll(/^\s*(?:(?:optional|repeated)\s+)?\w+\s+(\w+)\s*=/gmu)].map((match) => match[1])),
  ]));
  const viewFields = new Map();
  for (const match of bindings("view")) {
    const owner = messages.find(({ start, end }) => match.index >= start && match.index < end)
      ?? messages.find(({ start }) => start > match.index);
    if (owner === undefined) throw new TypeError("native view lacks a schema owner");
    const identity = `${match[1]}#${match[2]}`;
    viewFields.set(identity, new Set([...(viewFields.get(identity) ?? []), ...schemaFields.get(owner.name)]));
  }
  const checkedFields = new Set();
  const nativeCode = [...code.values()].join("\n");
  for (const [, name] of schema.matchAll(/\/\/ Rust selector: (\w+); (?:public|crate);/gu)) {
    const expected = [...schema.matchAll(new RegExp(`// Rust variant: ${name}\\.(\\w+)`, "gu"))].map((match) => match[1]).sort();
    const declarations = [...nativeCode.matchAll(new RegExp(`pub(?:\\(crate\\))? enum ${name} \\{([^}]+)\\}`, "gu"))];
    const actual = declarations.length === 1 ? [...declarations[0][1].matchAll(/^\s*(\w+),/gmu)].map((match) => match[1]).sort() : [];
    if (expected.length === 0 || JSON.stringify(actual) !== JSON.stringify(expected)) {
      throw new TypeError("native selector variants differ from the schema profile");
    }
    if (!new RegExp(`impl From<${name}> for `, "u").test(nativeCode)) throw new TypeError("native selector lacks a total reverse mapping");
  }
  for (const [path, source] of code) {
    if (/(?:^|\/)(?:tests(?:\/|\.rs$)|[^/]*_tests\.rs$)/u.test(path)) continue;
    for (const [, name] of source.matchAll(/^pub enum (\w+)\s*/gmu)) {
      if (name.endsWith("Error")) continue;
      const conversions = [...nativeCode.matchAll(new RegExp(`\\bimpl\\s+TryFrom<([^;{]+)>\\s+for\\s+(?:\\w+::)*${name}\\s*\\{`, "gu"))];
      const input = conversions.length === 1 ? conversions[0][1].replace(/\s+/gu, "") : "";
      const schemaEnum = /^(?:\w+::)*EnumValue<((?:\w+::)*\w+)>$/u.exec(input)?.[1].split("::").at(-1);
      if (schemaEnum === undefined || !enumNames.has(schemaEnum)) {
        throw new TypeError("native enum requires one total generated-enum conversion");
      }
    }
    for (const [, name] of source.matchAll(new RegExp(`${functionDeclaration}(\\w+)`, "gmu"))) {
      if (!adapters.has(`${path}#${name}`)) throw new TypeError("public native operation lacks schema binding");
    }
    for (const [, kind, name] of source.matchAll(/^pub (struct|trait|type) (\w+)/gmu)) {
      const identity = `${path}#${name}`;
      if (!views.has(identity) && !capabilities.has(identity)) throw new TypeError("public native value or capability lacks schema binding");
      if (kind !== "struct") continue;
      const body = new RegExp(`^pub struct ${name}\\b[^;{]*\\{([\\s\\S]*?)^\\}`, "mu").exec(source)?.[1] ?? "";
      for (const [, field] of body.matchAll(/^\s*pub (\w+)\s*:/gmu)) {
        const fieldIdentity = `${identity}.${field}`;
        const target = fieldAliases.get(fieldIdentity) ?? field;
        if (!viewFields.get(identity)?.has(target)) throw new TypeError("public native field lacks schema representation");
        checkedFields.add(fieldIdentity);
      }
    }
    for (const [, name] of source.matchAll(/^pub const (\w+)\s*:/gmu)) {
      if (!constants.has(`${path}#${name}`)) throw new TypeError("public native constant lacks schema binding");
    }
    for (const [, error, body] of source.matchAll(/pub enum (\w+Error)\s*\{([\s\S]*?)^\}/gmu)) {
      for (const [, variant] of body.matchAll(/^ {4}(\w+)(?=\s*[({,])/gmu)) {
        const identity = `${error}::${variant}`;
        if (!failureBindings.includes(identity) || !failures.includes(identity) || !errorTests.includes(identity)) {
          throw new TypeError("native error variant lacks schema mapping or coverage");
        }
      }
    }
  }
  for (const identity of fieldAliases.keys()) {
    if (!checkedFields.has(identity)) throw new TypeError("schema native field alias does not exist");
  }
}
