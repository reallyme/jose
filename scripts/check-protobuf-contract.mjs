#!/usr/bin/env node
// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

import { readFileSync, readdirSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { assertNativeBindings } from "./check-native-bindings.mjs";
import { schemaMessages } from "./read-proto-schema.mjs";

const root = new URL("../", import.meta.url);
const read = (path) => readFileSync(new URL(path, root), "utf8");
const title = (name) => name.split("_").map((part) => part[0].toUpperCase() + part.slice(1)).join("");

export function assertProtobufContract({ schema, sources, dispatcher, responseBuilders, failures, errorTests }) {
  const messages = schemaMessages(schema);
  const messageByName = new Map(messages.map((message) => [message.name, message]));
  const enumNames = new Set([...schema.matchAll(/^enum (\w+) \{/gmu)].map((match) => match[1]));
  const reachable = new Set();
  const visit = (name) => {
    if (reachable.has(name)) return;
    reachable.add(name);
    const message = messageByName.get(name);
    if (message === undefined) return;
    for (const [, type] of message.body.matchAll(/^\s*(?:(?:optional|repeated)\s+)?(\w+)\s+\w+\s*=\s*\d+/gmu)) {
      if (messageByName.has(type) || enumNames.has(type)) visit(type);
    }
  };
  visit("JoseOperationRequest"); visit("JoseOperationResponse");
  // SDK-local errors use this enum directly, outside the operation envelopes.
  if (enumNames.has("JoseSdkErrorCode")) visit("JoseSdkErrorCode");
  for (const name of [...messageByName.keys(), ...enumNames]) {
    if (!reachable.has(name)) throw new TypeError("schema type is unreachable from the public contract");
  }
  for (const { rawBody } of messages) {
    if (/\bbool\s+has_\w+\s*=/u.test(rawBody)) throw new TypeError("handmade presence flag in schema");
    for (const field of rawBody.matchAll(/^\s*(?:(?:optional|repeated)\s+)?(?:bytes|string|sint64)\s+\w+\s*=/gmu)) {
      const comments = rawBody.slice(0, field.index).match(/(?:\s*\/\/[^\n]*\n)+\s*$/u)?.[0] ?? "";
      if (!comments.includes("SENSITIVE:")) throw new TypeError("sensitive scalar lacks ownership declaration");
    }
  }
  const bindings = [...schema.matchAll(/\/\/ Rust failure: (\w+::\w+)(?:\(_\))?/gu)].map((match) => match[1]);
  if (new Set(bindings).size !== bindings.length) throw new TypeError("native failure has multiple schema reasons");
  const request = messages.find(({ name }) => name === "JoseOperationRequest");
  const response = messages.find(({ name }) => name === "JoseOperationResponse");
  if (request === undefined || response === undefined) throw new TypeError("operation envelopes missing");
  const fields = (body) => new Map([...body.matchAll(/^\s*\w+\s+(\w+)\s*=\s*(\d+);/gmu)].map((m) => [m[1], m[2]]));
  const requests = fields(request.body);
  const responses = fields(response.body);
  responses.delete("contract_version");
  responses.delete("boundary_error");
  if (requests.size !== responses.size) throw new TypeError("request and response operation sets differ");
  for (const [name, number] of requests) {
    if (responses.get(name) !== number) throw new TypeError("operation numbers differ");
    const variant = title(name);
    if ([...dispatcher.matchAll(new RegExp(`RequestOperation::${variant}\\s*\\(`, "gu"))].length !== 1) throw new TypeError("operation must dispatch exactly once");
    if (!responseBuilders.includes(`Response::${variant}(`)) throw new TypeError("operation result pairing missing");
  }
  assertNativeBindings({ schema, messages, enumNames, sources, failures, errorTests, failureBindings: bindings });
}

function sources() {
  const result = new Map();
  const visit = (relative) => {
    for (const entry of readdirSync(new URL(`crates/jose/src/${relative}`, root), { withFileTypes: true })) {
      const path = `${relative}${entry.name}`;
      if (entry.isDirectory()) visit(`${path}/`);
      else if (entry.isFile() && path.endsWith(".rs")) result.set(path, read(`crates/jose/src/${path}`));
    }
  };
  visit("");
  return result;
}

export function checkProtobufContract() {
  assertProtobufContract({
    schema: read("crates/proto/proto/reallyme/jose/v1/jose.proto"), sources: sources(),
    dispatcher: read("crates/jose/src/wire/operation_response.rs"),
    responseBuilders: read("crates/jose/src/wire/operation_response/build_response.rs"),
    failures: read("crates/jose/src/map_failure.rs"), errorTests: read("crates/jose/tests/error_reason_tests.rs"),
  });
}

if (process.argv[1] === fileURLToPath(import.meta.url)) checkProtobufContract();
