// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

// Parse the bounded, flat message declarations accepted by the pinned pipeline.
// Braces in comments cannot create phantom contract types or bypass checks.
export function schemaMessages(schema) {
  const source = schema.replace(/\/\/[^\n]*/gu, (comment) => " ".repeat(comment.length));
  const messages = [];
  const pattern = /\bmessage\s+(\w+)\s*\{/gu;
  for (let match = pattern.exec(source); match !== null; match = pattern.exec(source)) {
    let depth = 1;
    let end = pattern.lastIndex;
    for (; end < source.length && depth !== 0; end += 1) {
      if (source[end] === "{") depth += 1;
      if (source[end] === "}") depth -= 1;
    }
    if (depth !== 0) throw new TypeError("unterminated schema message");
    messages.push({ start: match.index, end, name: match[1], body: source.slice(pattern.lastIndex, end - 1), rawBody: schema.slice(pattern.lastIndex, end - 1) });
    pattern.lastIndex = end;
  }
  return messages;
}
