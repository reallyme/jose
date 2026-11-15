// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

// SDK modes are views of the schema oneof. Reject additions until the adapter
// implements the new payload, rather than silently omitting a public mode.
export function sdkVerification(schema, header) {
  const body = /message JoseJwtVerificationPolicy \{\s*oneof mode \{([^}]+)\}/u.exec(schema)?.[1];
  if (body === undefined) throw new TypeError("verification oneof missing");
  const payloads = new Map([
    ["JoseJwtSignatureOnlyPolicy", undefined],
    ["JoseJwtTemporalValidationPolicy", "ClaimsPolicy"],
    ["JoseJwtTemporalOnlyPolicy", "TemporalPolicy"],
  ]);
  const modes = [...body.matchAll(/(\w+) (\w+) =/gu)].map(([, type, name]) => {
    if (!payloads.has(type)) throw new TypeError("verification mode needs an SDK adapter");
    const mode = name.replace(/_([a-z])/gu, (_, letter) => letter.toUpperCase());
    return { mode, title: mode[0].toUpperCase() + mode.slice(1), policy: payloads.get(type) };
  });
  const options = /message JoseJwtTemporalOptions \{([^}]+)\}/u.exec(schema)?.[1];
  const fields = new Map([
    ["require_exp", ["requireExpiration", "Bool", "Boolean", "boolean"]],
    ["require_nbf", ["requireNotBefore", "Bool", "Boolean", "boolean"]],
    ["require_iat", ["requireIssuedAt", "Bool", "Boolean", "boolean"]],
    ["clock_skew_seconds", ["clockSkewSeconds", "UInt64", "Long", "bigint"]],
    ["max_future_iat_skew_seconds", ["maximumFutureIssuedAtSkewSeconds", "UInt64", "Long", "bigint"]],
  ]);
  const temporalFields = [...(options ?? "").matchAll(/\w+ (\w+) =/gu)].map(([, name]) => {
    if (!fields.has(name)) throw new TypeError("temporal option needs an SDK adapter");
    return fields.get(name);
  });
  temporalFields.push(["nowUnix", "UInt64", "Long", "bigint"]);
  const swift = header + "/// Explicit schema verification mode. Temporal-only does not authorize an audience.\npublic enum ReallyMeJOSEJWTVerification: Sendable, Equatable {\n" +
    modes.map(({ mode, policy }) => `  case ${mode}${policy === undefined ? "" : `(ReallyMeJOSEJWT${policy})`}`).join("\n") +
    "\n}\n\npublic struct ReallyMeJOSEJWTTemporalPolicy: Sendable, Equatable, CustomReflectable {\n" +
    temporalFields.map(([name, type]) => `  public let ${name}: ${type}`).join("\n") +
    "\n\n  public init(\n" + temporalFields.map(([name, type]) => `    ${name}: ${type}`).join(",\n") + "\n  ) {\n" +
    temporalFields.map(([name]) => `    self.${name} = ${name}`).join("\n") +
    '\n  }\n\n  public var customMirror: Mirror { Mirror(self, children: [("value", "<redacted>")]) }\n}\n';
  const kotlin = header + "package me.really.jose\n\n/** Explicit schema verification mode. Temporal-only does not authorize an audience. */\npublic sealed interface ReallyMeJoseJwtVerification {\n" +
    modes.map(({ title, policy }) => policy === undefined ? `    public data object ${title} : ReallyMeJoseJwtVerification` : `    public class ${title}(public val policy: ReallyMeJoseJwt${policy}) : ReallyMeJoseJwtVerification`).join("\n") +
    "\n}\n\npublic class ReallyMeJoseJwtTemporalPolicy(\n" + temporalFields.map(([name, , type]) => `    public val ${name}: ${type},`).join("\n") + "\n)\n";
  const typescript = header + 'import type { ReallyMeJoseJwtClaimsPolicy } from "./facade.js";\n\n' +
    "export type ReallyMeJoseJwtVerification =\n" + modes.map(({ mode, policy }) => `  | Readonly<{ mode: "${mode}"${policy === undefined ? "" : `; policy: ReallyMeJoseJwt${policy}`} }>`).join("\n") + ";\n\n" +
    "export type ReallyMeJoseJwtTemporalPolicy = Readonly<{\n" + temporalFields.map(([name, , , type]) => `  ${name === "nowUnix" ? "verificationTimeUnixSeconds" : name}${name === "nowUnix" ? "" : "?"}: ${type};`).join("\n") + "\n}>;\n";
  return new Map([
    ["packages/swift/Sources/ReallyMeJOSE/ContractVerification.swift", swift],
    ["packages/kotlin/src/main/kotlin/me/really/jose/ContractVerification.kt", kotlin],
    ["packages/ts/src/contract-verification.ts", typescript],
  ]);
}
