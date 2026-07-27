// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

const GENERATED_TYPE_PATTERN = /\breallyme_jose_proto\b|\bJose(?:Jws|Jwt|Jwe|Operation|Compact|Verify|Error)/u;

const callPattern = (name) =>
  new RegExp(
    `\\b${name.replace(/[.*+?^${}()|[\]\\]/gu, "\\$&")}(?:\\s*<[^>{}\\n]*>)?\\s*\\(`,
    "gu",
  );

export function assertExactCallCount({ source, name, expected, label, fail }) {
  const count = source.match(callPattern(name))?.length ?? 0;
  if (count !== expected) {
    fail(`${label} calls ${name} ${count} time(s), expected exactly ${expected}`);
  }
}

export function assertForbiddenTokens({ source, tokens, label, fail }) {
  for (const token of tokens) {
    if (source.includes(token)) {
      fail(`${label} contains forbidden semantic-bypass token ${token}`);
    }
  }
}

export function assertExclusiveCallSites({ sources, name, expectedByFile, fail }) {
  const allowedFiles = new Set(expectedByFile.keys());
  for (const [file, source] of sources) {
    const count = source.match(callPattern(name))?.length ?? 0;
    const expected = expectedByFile.get(file) ?? 0;
    if (count !== expected) {
      const ownership = allowedFiles.has(file) ? "owned" : "unauthorized";
      fail(
        `${file} has ${count} ${ownership} ${name} call site(s), expected exactly ${expected}`,
      );
    }
  }
}

function assertNoGeneratedTypes({ source, label, fail }) {
  if (GENERATED_TYPE_PATTERN.test(source)) {
    fail(`${label} must remain independent of generated protobuf types`);
  }
}

function assertLineLimit({ source, file, fail }) {
  const lineCount = source.split("\n").length;
  const limit = file.endsWith("mod.rs") ? 40 : 500;
  if (lineCount > limit) {
    fail(`${file} has ${lineCount} lines, exceeding its ${limit}-line limit`);
  }
}

export function assertOperationContractArchitecture({ readText, listFiles, fail }) {
  const semanticFiles = [
    "crates/jose/src/operation_contract/jws/sign.rs",
    "crates/jose/src/operation_contract/jws/verify.rs",
    "crates/jose/src/operation_contract/jwt/execute.rs",
    "crates/jose/src/operation_contract/jwe/execute.rs",
  ];
  const protobufAdapters = [
    "crates/jose/src/operation_contract/protobuf/jws_sign.rs",
    "crates/jose/src/operation_contract/protobuf/jws_verify.rs",
    "crates/jose/src/operation_contract/protobuf/jwt.rs",
    "crates/jose/src/operation_contract/protobuf/jwt_jwk.rs",
    "crates/jose/src/operation_contract/protobuf/jwe.rs",
  ];
  const operationContractFiles = listFiles("crates/jose/src/operation_contract").filter(
    (file) => file.endsWith(".rs") && !file.endsWith("verify_tests.rs"),
  );
  const requiredFiles = [
    ...semanticFiles,
    ...protobufAdapters,
    "crates/jose/src/operation_contract/mod.rs",
    "crates/jose/src/operation_contract/jws/mod.rs",
    "crates/jose/src/operation_contract/jwt/mod.rs",
    "crates/jose/src/operation_contract/jwe/mod.rs",
    "crates/jose/src/operation_contract/protobuf/mod.rs",
  ];
  for (const file of requiredFiles) {
    readText(file);
  }
  for (const file of operationContractFiles) {
    assertLineLimit({ source: readText(file), file, fail });
  }

  for (const file of semanticFiles) {
    const source = readText(file);
    assertNoGeneratedTypes({ source, label: file, fail });
    assertForbiddenTokens({
      source,
      tokens: ["crate::wire", "JoseWireError", "JoseErrorReason"],
      label: file,
      fail,
    });
  }
  const jwsSignSemantic = readText("crates/jose/src/operation_contract/jws/sign.rs");
  assertForbiddenTokens({
    source: jwsSignSemantic,
    tokens: ["jws::suites", "JwsEs256Error", "JwsEddsaError"],
    label: "crates/jose/src/operation_contract/jws/sign.rs",
    fail,
  });
  for (const semanticCall of [
    "encode_jws_signing_input",
    "encode_compact_jws",
    "sign_p256_jose_signature",
    "dispatch_sign",
  ]) {
    assertExactCallCount({
      source: jwsSignSemantic,
      name: semanticCall,
      expected: 1,
      label: "crates/jose/src/operation_contract/jws/sign.rs",
      fail,
    });
  }
  const jwsVerifySemantic = readText("crates/jose/src/operation_contract/jws/verify.rs");
  assertForbiddenTokens({
    source: jwsVerifySemantic,
    tokens: ["jws::suites", "JwsEs256Error", "JwsEddsaError"],
    label: "crates/jose/src/operation_contract/jws/verify.rs",
    fail,
  });
  for (const semanticCall of [
    "parse_compact_jws",
    "decode_and_validate_header",
    "build_sig_structure",
    "decode_signature",
  ]) {
    assertExactCallCount({
      source: jwsVerifySemantic,
      name: semanticCall,
      expected: 1,
      label: "crates/jose/src/operation_contract/jws/verify.rs",
      fail,
    });
  }

  const protobufPolicies = [
    {
      file: "crates/jose/src/operation_contract/protobuf/jws_sign.rs",
      calls: new Map([["sign_jws", 1]]),
      forbidden: ["reallyme_crypto", "dispatch_sign", "sign_p256_jose_signature"],
    },
    {
      file: "crates/jose/src/operation_contract/protobuf/jws_verify.rs",
      calls: new Map([["verify_jws", 1]]),
      forbidden: ["reallyme_crypto", "dispatch_verify", "verify_p256_jose_signature"],
    },
    {
      file: "crates/jose/src/operation_contract/protobuf/jwt.rs",
      calls: new Map([
        ["encode_unsigned_jwt", 1],
        ["decode_unsigned_jwt", 1],
        ["sign_jwt", 1],
        ["verify_jwt_signature_only", 1],
        ["verify_jwt_with_claims_policy", 1],
      ]),
      forbidden: [
        "reallyme_crypto::dispatch",
        "encode_unsigned_jwt_claims_json_core",
        "decode_unsigned_jwt_claims_json_core",
        "encode_signed_jwt_claims_json_core",
        "decode_verify_jwt_claims_json_signature_only_core",
        "decode_verify_jwt_claims_json_with_temporal_policy_core",
        "decode_verify_jwt_claims_json_with_claims_policy_core",
      ],
    },
    {
      file: "crates/jose/src/operation_contract/protobuf/jwe.rs",
      calls: new Map([
        ["encrypt_jwe", 1],
        ["decrypt_jwe", 1],
      ]),
      forbidden: [
        "reallyme_crypto",
        "encrypt_compact_jwe_bytes",
        "decrypt_compact_jwe_bytes",
        "encrypt_compact_jwe_bytes_core",
        "decrypt_compact_jwe_bytes_core",
      ],
    },
  ];
  for (const policy of protobufPolicies) {
    const source = readText(policy.file);
    for (const [name, expected] of policy.calls) {
      assertExactCallCount({ source, name, expected, label: policy.file, fail });
    }
    assertForbiddenTokens({
      source,
      tokens: policy.forbidden,
      label: policy.file,
      fail,
    });
  }

  const wireFile = "crates/jose/src/wire.rs";
  const wireSource = readText(wireFile);
  const canonicalResponseFile = "crates/jose/src/wire/operation_response.rs";
  const canonicalResponseSource = readText(canonicalResponseFile);
  assertLineLimit({ source: canonicalResponseSource, file: canonicalResponseFile, fail });
  for (const adapterCall of [
    "sign_jws_request",
    "verify_jws_request",
    "encode_unsigned_jwt_request",
    "decode_unsigned_jwt_request",
    "sign_jwt_request",
    "verify_jwt_request",
    "encrypt_jwe_request",
    "decrypt_jwe_request",
  ]) {
    assertExactCallCount({
      source: canonicalResponseSource,
      name: adapterCall,
      expected: 1,
      label: canonicalResponseFile,
      fail,
    });
  }
  assertForbiddenTokens({
    source: wireSource,
    tokens: [
      "use crate::jws",
      "use crate::jwt",
      "use crate::jwe",
      "reallyme_crypto",
      "serde_json::Value",
      "jwk_from_json(",
      "map_jwt_error(",
      "map_jwe_error(",
      "sign_jws(",
      "verify_jws(",
      "encode_unsigned_jwt(",
      "decode_unsigned_jwt(",
      "sign_jwt(",
      "verify_jwt_signature_only(",
      "verify_jwt_with_temporal_policy(",
      "verify_jwt_with_claims_policy(",
      "encrypt_jwe(",
      "decrypt_jwe(",
      "encrypt_compact_jwe_bytes(",
      "decrypt_compact_jwe_bytes(",
    ],
    label: wireFile,
    fail,
  });
  assertForbiddenTokens({
    source: canonicalResponseSource,
    tokens: [
      "reallyme_crypto",
    ],
    label: canonicalResponseFile,
    fail,
  });
  const facadePolicies = [
    {
      file: "crates/jose/src/jws/suites/es256.rs",
      calls: new Map([
        ["sign_jws", 1],
        ["verify_jws", 1],
      ]),
      required: ["JwsSignAlgorithm::Es256", "JwsVerifyAlgorithm::Es256"],
      forbidden: [
        "encode_jws_signing_input(",
        "encode_compact_jws(",
        "parse_compact_jws(",
        "decode_and_validate_header(",
      ],
    },
    {
      file: "crates/jose/src/jws/suites/eddsa.rs",
      calls: new Map([
        ["sign_jws", 1],
        ["verify_jws", 1],
      ]),
      required: ["JwsSignAlgorithm::Eddsa", "JwsVerifyAlgorithm::Eddsa"],
      forbidden: [
        "reallyme_crypto::dispatch",
        "encode_jws_signing_input(",
        "encode_compact_jws(",
        "parse_compact_jws(",
        "decode_and_validate_header(",
      ],
    },
    {
      file: "crates/jose/src/jwt/sign.rs",
      calls: new Map([
        ["operation_contract::jwt::sign_jwt", 1],
        ["operation_contract::jwt::sign_jwt_with_signer", 1],
      ]),
      required: [],
      forbidden: [],
    },
    {
      file: "crates/jose/src/jwt/unsigned.rs",
      calls: new Map([
        ["operation_contract::jwt::encode_unsigned_jwt", 1],
        ["operation_contract::jwt::decode_unsigned_jwt", 2],
      ]),
      required: [],
      forbidden: [],
    },
    {
      file: "crates/jose/src/jwt/verify.rs",
      calls: new Map([
        ["operation_contract::jwt::verify_jwt_signature_only", 1],
        ["operation_contract::jwt::verify_jwt_with_temporal_policy", 3],
        ["operation_contract::jwt::verify_jwt_with_claims_policy", 1],
      ]),
      required: [],
      forbidden: [],
    },
    {
      file: "crates/jose/src/jwe/encrypt.rs",
      calls: new Map([["operation_contract::jwe::encrypt_jwe", 2]]),
      required: [],
      forbidden: [],
    },
    {
      file: "crates/jose/src/jwe/decrypt.rs",
      calls: new Map([["operation_contract::jwe::decrypt_jwe", 2]]),
      required: [],
      forbidden: [],
    },
  ];
  for (const policy of facadePolicies) {
    const source = readText(policy.file);
    for (const [name, expected] of policy.calls) {
      assertExactCallCount({ source, name, expected, label: policy.file, fail });
    }
    for (const required of policy.required) {
      if (!source.includes(required)) {
        fail(`${policy.file} does not select required typed mode ${required}`);
      }
    }
    assertForbiddenTokens({
      source,
      tokens: policy.forbidden,
      label: policy.file,
      fail,
    });
  }

  const productionSources = new Map(
    listFiles("crates/jose/src")
      .filter((file) => file.endsWith(".rs") && !file.endsWith("_tests.rs"))
      .map((file) => [file, readText(file)]),
  );
  const coreOwnership = [
    {
      name: "encrypt_compact_jwe_bytes_core",
      owner: "crates/jose/src/jwe/encrypt.rs",
      semantic: "crates/jose/src/operation_contract/jwe/execute.rs",
    },
    {
      name: "decrypt_compact_jwe_bytes_core",
      owner: "crates/jose/src/jwe/decrypt.rs",
      semantic: "crates/jose/src/operation_contract/jwe/execute.rs",
    },
    {
      name: "encode_unsigned_jwt_claims_json_core",
      owner: "crates/jose/src/jwt/unsigned.rs",
      semantic: "crates/jose/src/operation_contract/jwt/execute.rs",
    },
    {
      name: "decode_unsigned_jwt_claims_json_core",
      owner: "crates/jose/src/jwt/unsigned.rs",
      semantic: "crates/jose/src/operation_contract/jwt/execute.rs",
    },
    {
      name: "encode_signed_jwt_claims_json_core",
      owner: "crates/jose/src/jwt/sign.rs",
      semantic: "crates/jose/src/operation_contract/jwt/execute.rs",
    },
    {
      name: "encode_signed_jwt_claims_json_with_signer_core",
      owner: "crates/jose/src/jwt/sign.rs",
      semantic: "crates/jose/src/operation_contract/jwt/execute.rs",
    },
    {
      name: "decode_verify_jwt_claims_json_signature_only_core",
      owner: "crates/jose/src/jwt/verify.rs",
      semantic: "crates/jose/src/operation_contract/jwt/execute.rs",
    },
    {
      name: "decode_verify_jwt_claims_json_with_temporal_policy_core",
      owner: "crates/jose/src/jwt/verify.rs",
      semantic: "crates/jose/src/operation_contract/jwt/execute.rs",
    },
    {
      name: "decode_verify_jwt_claims_json_with_claims_policy_core",
      owner: "crates/jose/src/jwt/verify.rs",
      semantic: "crates/jose/src/operation_contract/jwt/execute.rs",
    },
  ];
  for (const ownership of coreOwnership) {
    assertExclusiveCallSites({
      sources: productionSources,
      name: ownership.name,
      expectedByFile: new Map([
        [ownership.owner, 1],
        [ownership.semantic, 1],
      ]),
      fail,
    });
  }

  const jwsSignPrimitive = readText("crates/jose/src/jws/sign_p256.rs");
  assertForbiddenTokens({
    source: jwsSignPrimitive,
    tokens: ["operation_contract", "JwsEs256Error", "JwsEddsaError"],
    label: "crates/jose/src/jws/sign_p256.rs",
    fail,
  });
  const jwsVerifyPrimitive = readText("crates/jose/src/jws/verify_p256.rs");
  assertForbiddenTokens({
    source: jwsVerifyPrimitive,
    tokens: ["operation_contract", "JwsEs256Error", "JwsEddsaError"],
    label: "crates/jose/src/jws/verify_p256.rs",
    fail,
  });
}
