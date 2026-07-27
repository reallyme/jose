// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { dirname, resolve } from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

import {
  installReallyMeJoseWasmProvider,
  JoseErrorReason,
  JoseJweContentEncryptionAlgorithm,
  JoseJweKeyManagementAlgorithm,
  JoseSignatureAlgorithm,
  ReallyMeJose,
  ReallyMeJoseError,
} from "../dist/index.js";
import { initializeWasmProvider } from "./wasm-provider-module.mjs";

const testDirectory = dirname(fileURLToPath(import.meta.url));
const vectorDirectory = resolve(testDirectory, "..", "..", "..", "vectors");
const textEncoder = new TextEncoder();
const textDecoder = new TextDecoder("utf-8", { fatal: true });

const requireRecord = (value) => {
  assert.equal(typeof value, "object");
  assert.notEqual(value, null);
  assert.equal(Array.isArray(value), false);
  return value;
};

const requireString = (record, name) => {
  const value = record[name];
  assert.equal(typeof value, "string", `${name} must be a string`);
  return value;
};

const optionalRecord = (record, name) => {
  const value = record[name];
  return value === undefined ? undefined : requireRecord(value);
};

const loadCases = async (filename) => {
  const bytes = await readFile(resolve(vectorDirectory, filename), "utf8");
  const root = requireRecord(JSON.parse(bytes));
  assert.ok(Array.isArray(root.cases));
  return root.cases.map(requireRecord);
};

const bytesFromHex = (hex) => {
  assert.match(hex, /^(?:[0-9a-f]{2})*$/u);
  return Uint8Array.from(Buffer.from(hex, "hex"));
};

const assertJsonBytesEqual = (actual, expected) => {
  try {
    assert.deepEqual(JSON.parse(textDecoder.decode(actual)), expected);
  } finally {
    actual.fill(0);
  }
};

const expectedJwsReasons = new Map([
  ["InvalidCompactEncoding", JoseErrorReason.JWS_INVALID_COMPACT],
  ["HeaderMismatch", JoseErrorReason.JWS_HEADER_MISMATCH],
  ["BadSignatureBase64", JoseErrorReason.JWS_BAD_SIGNATURE_BASE64],
  ["InvalidSignature", JoseErrorReason.JWS_INVALID_SIGNATURE],
]);

const expectedJwtReasons = new Map([
  ["InvalidJwtFormat", JoseErrorReason.JWT_INVALID_COMPACT],
  ["InvalidHeader", JoseErrorReason.JWT_INVALID_HEADER],
  ["UnsupportedAlgorithm", JoseErrorReason.JWT_UNSUPPORTED_ALGORITHM],
  ["AlgorithmMismatch", JoseErrorReason.JWT_ALGORITHM_MISMATCH],
  ["KeyIdMismatch", JoseErrorReason.JWT_KID_POLICY_MISMATCH],
  ["InvalidSignature", JoseErrorReason.JWT_INVALID_SIGNATURE],
  ["MissingRequiredTemporalClaim", JoseErrorReason.JWT_MISSING_REQUIRED_TEMPORAL_CLAIM],
  ["InvalidTemporalClaimValue", JoseErrorReason.JWT_INVALID_TEMPORAL_CLAIM_VALUE],
  ["Expired", JoseErrorReason.JWT_EXPIRED],
  ["NotYetValid", JoseErrorReason.JWT_NOT_YET_VALID],
  ["IssuedAtInFuture", JoseErrorReason.JWT_ISSUED_AT_IN_FUTURE],
]);

const expectedJweReasons = new Map([
  ["InvalidCompact", JoseErrorReason.JWE_INVALID_COMPACT],
  ["InvalidEncoding", JoseErrorReason.JWE_INVALID_ENCODING],
  ["InvalidHeader", JoseErrorReason.JWE_INVALID_HEADER],
  ["UnsupportedKeyManagementAlgorithm", JoseErrorReason.JWE_UNSUPPORTED_KEY_MANAGEMENT_ALGORITHM],
  ["UnsupportedContentEncryptionAlgorithm", JoseErrorReason.JWE_UNSUPPORTED_CONTENT_ENCRYPTION_ALGORITHM],
  ["MissingRequiredHeaderParameter", JoseErrorReason.JWE_MISSING_REQUIRED_HEADER_PARAMETER],
  ["HeaderPolicyMismatch", JoseErrorReason.JWE_HEADER_POLICY_MISMATCH],
  ["InvalidEncryptedKey", JoseErrorReason.JWE_INVALID_ENCRYPTED_KEY],
  ["InvalidContentEncryptionKey", JoseErrorReason.JWE_INVALID_CONTENT_ENCRYPTION_KEY],
  ["InvalidContentCipherInput", JoseErrorReason.JWE_INVALID_CONTENT_CIPHER_INPUT],
  ["Decrypt", JoseErrorReason.JWE_DECRYPT_FAILED],
  ["Encrypt", JoseErrorReason.JWE_ENCRYPT_FAILED],
  ["InvalidKeyAgreementKey", JoseErrorReason.JWE_INVALID_KEY_AGREEMENT_KEY],
  ["InvalidPayloadJson", JoseErrorReason.JWE_INVALID_PAYLOAD_JSON],
]);

const wasmUnsupportedVectorIds = new Set([
  "reallyme-jwe/ecdh-es-p384-a192gcm-json",
  "reallyme-jwe/ecdh-es-p521-a256gcm-json",
]);

const assertVectorError = (operation, reason, branch = "primitive") => {
  assert.notEqual(reason, undefined, "vector expected an unmapped error reason");
  assert.throws(operation, (error) => {
    assert.ok(error instanceof ReallyMeJoseError);
    assert.equal(error.code, "jose-failure");
    assert.equal(error.branch, branch);
    assert.equal(error.reason, reason);
    return true;
  });
};

const signatureAlgorithm = (name) => {
  if (name === "EdDSA") return JoseSignatureAlgorithm.EDDSA;
  assert.equal(name, "ES256");
  return JoseSignatureAlgorithm.ES256;
};

const runJwsCase = (vector) => {
  const publicKey = bytesFromHex(requireString(vector, "public_key_hex"));
  try {
    const operation = () => ReallyMeJose.verifyJws({
      algorithm: signatureAlgorithm(requireString(vector, "alg")),
      compact: requireString(vector, "compact"),
      publicKey,
    });
    if (vector.expected_valid === true) {
      operation();
    } else {
      assertVectorError(operation, expectedJwsReasons.get(requireString(vector, "expected_error")));
    }
  } finally {
    publicKey.fill(0);
  }
};

const runUnsignedJwtCase = (vector) => {
  const operation = () => ReallyMeJose.decodeUnsignedJwt(requireString(vector, "compact"));
  const expected = optionalRecord(vector, "expected_claims_json");
  if (expected !== undefined) {
    assertJsonBytesEqual(operation(), expected);
  } else {
    const name = requireString(vector, "expected_error").split(":", 1)[0];
    assertVectorError(operation, expectedJwtReasons.get(name));
  }
};

const runSignedJwtCase = (vector) => {
  const publicKey = bytesFromHex(requireString(vector, "public_key_hex"));
  const jwk = textEncoder.encode(JSON.stringify(requireRecord(vector.verification_jwk)));
  const now = vector.now_unix;
  if (now !== undefined) {
    assert.ok(Number.isSafeInteger(now));
    assert.ok(now > 0);
    assert.equal(vector.temporal_policy ?? "strict", "strict");
  }
  const temporalPolicy = now === undefined
    ? undefined
    : {
        requireExpiration: true,
        requireNotBefore: false,
        requireIssuedAt: false,
        clockSkewSeconds: 60n,
        maximumFutureIssuedAtSkewSeconds: 60n,
        verificationTimeUnixSeconds: BigInt(now),
        expectedAudience: "did:me:verifier",
      };
  try {
    const operation = () => ReallyMeJose.verifyJwt({
      compact: requireString(vector, "compact"),
      jwkJson: jwk,
      publicKey,
      temporalPolicy,
      signatureOnly: temporalPolicy === undefined,
    });
    const expected = optionalRecord(vector, "expected_claims_json");
    if (expected !== undefined) {
      assertJsonBytesEqual(operation(), expected);
    } else {
      const name = requireString(vector, "expected_error").split(":", 1)[0];
      assertVectorError(operation, expectedJwtReasons.get(name));
    }
  } finally {
    publicKey.fill(0);
    jwk.fill(0);
  }
};

const contentEncryptionAlgorithm = (name) => {
  if (name === "A192GCM") return JoseJweContentEncryptionAlgorithm.A192GCM;
  if (name === "A256GCM") return JoseJweContentEncryptionAlgorithm.A256GCM;
  return JoseJweContentEncryptionAlgorithm.A128GCM;
};

const runJweCase = (vector) => {
  const keyHex = vector.recipient_private_key_hex ?? vector.cek_hex;
  assert.equal(typeof keyHex, "string");
  const key = bytesFromHex(keyHex);
  const keyManagementAlgorithm = vector.alg === "ECDH-ES"
    ? new Map([
        [32, JoseJweKeyManagementAlgorithm.ECDH_ES_P256],
        [48, JoseJweKeyManagementAlgorithm.ECDH_ES_P384],
        [66, JoseJweKeyManagementAlgorithm.ECDH_ES_P521],
      ]).get(key.length)
    : JoseJweKeyManagementAlgorithm.DIRECT;
  assert.notEqual(keyManagementAlgorithm, undefined);
  try {
    const operation = () => ReallyMeJose.decryptJwe({
      compact: requireString(vector, "compact"),
      keyManagementAlgorithm,
      contentEncryptionAlgorithm: contentEncryptionAlgorithm(requireString(vector, "enc")),
      key,
    });
    const expected = optionalRecord(vector, "expected_plaintext_json");
    if (wasmUnsupportedVectorIds.has(requireString(vector, "id"))) {
      assertVectorError(operation, JoseErrorReason.PROVIDER_UNSUPPORTED, "provider");
    } else if (expected !== undefined) {
      assertJsonBytesEqual(operation(), expected);
    } else {
      assertVectorError(
        operation,
        expectedJweReasons.get(requireString(vector, "expected_error")),
      );
    }
  } finally {
    key.fill(0);
  }
};

test("TypeScript/WASM executes all 96 cross-lane conformance vectors", async (suite) => {
  installReallyMeJoseWasmProvider(await initializeWasmProvider());

  const jwsCases = await loadCases("jws-compact.json");
  const unsignedJwtCases = await loadCases("unsigned-jwt.json");
  const signedJwtCases = await loadCases("signed-jwt.json");
  const jweCases = await loadCases("jwe-compact.json");
  const panvaCases = await loadCases("panva-jose.json");
  assert.equal(
    jwsCases.length + unsignedJwtCases.length + signedJwtCases.length + jweCases.length + panvaCases.length,
    96,
  );

  await suite.test("JWS corpus", () => {
    for (const vector of jwsCases) runJwsCase(vector);
    for (const vector of panvaCases.filter((candidate) => candidate.format === "jws-compact")) {
      runJwsCase(vector);
    }
  });
  await suite.test("unsigned JWT corpus", () => {
    for (const vector of unsignedJwtCases) runUnsignedJwtCase(vector);
  });
  await suite.test("signed JWT corpus", () => {
    for (const vector of signedJwtCases) runSignedJwtCase(vector);
    for (const vector of panvaCases.filter((candidate) => candidate.format === "jwt-compact")) {
      runSignedJwtCase(vector);
    }
  });
  await suite.test("JWE corpus", () => {
    for (const vector of jweCases) runJweCase(vector);
    for (const vector of panvaCases.filter((candidate) => candidate.format === "jwe-compact")) {
      runJweCase(vector);
    }
  });
});
