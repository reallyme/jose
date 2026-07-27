// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

import assert from "node:assert/strict";
import test from "node:test";

import { create, toBinary, toJsonString } from "@bufbuild/protobuf";
import {
  bestEffortClear,
  executeOperation,
  executeOperationJson,
  installReallyMeJoseWasmProvider,
  JoseErrorReason,
  JoseJweContentEncryptionAlgorithm,
  JoseJweKeyManagementAlgorithm,
  JoseSignatureAlgorithm,
  ReallyMeJose,
  ReallyMeJoseError,
} from "../dist/index.js";
import { JoseOperationRequestSchema } from "../dist/proto.js";
import { initializeWasmProvider } from "./wasm-provider-module.mjs";

const textEncoder = new TextEncoder();
const textDecoder = new TextDecoder("utf-8", { fatal: true });

const fromHex = (hex) => Uint8Array.from(Buffer.from(hex, "hex"));
const assertSdkError = (expectedCode, expectedReason) => (error) => {
  assert.ok(error instanceof ReallyMeJoseError);
  assert.equal(error.code, expectedCode);
  if (expectedReason !== undefined) assert.equal(error.reason, expectedReason);
  return true;
};

test("production WASM provider and TypeScript facade", async (suite) => {
  await suite.test("fails closed before provider installation", () => {
    assert.throws(
      () => ReallyMeJose.encodeUnsignedJwt(textEncoder.encode("{}")),
      assertSdkError("provider-not-installed"),
    );
  });

  await suite.test("rejects malformed, oversized, and aliased provider boundaries", () => {
    assert.throws(
      () => installReallyMeJoseWasmProvider(Object.create(null)),
      assertSdkError("provider-failure"),
    );

    let providerCalls = 0;
    installReallyMeJoseWasmProvider({
      executeOperation(request) {
        providerCalls += 1;
        return request;
      },
      executeOperationJson(request) {
        providerCalls += 1;
        return request;
      },
    });
    assert.throws(
      () => executeOperation(new Uint8Array(1_048_577)),
      assertSdkError("invalid-input"),
    );
    assert.equal(providerCalls, 0);
    assert.throws(
      () => executeOperation(new Uint8Array([1])),
      assertSdkError("provider-failure"),
    );
    assert.equal(providerCalls, 1);

    installReallyMeJoseWasmProvider({
      executeOperation() {
        return new Uint8Array([0]);
      },
      executeOperationJson() {
        return new Uint8Array([0]);
      },
    });
    assert.throws(
      () => ReallyMeJose.encodeUnsignedJwt(textEncoder.encode("{}")),
      assertSdkError("malformed-provider-response"),
    );
  });

  const wasm = await initializeWasmProvider();
  installReallyMeJoseWasmProvider(wasm);

  await suite.test("binary and ProtoJSON routes produce the same canonical response", () => {
    const request = create(JoseOperationRequestSchema, {
      operation: {
        case: "jwtDecodeUnsigned",
        value: {
          compact:
            "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiJ0eXBlc2NyaXB0In0.",
        },
      },
    });
    const binaryRequest = toBinary(JoseOperationRequestSchema, request);
    const jsonRequest = textEncoder.encode(toJsonString(JoseOperationRequestSchema, request));
    const binaryResponse = executeOperation(binaryRequest);
    const jsonResponse = executeOperationJson(jsonRequest);
    try {
      assert.deepEqual(jsonResponse, binaryResponse);
    } finally {
      binaryRequest.fill(0);
      jsonRequest.fill(0);
      binaryResponse.fill(0);
      jsonResponse.fill(0);
    }
  });

  await suite.test("JWS signs, verifies, and returns a stable typed tamper error", () => {
    const privateKey = fromHex("09".repeat(32));
    const publicKey = fromHex(
      "fd1724385aa0c75b64fb78cd602fa1d991fdebf76b13c58ed702eac835e9f618",
    );
    const payload = textEncoder.encode("reallyme-typescript-jws");
    const compact = ReallyMeJose.signJws({
      algorithm: JoseSignatureAlgorithm.EDDSA,
      privateKey,
      payload,
    });
    ReallyMeJose.verifyJws({
      algorithm: JoseSignatureAlgorithm.EDDSA,
      compact,
      publicKey,
    });
    const tampered = compact.replace(/\.[^.]+$/, ".AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA");
    assert.throws(
      () => ReallyMeJose.verifyJws({
        algorithm: JoseSignatureAlgorithm.EDDSA,
        compact: tampered,
        publicKey,
      }),
      assertSdkError("jose-failure", JoseErrorReason.JWS_INVALID_SIGNATURE),
    );
    assert.ok(privateKey.some((value) => value !== 0));
    privateKey.fill(0);
    publicKey.fill(0);
    payload.fill(0);
  });

  await suite.test("unsigned JWT encodes, decodes, and rejects a signed-path token", () => {
    const claims = textEncoder.encode('{"iss":"did:me:issuer","sub":"typescript"}');
    const compact = ReallyMeJose.encodeUnsignedJwt(claims);
    const decoded = ReallyMeJose.decodeUnsignedJwt(compact);
    assert.deepEqual(decoded, claims);
    assert.throws(
      () => ReallyMeJose.decodeUnsignedJwt(`${compact}AAAA`),
      assertSdkError("jose-failure", JoseErrorReason.JWT_INVALID_FORMAT),
    );
    claims.fill(0);
    decoded.fill(0);
  });

  await suite.test("signed JWT round-trips through explicit signature-only policy", () => {
    const privateKey = fromHex("09".repeat(32));
    const publicKey = fromHex(
      "fd1724385aa0c75b64fb78cd602fa1d991fdebf76b13c58ed702eac835e9f618",
    );
    const claims = textEncoder.encode('{"sub":"reallyme-typescript-signed"}');
    const jwk = textEncoder.encode(
      '{"alg":"EdDSA","crv":"Ed25519","kid":"k-ed","kty":"OKP","use":"sig","x":"_RckOFqgx1tk-3jNYC-h2ZH96_drE8WO1wLqyDXp9hg"}',
    );
    const compact = ReallyMeJose.signJwt({ claimsJson: claims, jwkJson: jwk, privateKey });
    const verified = ReallyMeJose.verifyJwt({
      compact,
      jwkJson: jwk,
      publicKey,
      signatureOnly: true,
    });
    assert.deepEqual(verified, claims);
    privateKey.fill(0);
    publicKey.fill(0);
    claims.fill(0);
    jwk.fill(0);
    verified.fill(0);
  });

  await suite.test("direct JWE round-trips and fails closed on a tampered tag", () => {
    const key = new Uint8Array(16).fill(8);
    const plaintext = textEncoder.encode("reallyme-typescript-jwe");
    const compact = ReallyMeJose.encryptJwe({
      keyManagementAlgorithm: JoseJweKeyManagementAlgorithm.DIRECT,
      contentEncryptionAlgorithm: JoseJweContentEncryptionAlgorithm.A128GCM,
      key,
      plaintext,
      keyIdentifier: "typescript-key",
    });
    const decrypted = ReallyMeJose.decryptJwe({
      compact,
      keyManagementAlgorithm: JoseJweKeyManagementAlgorithm.DIRECT,
      contentEncryptionAlgorithm: JoseJweContentEncryptionAlgorithm.A128GCM,
      key,
      headerPolicy: {
        requireKeyIdentifier: true,
        expectedKeyIdentifier: "typescript-key",
      },
    });
    assert.equal(textDecoder.decode(decrypted), "reallyme-typescript-jwe");
    const parts = compact.split(".");
    assert.equal(parts.length, 5);
    parts[4] = "AAAAAAAAAAAAAAAAAAAAAA";
    assert.throws(
      () => ReallyMeJose.decryptJwe({
        compact: parts.join("."),
        keyManagementAlgorithm: JoseJweKeyManagementAlgorithm.DIRECT,
        contentEncryptionAlgorithm: JoseJweContentEncryptionAlgorithm.A128GCM,
        key,
      }),
      assertSdkError("jose-failure", JoseErrorReason.JWE_DECRYPT_FAILED),
    );
    key.fill(0);
    plaintext.fill(0);
    decrypted.fill(0);
  });

  await suite.test("runtime enum and temporal-policy validation reject malicious JS input", () => {
    assert.throws(
      () => ReallyMeJose.verifyJws({
        algorithm: 999,
        compact: "a.b.c",
        publicKey: new Uint8Array(),
      }),
      assertSdkError("invalid-input"),
    );
    assert.throws(
      () => ReallyMeJose.verifyJwt({
        compact: "a.b.c",
        jwkJson: new Uint8Array(),
        publicKey: new Uint8Array(),
        temporalPolicy: {
          verificationTimeUnixSeconds: 0n,
          expectedAudience: "required-audience",
        },
      }),
      assertSdkError("invalid-input"),
    );
    assert.throws(() => bestEffortClear([]), assertSdkError("invalid-input"));
    const bytes = new Uint8Array([1, 2, 3]);
    bestEffortClear(bytes);
    assert.deepEqual(bytes, new Uint8Array(3));
  });
});
