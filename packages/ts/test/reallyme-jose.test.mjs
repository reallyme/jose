// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

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
import { JoseOperationResponseSchema, JoseOperationRequestSchema } from "../dist/proto.js";
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

  await suite.test("Buffer-backed provider results survive response cleanup", () => {
    for (const [operation, field, invoke] of [
      ["jwtDecodeUnsigned", "claimsJson", () => ReallyMeJose.decodeUnsignedJwt("a.b.")],
      ["jweDecrypt", "plaintext", () => ReallyMeJose.decryptJwe({
        compact: "a..b.c.d",
        keyManagementAlgorithm: JoseJweKeyManagementAlgorithm.DIRECT,
        contentEncryptionAlgorithm: JoseJweContentEncryptionAlgorithm.A128GCM,
        key: Buffer.alloc(16, 8),
      })],
    ]) {
      const expected = new Uint8Array([11, 22, 33]);
      let returned;
      const execute = () => {
        returned = Buffer.from(toBinary(JoseOperationResponseSchema, create(
          JoseOperationResponseSchema,
          { contractVersion: 1, response: { case: operation, value: {
            outcome: { case: "result", value: { [field]: expected } },
          } } },
        )));
        return returned;
      };
      installReallyMeJoseWasmProvider({ executeOperation: execute, executeOperationJson: execute });
      const actual = invoke();
      assert.deepEqual(actual, expected);
      assert.ok(returned.every((byte) => byte === 0));
      actual.fill(0);
    }
  });

  await suite.test("rejects unknown response fields at every contract layer", () => {
    for (const layer of ["response", "operation", "result", "error", "reason"]) {
      const message = create(JoseOperationResponseSchema, {
        contractVersion: 1,
        response: { case: "jwtDecodeUnsigned", value: { outcome: {
          case: "result", value: { claimsJson: new Uint8Array([123, 125]) },
        } } },
      });
      if (layer === "error" || layer === "reason") {
        message.response.value.outcome = {
          case: "error", value: {
            $typeName: "reallyme.jose.v1.JoseError",
            error: { case: "primitive", value: {
              $typeName: "reallyme.jose.v1.JosePrimitiveError", reason: JoseErrorReason.JWT_INVALID_COMPACT,
            } },
          },
        };
      }
      const outcome = message.response.value.outcome;
      const target = layer === "response" ? message
        : layer === "operation" ? message.response.value
        : layer === "reason" ? outcome.value.error.value
        : outcome.value;
      target.$unknown = [{ no: 127, wireType: 0, data: new Uint8Array([1]) }];
      const execute = () => toBinary(JoseOperationResponseSchema, message);
      installReallyMeJoseWasmProvider({ executeOperation: execute, executeOperationJson: execute });
      assert.throws(
        () => ReallyMeJose.decodeUnsignedJwt("a.b."),
        assertSdkError("malformed-provider-response"),
        layer,
      );
    }
  });

  await suite.test("clears earlier copies when later input validation fails", (context) => {
    const cleared = [];
    const fill = Uint8Array.prototype.fill;
    context.mock.method(Uint8Array.prototype, "fill", function (value, ...rest) {
      if (value === 0 && this.length > 0) cleared.push(this);
      return Reflect.apply(fill, this, [value, ...rest]);
    });
    const privateKey = Buffer.alloc(32, 9);
    const claims = Buffer.from("{}");
    const jwk = Buffer.from("{}");
    for (const [expectedCopies, invoke] of [
      [1, () => ReallyMeJose.signJws({ algorithm: JoseSignatureAlgorithm.EDDSA, privateKey, payload: null })],
      [3, () => ReallyMeJose.signJwt({ claimsJson: claims, jwkJson: jwk, privateKey, type: 123 })],
      [2, () => ReallyMeJose.encryptJwe({
        keyManagementAlgorithm: JoseJweKeyManagementAlgorithm.DIRECT,
        contentEncryptionAlgorithm: JoseJweContentEncryptionAlgorithm.A128GCM,
        key: privateKey, plaintext: claims, agreementPartyUInfo: [],
      })],
      [1, () => ReallyMeJose.decryptJwe({
        compact: "a..b.c.d",
        keyManagementAlgorithm: JoseJweKeyManagementAlgorithm.DIRECT,
        contentEncryptionAlgorithm: JoseJweContentEncryptionAlgorithm.A128GCM,
        key: privateKey, headerPolicy: { expectedAgreementPartyUInfo: [] },
      })],
    ]) {
      cleared.length = 0;
      assert.throws(invoke, assertSdkError("invalid-input"));
      assert.equal(cleared.length, expectedCopies);
      assert.ok(cleared.every((bytes) => bytes.every((byte) => byte === 0)));
      assert.ok(privateKey.every((byte) => byte === 9));
      assert.equal(claims.toString(), "{}");
      assert.equal(jwk.toString(), "{}");
    }
  });

  const wasm = await initializeWasmProvider();
  installReallyMeJoseWasmProvider(wasm);

  await suite.test("Buffer inputs retain caller ownership through signing and encryption", () => {
    const key = Buffer.alloc(16, 8);
    const plaintext = Buffer.from("caller-owned plaintext");
    const compact = ReallyMeJose.encryptJwe({
      keyManagementAlgorithm: JoseJweKeyManagementAlgorithm.DIRECT,
      contentEncryptionAlgorithm: JoseJweContentEncryptionAlgorithm.A128GCM,
      key, plaintext,
    });
    assert.ok(key.every((byte) => byte === 8));
    assert.equal(plaintext.toString(), "caller-owned plaintext");
    const decrypted = ReallyMeJose.decryptJwe({
      compact,
      keyManagementAlgorithm: JoseJweKeyManagementAlgorithm.DIRECT,
      contentEncryptionAlgorithm: JoseJweContentEncryptionAlgorithm.A128GCM,
      key,
    });
    assert.deepEqual(decrypted, new Uint8Array(plaintext));
    const privateKey = Buffer.alloc(32, 9);
    ReallyMeJose.signJws({ algorithm: JoseSignatureAlgorithm.EDDSA, privateKey, payload: plaintext });
    assert.ok(privateKey.every((byte) => byte === 9));
    assert.equal(plaintext.toString(), "caller-owned plaintext");
    for (const value of [key, plaintext, decrypted, privateKey]) value.fill(0);
  });

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
      assertSdkError("jose-failure", JoseErrorReason.JWT_INVALID_COMPACT),
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

  await suite.test("malformed option and policy objects return typed input errors", () => {
    for (const options of [null, undefined, [], "invalid"]) {
      for (const method of ["signJws", "verifyJws", "signJwt", "verifyJwt", "encryptJwe", "decryptJwe"]) {
        assert.throws(() => ReallyMeJose[method](options), assertSdkError("invalid-input"));
      }
    }
    for (const headerPolicy of [null, [], { acceptedTypes: "JWT" }]) {
      assert.throws(() => ReallyMeJose.verifyJwt({
        compact: "a.b.c", jwkJson: new Uint8Array(), publicKey: new Uint8Array(), headerPolicy,
      }), assertSdkError("invalid-input"));
    }
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
