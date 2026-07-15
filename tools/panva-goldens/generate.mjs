#!/usr/bin/env node
// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

import { createECDH, createHash } from "node:crypto";
import { mkdir, writeFile } from "node:fs/promises";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { CompactEncrypt, CompactSign, SignJWT, importJWK } from "jose";

const source = "panva/jose@6.2.3";
const payloadUtf8 = "reallyme-panva-interop";
const claims = {
  iss: "panva",
  sub: "reallyme-interop",
  aud: "reallyme-jose",
  iat: 1_700_000_000,
};

const root = resolve(fileURLToPath(new URL("../..", import.meta.url)));
const outputPath = resolve(root, "conformance/vectors/panva-jose.json");

function base64url(bytes) {
  return Buffer.from(bytes).toString("base64url");
}

function hexToBytes(hex) {
  if (hex.length % 2 !== 0) {
    throw new TypeError("odd-length hex");
  }
  return Uint8Array.from(Buffer.from(hex, "hex"));
}

function ecP256Jwk(privateHex, kid, alg) {
  const privateKey = hexToBytes(privateHex);
  const ecdh = createECDH("prime256v1");
  ecdh.setPrivateKey(privateKey);
  const publicKey = ecdh.getPublicKey(undefined, "uncompressed");
  return {
    kty: "EC",
    crv: "P-256",
    kid,
    alg,
    x: base64url(publicKey.subarray(1, 33)),
    y: base64url(publicKey.subarray(33, 65)),
    d: base64url(privateKey),
  };
}

function okpEd25519Jwk(seedHex, publicHex, kid) {
  return {
    kty: "OKP",
    crv: "Ed25519",
    kid,
    alg: "EdDSA",
    x: base64url(hexToBytes(publicHex)),
    d: base64url(hexToBytes(seedHex)),
  };
}

function publicEcSec1Hex(jwk) {
  const x = Buffer.from(jwk.x, "base64url");
  const y = Buffer.from(jwk.y, "base64url");
  return Buffer.concat([Buffer.from([0x04]), x, y]).toString("hex");
}

function publicEcP256CompressedHex(privateHex) {
  const ecdh = createECDH("prime256v1");
  ecdh.setPrivateKey(hexToBytes(privateHex));
  return ecdh.getPublicKey(undefined, "compressed").toString("hex");
}

function u32be(value) {
  const out = Buffer.alloc(4);
  out.writeUInt32BE(value, 0);
  return out;
}

function lengthPrefixed(bytes) {
  return Buffer.concat([u32be(bytes.length), Buffer.from(bytes)]);
}

function cekLengthBits(enc) {
  switch (enc) {
    case "A128GCM":
      return 128;
    case "A192GCM":
      return 192;
    case "A256GCM":
      return 256;
    default:
      throw new TypeError(`unsupported JWE content encryption algorithm: ${enc}`);
  }
}

function p256SharedSecret(privateHex, epk) {
  const ecdh = createECDH("prime256v1");
  ecdh.setPrivateKey(hexToBytes(privateHex));
  const publicKey = Buffer.concat([
    Buffer.from([0x04]),
    Buffer.from(epk.x, "base64url"),
    Buffer.from(epk.y, "base64url"),
  ]);
  return ecdh.computeSecret(publicKey);
}

function concatKdfAesGcmCek(secret, protectedHeader) {
  const enc = Buffer.from(protectedHeader.enc, "ascii");
  const apu = Buffer.from(protectedHeader.apu ?? "", "base64url");
  const apv = Buffer.from(protectedHeader.apv ?? "", "base64url");
  const keyDataLenBits = cekLengthBits(protectedHeader.enc);
  const otherInfo = Buffer.concat([
    lengthPrefixed(enc),
    lengthPrefixed(apu),
    lengthPrefixed(apv),
    u32be(keyDataLenBits),
  ]);
  return createHash("sha256")
    .update(u32be(1))
    .update(secret)
    .update(otherInfo)
    .digest()
    .subarray(0, keyDataLenBits / 8);
}

const es256Jwk = ecP256Jwk(
  "0000000000000000000000000000000000000000000000000000000000000011",
  "panva-es256",
  "ES256",
);
const p256JweRecipientJwk = ecP256Jwk(
  "0000000000000000000000000000000000000000000000000000000000000005",
  "panva-p256-ecdh",
  "ECDH-ES",
);
const eddsaJwk = okpEd25519Jwk(
  "0909090909090909090909090909090909090909090909090909090909090909",
  "fd1724385aa0c75b64fb78cd602fa1d991fdebf76b13c58ed702eac835e9f618",
  "panva-eddsa",
);

const es256PrivateKey = await importJWK(es256Jwk, "ES256");
const eddsaPrivateKey = await importJWK(eddsaJwk, "EdDSA");
const jwePublicKey = await importJWK(
  {
    kty: p256JweRecipientJwk.kty,
    crv: p256JweRecipientJwk.crv,
    kid: p256JweRecipientJwk.kid,
    alg: p256JweRecipientJwk.alg,
    x: p256JweRecipientJwk.x,
    y: p256JweRecipientJwk.y,
  },
  "ECDH-ES",
);

const es256Jws = await new CompactSign(Buffer.from(payloadUtf8, "utf8"))
  .setProtectedHeader({ alg: "ES256", kid: es256Jwk.kid })
  .sign(es256PrivateKey);
const eddsaJws = await new CompactSign(Buffer.from(payloadUtf8, "utf8"))
  .setProtectedHeader({ alg: "EdDSA", kid: eddsaJwk.kid })
  .sign(eddsaPrivateKey);
const es256Jwt = await new SignJWT(claims)
  .setProtectedHeader({ alg: "ES256", typ: "JWT", kid: es256Jwk.kid })
  .sign(es256PrivateKey);
const jwePlaintext = Buffer.from(
  JSON.stringify({ source: "panva", kind: "ecdh-es" }),
  "utf8",
);
const p256Jwe = await new CompactEncrypt(jwePlaintext)
  .setProtectedHeader({
    alg: "ECDH-ES",
    enc: "A128GCM",
    kid: p256JweRecipientJwk.kid,
  })
  .setKeyManagementParameters({
    apu: Buffer.from("wallet", "utf8"),
    apv: Buffer.from("issuer", "utf8"),
  })
  .encrypt(jwePublicKey);
const p256JweProtectedHeader = JSON.parse(
  Buffer.from(p256Jwe.split(".")[0], "base64url").toString("utf8"),
);
const p256JweSharedSecret = p256SharedSecret(
  "0000000000000000000000000000000000000000000000000000000000000005",
  p256JweProtectedHeader.epk,
);
const p256JweDerivedCek = concatKdfAesGcmCek(
  p256JweSharedSecret,
  p256JweProtectedHeader,
);

const suite = {
  schema: "reallyme.identity.conformance.vectors.v1",
  suite: "panva-jose",
  source,
  note:
    "Independent positive interop vectors generated by panva/jose. Tokens are consumed statically by Rust tests; Node is only a maintenance generator.",
  cases: [
    {
      id: "panva-jose/jws-es256-verify",
      source,
      format: "jws-compact",
      alg: "ES256",
      compact: es256Jws,
      payload_utf8: payloadUtf8,
      public_key_hex: publicEcP256CompressedHex(
        "0000000000000000000000000000000000000000000000000000000000000011",
      ),
      expected_valid: true,
    },
    {
      id: "panva-jose/jws-eddsa-verify",
      source,
      format: "jws-compact",
      alg: "EdDSA",
      compact: eddsaJws,
      payload_utf8: payloadUtf8,
      public_key_hex: Buffer.from(eddsaJwk.x, "base64url").toString("hex"),
      expected_valid: true,
    },
    {
      id: "panva-jose/jwt-es256-verify",
      source,
      format: "jwt-compact",
      alg: "ES256",
      compact: es256Jwt,
      public_key_hex: publicEcP256CompressedHex(
        "0000000000000000000000000000000000000000000000000000000000000011",
      ),
      verification_jwk: {
        kty: es256Jwk.kty,
        crv: es256Jwk.crv,
        kid: es256Jwk.kid,
        alg: es256Jwk.alg,
        x: es256Jwk.x,
        y: es256Jwk.y,
      },
      expected_claims_json: claims,
    },
    {
      id: "panva-jose/jwe-ecdh-es-p256-a128gcm",
      source,
      format: "jwe-compact",
      alg: "ECDH-ES",
      enc: "A128GCM",
      protected_header: p256JweProtectedHeader,
      compact: p256Jwe,
      plaintext_json_utf8: jwePlaintext.toString("utf8"),
      expected_plaintext_json: JSON.parse(jwePlaintext.toString("utf8")),
      recipient_private_key_hex:
        "0000000000000000000000000000000000000000000000000000000000000005",
      recipient_public_key_sec1_hex: publicEcP256CompressedHex(
        "0000000000000000000000000000000000000000000000000000000000000005",
      ),
      derived_cek_hex: p256JweDerivedCek.toString("hex"),
    },
  ],
};

await mkdir(dirname(outputPath), { recursive: true });
await writeFile(outputPath, `${JSON.stringify(suite, null, 2)}\n`);
console.log(`wrote ${outputPath}`);
