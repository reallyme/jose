// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

package me.really.jose.consumer.r8;

import android.content.res.AssetManager;
import com.google.protobuf.ByteString;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Iterator;
import me.really.jose.ReallyMeJose;
import me.really.jose.ReallyMeJoseErrorBranch;
import me.really.jose.ReallyMeJoseErrorReason;
import me.really.jose.ReallyMeJoseException;
import me.really.jose.ReallyMeJoseJweContentEncryptionAlgorithm;
import me.really.jose.ReallyMeJoseJweKeyManagementAlgorithm;
import me.really.jose.ReallyMeJoseJwtTemporalPolicy;
import me.really.jose.ReallyMeJoseSignatureAlgorithm;
import me.really.jose.v1.JoseError;
import me.really.jose.v1.JoseJwsVerifyRequest;
import me.really.jose.v1.JoseJwtDecodeUnsignedRequest;
import me.really.jose.v1.JoseJwtTemporalValidationPolicy;
import me.really.jose.v1.JoseJwtVerifyRequest;
import me.really.jose.v1.JoseOperationRequest;
import me.really.jose.v1.JoseOperationResponse;
import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

/** Executes the audited cross-language corpus through the minified Android facade. */
final class AndroidConformanceVectorRunner {
  private static final int MAX_VECTOR_FILE_BYTES = 2 * 1024 * 1024;
  private static final int COPY_BUFFER_BYTES = 8192;

  private AndroidConformanceVectorRunner() {}

  static void run(AssetManager assets) {
    runSuite(assets, "jws-compact.json", AndroidConformanceVectorRunner::runJwsCase);
    runSuite(assets, "signed-jwt.json", AndroidConformanceVectorRunner::runSignedJwtCase);
    runSuite(assets, "unsigned-jwt.json", AndroidConformanceVectorRunner::runUnsignedJwtCase);
    runSuite(assets, "jwe-compact.json", AndroidConformanceVectorRunner::runJweCase);
    runSuite(assets, "panva-jose.json", AndroidConformanceVectorRunner::runPanvaCase);
    runWireCases(assets);
  }

  private static void runWireCases(AssetManager assets) {
    JSONObject unsigned = firstCase(assets, "unsigned-jwt.json");
    JSONObject signed = firstCase(assets, "signed-jwt.json");
    try {
      String compact = requiredString(unsigned, "compact");
      byte[] binary = JoseOperationRequest.newBuilder().setJwtDecodeUnsigned(
          JoseJwtDecodeUnsignedRequest.newBuilder().setCompact(compact)).build().toByteArray();
      byte[] json = ("{\"jwtDecodeUnsigned\":{\"compact\":\"" + compact + "\"}}")
          .getBytes(StandardCharsets.UTF_8);
      byte[] binaryResponse = ReallyMeJose.executeWireRequest(binary);
      byte[] jsonResponse = ReallyMeJose.executeWireJsonRequest(json);
      try {
        require(Arrays.equals(binaryResponse, jsonResponse));
      } finally {
        Arrays.fill(binary, (byte) 0);
        Arrays.fill(json, (byte) 0);
        Arrays.fill(binaryResponse, (byte) 0);
        Arrays.fill(jsonResponse, (byte) 0);
      }

      requireMalformedWireError(
          new byte[] {(byte) 0xff}, false,
          ReallyMeJoseErrorReason.COMMON_MALFORMED_PROTOBUF);
      requireMalformedWireError(
          "{\"jwtDecodeUnsigned\":".getBytes(StandardCharsets.UTF_8), true,
          ReallyMeJoseErrorReason.COMMON_MALFORMED_JSON);

      byte[] unsupportedRequest = JoseOperationRequest.newBuilder().setJwsVerify(
          JoseJwsVerifyRequest.newBuilder().setAlgorithmValue(999)).build().toByteArray();
      byte[] unsupportedResponse = ReallyMeJose.executeWireRequest(unsupportedRequest);
      try {
        JoseOperationResponse response = JoseOperationResponse.parseFrom(unsupportedResponse);
        require(response.getResponseCase() == JoseOperationResponse.ResponseCase.JWS_VERIFY);
        requireGeneratedError(
            response.getJwsVerify().getError(), ReallyMeJoseErrorBranch.PROVIDER,
            ReallyMeJoseErrorReason.PROVIDER_UNSUPPORTED);
      } catch (IOException failure) {
        throw invalidFixture(failure);
      } finally {
        Arrays.fill(unsupportedRequest, (byte) 0);
        Arrays.fill(unsupportedResponse, (byte) 0);
      }

      byte[] jwk = signed.getJSONObject("verification_jwk").toString()
          .getBytes(StandardCharsets.UTF_8);
      byte[] publicKey = decodeHex(requiredString(signed, "public_key_hex"));
      byte[] temporalRequest = JoseOperationRequest.newBuilder().setJwtVerify(
          JoseJwtVerifyRequest.newBuilder()
              .setCompact(requiredString(signed, "compact"))
              .setJwkJson(ByteString.copyFrom(jwk))
              .setPublicKey(ByteString.copyFrom(publicKey))
              .setTemporalPolicy(
                  JoseJwtTemporalValidationPolicy.newBuilder().setRequireExp(true)))
          .build().toByteArray();
      byte[] temporalResponse = ReallyMeJose.executeWireRequest(temporalRequest);
      try {
        JoseOperationResponse response = JoseOperationResponse.parseFrom(temporalResponse);
        require(response.getResponseCase() == JoseOperationResponse.ResponseCase.JWT_VERIFY);
        requireGeneratedError(
            response.getJwtVerify().getError(), ReallyMeJoseErrorBranch.PRIMITIVE,
            ReallyMeJoseErrorReason.JWT_INVALID_VERIFICATION_TIME);
      } catch (IOException failure) {
        throw invalidFixture(failure);
      } finally {
        Arrays.fill(jwk, (byte) 0);
        Arrays.fill(publicKey, (byte) 0);
        Arrays.fill(temporalRequest, (byte) 0);
        Arrays.fill(temporalResponse, (byte) 0);
      }
    } catch (JSONException failure) {
      throw invalidFixture(failure);
    }
  }

  private static JSONObject firstCase(AssetManager assets, String name) {
    byte[] encoded = readBoundedAsset(assets, name);
    try {
      JSONArray cases = new JSONObject(new String(encoded, StandardCharsets.UTF_8))
          .getJSONArray("cases");
      require(cases.length() > 0);
      return cases.getJSONObject(0);
    } catch (JSONException failure) {
      throw invalidFixture(failure);
    } finally {
      Arrays.fill(encoded, (byte) 0);
    }
  }

  private static void requireBoundaryError(
      byte[] responseBytes,
      ReallyMeJoseErrorReason reason) {
    try {
      JoseOperationResponse response = JoseOperationResponse.parseFrom(responseBytes);
      require(response.getResponseCase() == JoseOperationResponse.ResponseCase.BOUNDARY_ERROR);
      requireGeneratedError(response.getBoundaryError(), ReallyMeJoseErrorBranch.PRIMITIVE, reason);
    } catch (IOException failure) {
      throw invalidFixture(failure);
    } finally {
      Arrays.fill(responseBytes, (byte) 0);
    }
  }

  private static void requireMalformedWireError(
      byte[] request,
      boolean json,
      ReallyMeJoseErrorReason reason) {
    try {
      byte[] response = json
          ? ReallyMeJose.executeWireJsonRequest(request)
          : ReallyMeJose.executeWireRequest(request);
      requireBoundaryError(response, reason);
    } finally {
      Arrays.fill(request, (byte) 0);
    }
  }

  private static void requireGeneratedError(
      JoseError error,
      ReallyMeJoseErrorBranch branch,
      ReallyMeJoseErrorReason reason) {
    int actualReason = switch (error.getErrorCase()) {
      case PRIMITIVE -> {
        require(branch == ReallyMeJoseErrorBranch.PRIMITIVE);
        yield error.getPrimitive().getReasonValue();
      }
      case PROVIDER -> {
        require(branch == ReallyMeJoseErrorBranch.PROVIDER);
        yield error.getProvider().getReasonValue();
      }
      case BACKEND -> {
        require(branch == ReallyMeJoseErrorBranch.BACKEND);
        yield error.getBackend().getReasonValue();
      }
      default -> throw invalidFixture(null);
    };
    require(actualReason == reason.getCode());
  }

  private static void runSuite(AssetManager assets, String name, VectorOperation operation) {
    byte[] encoded = readBoundedAsset(assets, name);
    try {
      JSONObject root = new JSONObject(new String(encoded, StandardCharsets.UTF_8));
      JSONArray cases = root.getJSONArray("cases");
      require(cases.length() > 0);
      for (int index = 0; index < cases.length(); index += 1) {
        operation.run(cases.getJSONObject(index));
      }
    } catch (JSONException failure) {
      throw invalidFixture(failure);
    } finally {
      Arrays.fill(encoded, (byte) 0);
    }
  }

  private static void runPanvaCase(JSONObject vector) throws JSONException {
    switch (requiredString(vector, "format")) {
      case "jws-compact" -> runJwsCase(vector);
      case "jwt-compact", "signed-jwt" -> runSignedJwtCase(vector);
      case "jwe-compact" -> runJweCase(vector);
      default -> throw invalidFixture(null);
    }
  }

  private static void runJwsCase(JSONObject vector) throws JSONException {
    ReallyMeJoseSignatureAlgorithm algorithm = switch (requiredString(vector, "alg")) {
      case "EdDSA" -> ReallyMeJoseSignatureAlgorithm.ED_DSA;
      case "ES256" -> ReallyMeJoseSignatureAlgorithm.ES256;
      default -> throw invalidFixture(null);
    };
    byte[] publicKey = decodeHex(requiredString(vector, "public_key_hex"));
    try {
      if (vector.optBoolean("expected_valid", false)) {
        ReallyMeJose.verifyJws(algorithm, requiredString(vector, "compact"), publicKey);
      } else {
        expectFailure(expectedJwsReason(requiredString(vector, "expected_error")), () ->
            ReallyMeJose.verifyJws(algorithm, requiredString(vector, "compact"), publicKey));
      }
    } finally {
      Arrays.fill(publicKey, (byte) 0);
    }
  }

  private static void runSignedJwtCase(JSONObject vector) throws JSONException {
    byte[] publicKey = decodeHex(requiredString(vector, "public_key_hex"));
    byte[] jwk = vector.getJSONObject("verification_jwk").toString()
        .getBytes(StandardCharsets.UTF_8);
    try {
      ReallyMeJoseJwtTemporalPolicy temporalPolicy = null;
      if (vector.has("now_unix")) {
        require("strict".equals(vector.optString("temporal_policy", "strict")));
        temporalPolicy = new ReallyMeJoseJwtTemporalPolicy(
            true, false, false, 60L, 60L, vector.getLong("now_unix"),
            "did:me:verifier", null, null);
      }
      ReallyMeJoseJwtTemporalPolicy selectedPolicy = temporalPolicy;
      boolean signatureOnly = selectedPolicy == null;
      if (vector.has("expected_claims_json")) {
        byte[] actual = ReallyMeJose.verifyJwt(
            requiredString(vector, "compact"), jwk, publicKey, null,
            selectedPolicy, signatureOnly);
        try {
          requireJsonEquals(vector.getJSONObject("expected_claims_json"), actual);
        } finally {
          Arrays.fill(actual, (byte) 0);
        }
      } else {
        expectFailure(expectedJwtReason(requiredString(vector, "expected_error")), () -> {
          byte[] unexpected = ReallyMeJose.verifyJwt(
              requiredString(vector, "compact"), jwk, publicKey, null,
              selectedPolicy, signatureOnly);
          Arrays.fill(unexpected, (byte) 0);
        });
      }
    } finally {
      Arrays.fill(jwk, (byte) 0);
      Arrays.fill(publicKey, (byte) 0);
    }
  }

  private static void runUnsignedJwtCase(JSONObject vector) throws JSONException {
    if (vector.has("expected_claims_json")) {
      byte[] actual = ReallyMeJose.decodeUnsignedJwt(requiredString(vector, "compact"));
      try {
        requireJsonEquals(vector.getJSONObject("expected_claims_json"), actual);
      } finally {
        Arrays.fill(actual, (byte) 0);
      }
    } else {
      expectFailure(expectedJwtReason(requiredString(vector, "expected_error")), () -> {
        byte[] unexpected = ReallyMeJose.decodeUnsignedJwt(requiredString(vector, "compact"));
        Arrays.fill(unexpected, (byte) 0);
      });
    }
  }

  private static void runJweCase(JSONObject vector) throws JSONException {
    String keyHex = nullableString(vector, "recipient_private_key_hex");
    if (keyHex == null) keyHex = nullableString(vector, "cek_hex");
    if (keyHex == null) throw invalidFixture(null);
    byte[] key = decodeHex(keyHex);
    try {
      ReallyMeJoseJweKeyManagementAlgorithm keyManagement;
      if ("ECDH-ES".equals(requiredString(vector, "alg"))) {
        keyManagement = switch (key.length) {
          case 32 -> ReallyMeJoseJweKeyManagementAlgorithm.ECDH_ES_P256;
          case 48 -> ReallyMeJoseJweKeyManagementAlgorithm.ECDH_ES_P384;
          case 66 -> ReallyMeJoseJweKeyManagementAlgorithm.ECDH_ES_P521;
          default -> throw invalidFixture(null);
        };
      } else {
        keyManagement = ReallyMeJoseJweKeyManagementAlgorithm.DIRECT;
      }
      ReallyMeJoseJweContentEncryptionAlgorithm contentEncryption =
          switch (requiredString(vector, "enc")) {
            case "A192GCM" -> ReallyMeJoseJweContentEncryptionAlgorithm.A192_GCM;
            case "A256GCM" -> ReallyMeJoseJweContentEncryptionAlgorithm.A256_GCM;
            default -> ReallyMeJoseJweContentEncryptionAlgorithm.A128_GCM;
          };
      if (vector.has("expected_plaintext_json")) {
        byte[] actual = ReallyMeJose.decryptJwe(
            requiredString(vector, "compact"), keyManagement, contentEncryption, key, null);
        try {
          requireJsonEquals(vector.getJSONObject("expected_plaintext_json"), actual);
        } finally {
          Arrays.fill(actual, (byte) 0);
        }
      } else {
        expectFailure(expectedJweReason(requiredString(vector, "expected_error")), () -> {
          byte[] unexpected = ReallyMeJose.decryptJwe(
              requiredString(vector, "compact"), keyManagement, contentEncryption, key, null);
          Arrays.fill(unexpected, (byte) 0);
        });
      }
    } finally {
      Arrays.fill(key, (byte) 0);
    }
  }

  private static void expectFailure(ReallyMeJoseErrorReason reason, VectorAction operation) {
    try {
      operation.run();
      throw new IllegalStateException("expected typed JOSE vector failure");
    } catch (ReallyMeJoseException.JoseFailure failure) {
      require(failure.getBranch() == ReallyMeJoseErrorBranch.PRIMITIVE);
      require(failure.getReason() == reason);
    } catch (JSONException failure) {
      throw invalidFixture(failure);
    }
  }

  private static ReallyMeJoseErrorReason expectedJwsReason(String name) {
    return switch (name) {
      case "InvalidCompactEncoding" -> ReallyMeJoseErrorReason.JWS_INVALID_COMPACT;
      case "HeaderMismatch" -> ReallyMeJoseErrorReason.JWS_HEADER_MISMATCH;
      case "BadSignatureBase64" -> ReallyMeJoseErrorReason.JWS_BAD_SIGNATURE_BASE64;
      case "InvalidSignature" -> ReallyMeJoseErrorReason.JWS_INVALID_SIGNATURE;
      default -> throw invalidFixture(null);
    };
  }

  private static ReallyMeJoseErrorReason expectedJwtReason(String name) {
    String baseName = name.contains(":") ? name.substring(0, name.indexOf(':')) : name;
    return switch (baseName) {
      case "InvalidJwtFormat" -> ReallyMeJoseErrorReason.JWT_INVALID_COMPACT;
      case "InvalidHeader" -> ReallyMeJoseErrorReason.JWT_INVALID_HEADER;
      case "UnsupportedAlgorithm" -> ReallyMeJoseErrorReason.JWT_UNSUPPORTED_ALGORITHM;
      case "AlgorithmMismatch" -> ReallyMeJoseErrorReason.JWT_ALGORITHM_MISMATCH;
      case "KeyIdMismatch" -> ReallyMeJoseErrorReason.JWT_KID_POLICY_MISMATCH;
      case "InvalidSignature" -> ReallyMeJoseErrorReason.JWT_INVALID_SIGNATURE;
      case "MissingRequiredTemporalClaim" ->
          ReallyMeJoseErrorReason.JWT_MISSING_REQUIRED_TEMPORAL_CLAIM;
      case "InvalidTemporalClaimValue" ->
          ReallyMeJoseErrorReason.JWT_INVALID_TEMPORAL_CLAIM_VALUE;
      case "Expired" -> ReallyMeJoseErrorReason.JWT_EXPIRED;
      case "NotYetValid" -> ReallyMeJoseErrorReason.JWT_NOT_YET_VALID;
      case "IssuedAtInFuture" -> ReallyMeJoseErrorReason.JWT_ISSUED_AT_IN_FUTURE;
      default -> throw invalidFixture(null);
    };
  }

  private static ReallyMeJoseErrorReason expectedJweReason(String name) {
    return switch (name) {
      case "InvalidCompact" -> ReallyMeJoseErrorReason.JWE_INVALID_COMPACT;
      case "InvalidEncoding" -> ReallyMeJoseErrorReason.JWE_INVALID_ENCODING;
      case "InvalidHeader" -> ReallyMeJoseErrorReason.JWE_INVALID_HEADER;
      case "UnsupportedKeyManagementAlgorithm" ->
          ReallyMeJoseErrorReason.JWE_UNSUPPORTED_KEY_MANAGEMENT_ALGORITHM;
      case "UnsupportedContentEncryptionAlgorithm" ->
          ReallyMeJoseErrorReason.JWE_UNSUPPORTED_CONTENT_ENCRYPTION_ALGORITHM;
      case "MissingRequiredHeaderParameter" ->
          ReallyMeJoseErrorReason.JWE_MISSING_REQUIRED_HEADER_PARAMETER;
      case "HeaderPolicyMismatch" -> ReallyMeJoseErrorReason.JWE_HEADER_POLICY_MISMATCH;
      case "InvalidEncryptedKey" -> ReallyMeJoseErrorReason.JWE_INVALID_ENCRYPTED_KEY;
      case "InvalidContentEncryptionKey" ->
          ReallyMeJoseErrorReason.JWE_INVALID_CONTENT_ENCRYPTION_KEY;
      case "InvalidContentCipherInput" ->
          ReallyMeJoseErrorReason.JWE_INVALID_CONTENT_CIPHER_INPUT;
      case "Decrypt" -> ReallyMeJoseErrorReason.JWE_DECRYPT_FAILED;
      case "Encrypt" -> ReallyMeJoseErrorReason.JWE_ENCRYPT_FAILED;
      case "InvalidKeyAgreementKey" -> ReallyMeJoseErrorReason.JWE_INVALID_KEY_AGREEMENT_KEY;
      case "InvalidPayloadJson" -> ReallyMeJoseErrorReason.JWE_INVALID_PAYLOAD_JSON;
      default -> throw invalidFixture(null);
    };
  }

  private static byte[] readBoundedAsset(AssetManager assets, String name) {
    byte[] buffer = new byte[COPY_BUFFER_BYTES];
    try (InputStream input = assets.open(name);
         ByteArrayOutputStream output = new ByteArrayOutputStream()) {
      while (true) {
        int read = input.read(buffer);
        if (read < 0) break;
        int nextSize = Math.addExact(output.size(), read);
        if (nextSize > MAX_VECTOR_FILE_BYTES) throw invalidFixture(null);
        output.write(buffer, 0, read);
      }
      return output.toByteArray();
    } catch (IOException | ArithmeticException failure) {
      throw invalidFixture(failure);
    } finally {
      Arrays.fill(buffer, (byte) 0);
    }
  }

  private static void requireJsonEquals(JSONObject expected, byte[] actualBytes) {
    try {
      JSONObject actual = new JSONObject(new String(actualBytes, StandardCharsets.UTF_8));
      require(jsonEquals(expected, actual));
    } catch (JSONException failure) {
      throw invalidFixture(failure);
    }
  }

  private static boolean jsonEquals(Object left, Object right) throws JSONException {
    if (left instanceof JSONObject leftObject && right instanceof JSONObject rightObject) {
      if (leftObject.length() != rightObject.length()) return false;
      Iterator<String> keys = leftObject.keys();
      while (keys.hasNext()) {
        String key = keys.next();
        if (!rightObject.has(key) || !jsonEquals(leftObject.get(key), rightObject.get(key))) {
          return false;
        }
      }
      return true;
    }
    if (left instanceof JSONArray leftArray && right instanceof JSONArray rightArray) {
      if (leftArray.length() != rightArray.length()) return false;
      for (int index = 0; index < leftArray.length(); index += 1) {
        if (!jsonEquals(leftArray.get(index), rightArray.get(index))) return false;
      }
      return true;
    }
    if (left instanceof Number leftNumber && right instanceof Number rightNumber) {
      return Double.compare(leftNumber.doubleValue(), rightNumber.doubleValue()) == 0;
    }
    return left.equals(right);
  }

  private static String requiredString(JSONObject object, String field) throws JSONException {
    Object value = object.get(field);
    if (!(value instanceof String text)) throw invalidFixture(null);
    return text;
  }

  private static String nullableString(JSONObject object, String field) throws JSONException {
    if (!object.has(field) || object.isNull(field)) return null;
    return requiredString(object, field);
  }

  private static byte[] decodeHex(String value) {
    if (value.length() % 2 != 0) throw invalidFixture(null);
    byte[] result = new byte[value.length() / 2];
    try {
      for (int index = 0; index < result.length; index += 1) {
        int offset = Math.multiplyExact(index, 2);
        int high = Character.digit(value.charAt(offset), 16);
        int low = Character.digit(value.charAt(Math.addExact(offset, 1)), 16);
        if (high < 0 || low < 0) throw invalidFixture(null);
        result[index] = (byte) ((high << 4) | low);
      }
      return result;
    } catch (RuntimeException failure) {
      Arrays.fill(result, (byte) 0);
      throw failure;
    }
  }

  private static void require(boolean condition) {
    if (!condition) throw new IllegalStateException("conformance assertion failed");
  }

  private static IllegalStateException invalidFixture(Throwable cause) {
    return new IllegalStateException("invalid conformance fixture", cause);
  }

  @FunctionalInterface
  private interface VectorOperation {
    void run(JSONObject vector) throws JSONException;
  }

  @FunctionalInterface
  private interface VectorAction {
    void run() throws JSONException;
  }
}
