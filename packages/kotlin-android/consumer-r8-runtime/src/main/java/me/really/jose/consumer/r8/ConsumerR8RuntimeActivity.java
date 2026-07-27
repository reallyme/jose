// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

package me.really.jose.consumer.r8;

import android.app.Activity;
import android.os.Bundle;
import android.util.Log;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import me.really.jose.ReallyMeJose;
import me.really.jose.ReallyMeJoseErrorBranch;
import me.really.jose.ReallyMeJoseErrorReason;
import me.really.jose.ReallyMeJoseException;
import me.really.jose.ReallyMeJoseJweContentEncryptionAlgorithm;
import me.really.jose.ReallyMeJoseJweHeaderPolicy;
import me.really.jose.ReallyMeJoseJweKeyManagementAlgorithm;
import me.really.jose.ReallyMeJoseSignatureAlgorithm;

/** Release-only consumer fixture proving JNI and generated types survive R8. */
public final class ConsumerR8RuntimeActivity extends Activity {
  public static final String RESULT_TAG = "ReallyMeJoseR8Gate";
  public static final String RESULT_PASS = "PASS";
  public static final String RESULT_FAIL = "FAIL";

  private static final String KNOWN_COMPACT =
      "eyJhbGciOiJFZERTQSJ9.cmVhbGx5bWUtY29uZm9ybWFuY2UtY2lk."
          + "V-aqJPOjWYJ7P8hK-oyiqUsjO1kjXPsUp7YbXcTu2oXEJtElJoidqgSomnnsVBdING1fzza_rZwkdaE1RRYGDg";
  private static final String PUBLIC_KEY_HEX =
      "fd1724385aa0c75b64fb78cd602fa1d991fdebf76b13c58ed702eac835e9f618";

  @Override
  protected void onCreate(Bundle savedInstanceState) {
    super.onCreate(savedInstanceState);
    try {
      runGate();
      AndroidConformanceVectorRunner.run(getAssets());
      Log.i(RESULT_TAG, RESULT_PASS);
    } catch (RuntimeException failure) {
      // SDK failures are deliberately redacted; never attach operation inputs.
      Log.e(RESULT_TAG, RESULT_FAIL, failure);
    } finally {
      finish();
    }
  }

  private static void runGate() {
    byte[] publicKey = decodeHex(PUBLIC_KEY_HEX);
    try {
      ReallyMeJose.verifyJws(ReallyMeJoseSignatureAlgorithm.ED_DSA, KNOWN_COMPACT, publicKey);
      requireTypedInvalidSignature(publicKey);
    } finally {
      Arrays.fill(publicKey, (byte) 0);
    }

    byte[] claims = "{\"sub\":\"stage-16-android\"}".getBytes(StandardCharsets.UTF_8);
    String unsigned = ReallyMeJose.encodeUnsignedJwt(claims);
    byte[] decodedClaims = ReallyMeJose.decodeUnsignedJwt(unsigned);
    requireArrayEquals("unsigned JWT", claims, decodedClaims);

    byte[] key = new byte[16];
    Arrays.fill(key, (byte) 8);
    byte[] plaintext = "stage-16 plaintext".getBytes(StandardCharsets.UTF_8);
    byte[] decrypted = null;
    try (ReallyMeJoseJweHeaderPolicy policy = new ReallyMeJoseJweHeaderPolicy(
        true, "stage-16", null, null, null, null)) {
      String compact = ReallyMeJose.encryptJwe(
          ReallyMeJoseJweKeyManagementAlgorithm.DIRECT,
          ReallyMeJoseJweContentEncryptionAlgorithm.A128_GCM,
          key,
          plaintext,
          "stage-16");
      decrypted = ReallyMeJose.decryptJwe(
          compact,
          ReallyMeJoseJweKeyManagementAlgorithm.DIRECT,
          ReallyMeJoseJweContentEncryptionAlgorithm.A128_GCM,
          key,
          policy);
      requireArrayEquals("direct JWE", plaintext, decrypted);
    } finally {
      Arrays.fill(claims, (byte) 0);
      Arrays.fill(decodedClaims, (byte) 0);
      Arrays.fill(key, (byte) 0);
      Arrays.fill(plaintext, (byte) 0);
      if (decrypted != null) {
        Arrays.fill(decrypted, (byte) 0);
      }
    }
  }

  private static void requireTypedInvalidSignature(byte[] publicKey) {
    try {
      ReallyMeJose.verifyJws(
          ReallyMeJoseSignatureAlgorithm.ED_DSA,
          KNOWN_COMPACT.replace("V-aq", "A-aq"),
          publicKey);
      throw new IllegalStateException("typed invalid-signature failure was not returned");
    } catch (ReallyMeJoseException.JoseFailure failure) {
      if (failure.getBranch() != ReallyMeJoseErrorBranch.PRIMITIVE
          || failure.getReason() != ReallyMeJoseErrorReason.JWS_INVALID_SIGNATURE) {
        throw new IllegalStateException("unexpected typed failure");
      }
    }
  }

  private static byte[] decodeHex(String value) {
    byte[] result = new byte[value.length() / 2];
    for (int index = 0; index < result.length; index += 1) {
      int offset = index * 2;
      result[index] = (byte) Integer.parseInt(value.substring(offset, offset + 2), 16);
    }
    return result;
  }

  private static void requireArrayEquals(String label, byte[] expected, byte[] actual) {
    if (!Arrays.equals(expected, actual)) {
      throw new IllegalStateException(label);
    }
  }
}
