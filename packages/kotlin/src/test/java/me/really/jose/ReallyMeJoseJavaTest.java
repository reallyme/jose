// SPDX-FileCopyrightText: 2026 ReallyMe LLC
//
// SPDX-License-Identifier: MIT OR Apache-2.0

package me.really.jose;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.charset.StandardCharsets;
import org.junit.jupiter.api.Test;

final class ReallyMeJoseJavaTest {
  @Test
  void preCompressionHeaderPolicyConstructorRemainsAvailable() {
    try (ReallyMeJoseJweHeaderPolicy policy =
        new ReallyMeJoseJweHeaderPolicy(false, null, null, null, null, null)) {
      assertTrue(policy.getAllowedCompressionAlgorithms().isEmpty());
    }
  }

  @Test
  void typedFacadeIsUsableFromJava() {
    byte[] claims = "{\"sub\":\"stage-15-java\"}".getBytes(StandardCharsets.UTF_8);
    String compact = ReallyMeJose.encodeUnsignedJwt(claims);
    assertArrayEquals(claims, ReallyMeJose.decodeUnsignedJwt(compact));
  }
}
