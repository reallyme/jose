// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

package me.really.jose;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;

import java.nio.charset.StandardCharsets;
import org.junit.jupiter.api.Test;

final class ReallyMeJoseJavaTest {
  @Test
  void typedFacadeIsUsableFromJava() {
    byte[] claims = "{\"sub\":\"stage-15-java\"}".getBytes(StandardCharsets.UTF_8);
    String compact = ReallyMeJose.encodeUnsignedJwt(claims);
    assertArrayEquals(claims, ReallyMeJose.decodeUnsignedJwt(compact));
  }
}
