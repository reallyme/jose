// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

// Derived from the protobuf contract. Change the schema and regenerate.

import type { ReallyMeJoseJwtClaimsPolicy } from "./facade.js";

export type ReallyMeJoseJwtVerification =
  | Readonly<{ mode: "signatureOnly" }>
  | Readonly<{ mode: "claims"; policy: ReallyMeJoseJwtClaimsPolicy }>
  | Readonly<{ mode: "temporalOnly"; policy: ReallyMeJoseJwtTemporalPolicy }>;

export type ReallyMeJoseJwtTemporalPolicy = Readonly<{
  requireExpiration?: boolean;
  requireNotBefore?: boolean;
  requireIssuedAt?: boolean;
  clockSkewSeconds?: bigint;
  maximumFutureIssuedAtSkewSeconds?: bigint;
  verificationTimeUnixSeconds: bigint;
}>;
