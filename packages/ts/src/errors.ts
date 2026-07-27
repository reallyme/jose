// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

import type { JoseErrorReason } from "./proto/generated/reallyme/jose/v1/jose_pb.js";

export type ReallyMeJoseSdkErrorCode =
  | "invalid-input"
  | "provider-not-installed"
  | "provider-failure"
  | "malformed-provider-response"
  | "jose-failure";

export type ReallyMeJoseErrorBranch = "primitive" | "provider" | "backend";

/** Audit-safe SDK error. It never retains caller input or backend text. */
export class ReallyMeJoseError extends Error {
  readonly code: ReallyMeJoseSdkErrorCode;
  readonly branch: ReallyMeJoseErrorBranch | undefined;
  readonly reason: JoseErrorReason | undefined;

  constructor(
    code: ReallyMeJoseSdkErrorCode,
    branch?: ReallyMeJoseErrorBranch,
    reason?: JoseErrorReason,
  ) {
    super(code === "jose-failure" ? "JOSE operation failed" : code);
    this.name = "ReallyMeJoseError";
    this.code = code;
    this.branch = branch;
    this.reason = reason;
  }
}
