// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

import type { JoseErrorReason, JoseSdkErrorCode } from "./proto/generated/reallyme/jose/v1/jose_pb.js";
import { errorBranch, ReallyMeJoseSdkErrorCode, sdkErrorSchemaCodes } from "./proto/contract-values.js";
import type { ReallyMeJoseErrorBranch } from "./proto/contract-values.js";
export { ReallyMeJoseSdkErrorCode } from "./proto/contract-values.js";
export type { ReallyMeJoseErrorBranch } from "./proto/contract-values.js";

/** Audit-safe SDK error. It never retains caller input or backend text. */
export class ReallyMeJoseError extends Error {
  readonly code: ReallyMeJoseSdkErrorCode;
  /** Stable error code defined in the protobuf contract. */
  readonly schemaCode: JoseSdkErrorCode;
  readonly branch: ReallyMeJoseErrorBranch | undefined;
  readonly reason: JoseErrorReason | undefined;

  constructor(
    code: ReallyMeJoseSdkErrorCode,
    branch?: ReallyMeJoseErrorBranch,
    reason?: JoseErrorReason,
  ) {
    const knownCode = typeof code === "string" && Object.hasOwn(sdkErrorSchemaCodes, code);
    const requestedCode = knownCode ? code : ReallyMeJoseSdkErrorCode.INVALID_INPUT;
    const validReason = requestedCode === ReallyMeJoseSdkErrorCode.JOSE_FAILURE
      && branch !== undefined && reason !== undefined && errorBranch(reason) === branch;
    const safeCode = requestedCode === ReallyMeJoseSdkErrorCode.JOSE_FAILURE && !validReason
      ? ReallyMeJoseSdkErrorCode.MALFORMED_PROVIDER_RESPONSE
      : requestedCode;
    super(safeCode === ReallyMeJoseSdkErrorCode.JOSE_FAILURE ? "JOSE operation failed" : safeCode);
    this.name = "ReallyMeJoseError";
    this.code = safeCode;
    this.schemaCode = sdkErrorSchemaCodes[safeCode];
    this.branch = validReason ? branch : undefined;
    this.reason = validReason ? reason : undefined;
  }
}
