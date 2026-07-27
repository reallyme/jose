// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

export { executeOperation, executeOperationJson } from "./boundary.js";
export { ReallyMeJoseError } from "./errors.js";
export type {
  ReallyMeJoseErrorBranch,
  ReallyMeJoseSdkErrorCode,
} from "./errors.js";
export { ReallyMeJose } from "./facade.js";
export type {
  ReallyMeJoseDecryptJweOptions,
  ReallyMeJoseEncryptJweOptions,
  ReallyMeJoseJweHeaderPolicy,
  ReallyMeJoseJwtHeaderPolicy,
  ReallyMeJoseJwtTemporalPolicy,
  ReallyMeJoseSignJwsOptions,
  ReallyMeJoseSignJwtOptions,
  ReallyMeJoseVerifyJwsOptions,
  ReallyMeJoseVerifyJwtOptions,
} from "./facade.js";
export { bestEffortClear } from "./memory.js";
export {
  createReallyMeJoseWasmProvider,
  installReallyMeJoseWasmProvider,
} from "./provider.js";
export type { ReallyMeJoseWasmProvider } from "./provider.js";
export {
  JoseErrorReason,
  JoseJweContentEncryptionAlgorithm,
  JoseJweKeyManagementAlgorithm,
  JoseSignatureAlgorithm,
} from "./proto/generated/reallyme/jose/v1/jose_pb.js";
