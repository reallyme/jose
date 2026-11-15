// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

import { ReallyMeJoseError, ReallyMeJoseSdkErrorCode } from "./errors.js";

type OperationFunction = (request: Uint8Array) => unknown;

export type ReallyMeJoseWasmProvider = Readonly<{
  executeOperation: OperationFunction;
  executeOperationJson: OperationFunction;
}>;

let installedProvider: ReallyMeJoseWasmProvider | undefined;

const requireObject = (value: unknown): object => {
  if (typeof value !== "object" || value === null) {
    throw new ReallyMeJoseError(ReallyMeJoseSdkErrorCode.PROVIDER_FAILURE);
  }
  return value;
};

const requireFunction = (module: object, name: string): OperationFunction => {
  let value: unknown;
  try {
    value = Reflect.get(module, name);
  } catch (_error: unknown) {
    throw new ReallyMeJoseError(ReallyMeJoseSdkErrorCode.PROVIDER_FAILURE);
  }
  if (typeof value !== "function") {
    throw new ReallyMeJoseError(ReallyMeJoseSdkErrorCode.PROVIDER_FAILURE);
  }
  return (request: Uint8Array): unknown => {
    try {
      return Reflect.apply(value, undefined, [request]);
    } catch (_error: unknown) {
      throw new ReallyMeJoseError(ReallyMeJoseSdkErrorCode.PROVIDER_FAILURE);
    }
  };
};

export const createReallyMeJoseWasmProvider = (
  module: unknown,
): ReallyMeJoseWasmProvider => {
  const object = requireObject(module);
  return Object.freeze({
    executeOperation: requireFunction(object, "executeOperation"),
    executeOperationJson: requireFunction(object, "executeOperationJson"),
  });
};

export const installReallyMeJoseWasmProvider = (module: unknown): void => {
  installedProvider = createReallyMeJoseWasmProvider(module);
};

export const requireReallyMeJoseWasmProvider = (): ReallyMeJoseWasmProvider => {
  if (installedProvider === undefined) {
    throw new ReallyMeJoseError(ReallyMeJoseSdkErrorCode.PROVIDER_NOT_INSTALLED);
  }
  return installedProvider;
};
