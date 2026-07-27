// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

import { ReallyMeJoseError } from "./errors.js";

type OperationFunction = (request: Uint8Array) => unknown;

export type ReallyMeJoseWasmProvider = Readonly<{
  executeOperation: OperationFunction;
  executeOperationJson: OperationFunction;
}>;

let installedProvider: ReallyMeJoseWasmProvider | undefined;

const requireObject = (value: unknown): object => {
  if (typeof value !== "object" || value === null) {
    throw new ReallyMeJoseError("provider-failure");
  }
  return value;
};

const requireFunction = (module: object, name: string): OperationFunction => {
  const value: unknown = Reflect.get(module, name);
  if (typeof value !== "function") {
    throw new ReallyMeJoseError("provider-failure");
  }
  return (request: Uint8Array): unknown => {
    try {
      return Reflect.apply(value, undefined, [request]);
    } catch (_error: unknown) {
      throw new ReallyMeJoseError("provider-failure");
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
    throw new ReallyMeJoseError("provider-not-installed");
  }
  return installedProvider;
};
