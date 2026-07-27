// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

export type ReallyMeJoseWasmInitOutput = Readonly<{ memory: unknown }>;

export declare function initSync(module: { module: Uint8Array }): ReallyMeJoseWasmInitOutput;
export declare function executeOperation(request: Uint8Array): Uint8Array;
export declare function executeOperationJson(request: Uint8Array): Uint8Array;
