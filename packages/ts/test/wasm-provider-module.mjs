// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

import { readFile } from "node:fs/promises";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import * as wasm from "../dist/wasm/reallyme_jose_wasm.js";

const testDirectory = dirname(fileURLToPath(import.meta.url));

export const initializeWasmProvider = async () => {
  const bytes = await readFile(
    resolve(testDirectory, "..", "dist", "wasm", "reallyme_jose_wasm_bg.wasm"),
  );
  wasm.initSync({ module: bytes });
  return wasm;
};
