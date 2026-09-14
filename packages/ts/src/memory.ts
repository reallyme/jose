// SPDX-FileCopyrightText: 2026 ReallyMe LLC
//
// SPDX-License-Identifier: MIT OR Apache-2.0

import { invalidInput } from "./validate.js";

/** Best-effort cleanup for caller-controlled mutable byte storage. */
export const bestEffortClear = (value: Uint8Array): void => {
  if (!(value instanceof Uint8Array)) return invalidInput();
  value.fill(0);
};
