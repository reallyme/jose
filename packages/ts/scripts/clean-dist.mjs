// SPDX-FileCopyrightText: 2026 ReallyMe LLC
//
// SPDX-License-Identifier: MIT OR Apache-2.0

import { rmSync } from "node:fs";
import { resolve } from "node:path";
import { fileURLToPath } from "node:url";

const packageDirectory = resolve(fileURLToPath(new URL("..", import.meta.url)));
rmSync(resolve(packageDirectory, "dist"), { force: true, recursive: true });
