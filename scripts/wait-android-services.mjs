#!/usr/bin/env node
// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

import { spawnSync } from "node:child_process";
import { setTimeout as sleep } from "node:timers/promises";
import { pathToFileURL } from "node:url";

const STABILITY_MS = 20_000;
const DEADLINE_MS = 120_000;
const POLL_MS = 2_000;
const PROBE_TIMEOUT_MS = 5_000;
const SERIAL = /^[A-Za-z0-9][A-Za-z0-9_.:\[\]-]{0,127}$/u;

// Boot-completed and service registration can survive a framework restart.
// Require both processes to remain unchanged while window service is usable.
export async function waitForStableServices({ serial, adb }, {
  execute = spawnSync,
  now = () => performance.now(),
  pause = sleep,
} = {}) {
  if (typeof serial !== "string" || !SERIAL.test(serial) ||
      typeof adb !== "string" || adb.length === 0 || adb.includes("\0")) {
    return { kind: "invalid-input" };
  }
  const deadline = now() + DEADLINE_MS;
  let identity;
  let stableSince;
  while (now() < deadline) {
    const values = [];
    for (const args of [
      ["shell", "pidof", "system_server"],
      ["shell", "pidof", "surfaceflinger"],
      ["shell", "service", "check", "window"],
    ]) {
      const remaining = deadline - now();
      if (remaining <= 0) return { kind: "timeout" };
      const result = execute(adb, ["-s", serial, ...args], {
        encoding: "utf8", timeout: Math.min(PROBE_TIMEOUT_MS, Math.ceil(remaining)),
        killSignal: "SIGKILL", maxBuffer: 4_096, stdio: ["ignore", "pipe", "pipe"],
      });
      if (["ENOENT", "EACCES", "EPERM"].includes(result.error?.code)) {
        return { kind: "adb-unavailable" };
      }
      values.push(result.error === undefined && result.status === 0 ? result.stdout.trim() : "");
    }
    const ready = /^[1-9][0-9]*$/u.test(values[0]) && /^[1-9][0-9]*$/u.test(values[1]) &&
      values[2] === "Service window: found";
    const observed = ready ? `${values[0]}:${values[1]}` : undefined;
    if (!ready || observed !== identity) {
      identity = observed;
      stableSince = ready ? now() : undefined;
    }
    if (stableSince !== undefined && now() - stableSince >= STABILITY_MS && now() <= deadline) {
      return { kind: "ready" };
    }
    const remaining = deadline - now();
    if (remaining > 0) await pause(Math.min(POLL_MS, remaining));
  }
  return { kind: "timeout" };
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  const result = process.argv.length === 3
    ? await waitForStableServices({ serial: process.argv[2], adb: process.env.ADB })
    : { kind: "invalid-input" };
  if (result.kind === "ready") {
    console.log("Android framework processes are stable.");
  } else {
    console.error(`Android framework stability check failed: ${result.kind}.`);
    process.exitCode = result.kind === "timeout" ? 75 : 1;
  }
}
