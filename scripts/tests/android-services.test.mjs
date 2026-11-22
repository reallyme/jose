// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

import assert from "node:assert/strict";
import test from "node:test";
import { waitForStableServices } from "../wait-android-services.mjs";

function fixture(observe) {
  let time = 0;
  return {
    options: {
      now: () => time,
      pause: async (milliseconds) => { time += milliseconds; },
      execute: (_adb, args, options) => {
        assert.ok(options.timeout > 0 && options.timeout <= 5_000);
        return observe(args, time);
      },
    },
    elapsed: () => time,
  };
}
const ready = (args, pid = "100") => ({ status: 0, stdout: args.includes("pidof") ? pid : "Service window: found" });
const input = { serial: "emulator-5554", adb: "adb" };

test("framework readiness requires twenty seconds of stable processes", async () => {
  const clock = fixture((args) => ready(args));
  assert.deepEqual(await waitForStableServices(input, clock.options), { kind: "ready" });
  assert.equal(clock.elapsed(), 20_000);
});

test("a compositor restart resets the stability interval", async () => {
  const clock = fixture((args, time) => ready(args, time < 10_000 ? "100" : "200"));
  assert.deepEqual(await waitForStableServices(input, clock.options), { kind: "ready" });
  assert.equal(clock.elapsed(), 30_000);
});

test("unavailable window service resets readiness despite successful ADB exit", async () => {
  const clock = fixture((args, time) => time === 10_000 && args.includes("window")
    ? { status: 0, stdout: "Service window: not found" } : ready(args));
  assert.deepEqual(await waitForStableServices(input, clock.options), { kind: "ready" });
  assert.equal(clock.elapsed(), 32_000);
});

for (const failure of [
  () => ({ status: 1, stdout: "" }),
  () => ({ status: 0, stdout: "100 200" }),
  (args, time) => ready(args, String(time + 1)),
  () => ({ status: null, error: { code: "ETIMEDOUT" }, stdout: "" }),
]) {
  test("unstable or malformed framework probes fail within the deadline", async () => {
    const clock = fixture(failure);
    assert.deepEqual(await waitForStableServices(input, clock.options), { kind: "timeout" });
    assert.equal(clock.elapsed(), 120_000);
  });
}

test("missing ADB fails without retrying", async () => {
  const clock = fixture(() => ({ error: { code: "ENOENT" } }));
  assert.deepEqual(await waitForStableServices(input, clock.options), { kind: "adb-unavailable" });
  assert.equal(clock.elapsed(), 0);
});

test("invalid serials and executable paths never reach ADB", async () => {
  const clock = fixture(() => assert.fail("unexpected execution"));
  for (const value of [{ ...input, serial: "-invalid" }, { ...input, adb: "" }, { ...input, serial: null }]) {
    assert.deepEqual(await waitForStableServices(value, clock.options), { kind: "invalid-input" });
  }
});
