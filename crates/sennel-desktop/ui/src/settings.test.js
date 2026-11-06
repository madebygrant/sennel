import { test } from "node:test";
import assert from "node:assert/strict";
import { CLIPBOARD_PRESETS, LOCK_PRESETS, choices, spell } from "./settings.js";

test("timeouts read in whole units, and zero reads as never", () => {
  assert.equal(spell(0), "Never");
  assert.equal(spell(60), "1 minute");
  assert.equal(spell(300), "5 minutes");
  assert.equal(spell(3600), "1 hour");
  assert.equal(spell(7200), "2 hours");
  assert.equal(spell(90), "90 seconds");
});

test("a timeout from the config file that is no preset still gets a choice, in order", () => {
  assert.deepEqual(choices(LOCK_PRESETS, 300), LOCK_PRESETS);
  assert.deepEqual(choices(LOCK_PRESETS, 90), [60, 90, 120, 300, 600, 900, 1800, 3600, 0]);
  assert.deepEqual(choices(LOCK_PRESETS, 7200), [60, 120, 300, 600, 900, 1800, 3600, 7200, 0]);
  assert.deepEqual(choices(CLIPBOARD_PRESETS, 5), [5, 10, 15, 20, 30, 45, 60, 90, 120, 0]);
});
