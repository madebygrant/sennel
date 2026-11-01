import assert from "node:assert/strict";
import { test } from "node:test";
import { resized, restyled } from "./picks.js";

const style = { upper: true, digits: true, symbols: false, noLookalikes: false };
const chosen = { kind: "complex", sizes: { complex: 20 }, bounds: { complex: [8, 128] }, style };

test("a size step moves within the bounds", () => {
  assert.deepEqual(resized(chosen, 1), ["complex", 21]);
  assert.deepEqual(resized(chosen, -1), ["complex", 19]);
});

test("a size step past a bound clamps to it", () => {
  assert.deepEqual(resized({ ...chosen, sizes: { complex: 9 } }, -5), ["complex", 8]);
});

test("a size step at a bound asks for nothing", () => {
  assert.equal(resized({ ...chosen, sizes: { complex: 128 } }, 1), null);
  assert.equal(resized({ ...chosen, sizes: { complex: 8 } }, -1), null);
});

test("no size step before the first reply gives the bounds", () => {
  assert.equal(resized({ ...chosen, bounds: {} }, 1), null);
  assert.equal(resized({ kind: null, sizes: {}, bounds: {}, style: null }, 1), null);
});

test("a character toggle flips one class and keeps the rest", () => {
  assert.deepEqual(restyled(chosen, "symbols"), ["complex", undefined, { ...style, symbols: true }]);
  assert.equal(chosen.style.symbols, false);
});

test("character toggles only apply to complex passwords", () => {
  assert.equal(restyled({ ...chosen, kind: "pin" }, "digits"), null);
  assert.equal(restyled({ ...chosen, style: null }, "digits"), null);
});
