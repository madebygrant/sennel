import { test } from "node:test";
import assert from "node:assert/strict";
import { strength, typedBits } from "./strength.js";

// The same table as `typed_entropy_matches_the_desktop_copy` in sennel-core's generator.rs.
const SHARED = [
  ["abcd", 18.801759],
  ["aB3!", 25.837726],
  ["a b", 17.101319],
  ["é", 6.643856],
  ["a🙂", 13.95456],
  ["Tr0ub4dor&3xkcd!", 103.350906],
];

test("gives the core's numbers for the shared table", () => {
  for (const [password, bits] of SHARED) {
    assert.ok(Math.abs(typedBits(password) - bits) < 1e-6, `${password}: ${typedBits(password)} != ${bits}`);
  }
  assert.equal(typedBits(""), 0);
});

test("uses the core's bands", () => {
  assert.deepEqual([39.9, 40, 60, 80].map(strength), ["weak", "fair", "good", "strong"]);
});
