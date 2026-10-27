import assert from "node:assert/strict";
import { test } from "node:test";
import { groupCells, looksLikePassphrase } from "./cells.js";

test("a password is one unbroken run", () => {
  assert.deepEqual(groupCells([..."abcdefghijk"], false), [[0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10]]);
});

test("a passphrase splits on its dashes and leaves them out", () => {
  assert.deepEqual(groupCells([..."ab-cde-f"], true), [[0, 1], [3, 4, 5], [7]]);
  assert.deepEqual(groupCells([..."word"], true), [[0, 1, 2, 3]]);
});

test("a dash in a password is just a character", () => {
  assert.deepEqual(groupCells([..."a-b"], false), [[0, 1, 2]]);
});

test("a passphrase is told from its shape", () => {
  assert.ok(looksLikePassphrase("tidal-ozone-crisp"));
  assert.ok(looksLikePassphrase("ab-cd"));
  for (const not of ["tidal", "Tidal-ozone", "x7-Rq", "tidal-ozone-", "-tidal-ozone", "tidal--ozone", "", null]) {
    assert.equal(looksLikePassphrase(not), false, String(not));
  }
});
