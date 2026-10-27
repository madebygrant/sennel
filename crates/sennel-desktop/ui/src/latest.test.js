import assert from "node:assert/strict";
import { test } from "node:test";
import { latestOnly } from "./latest.js";

// Each call returns a promise the test settles by hand, so replies can arrive in any order.
function deferred() {
  const calls = [];
  const fn = latestOnly(() => new Promise((resolve, reject) => calls.push({ resolve, reject })));
  return { fn, calls };
}

test("a reply overtaken by a newer call resolves to null", async () => {
  const { fn, calls } = deferred();
  const first = fn();
  const second = fn();
  calls[1].resolve("new");
  calls[0].resolve("old");
  assert.equal(await second, "new");
  assert.equal(await first, null);
});

test("an overtaken failure is dropped, the newest failure is not", async () => {
  const { fn, calls } = deferred();
  const first = fn();
  const second = fn();
  calls[0].reject(new Error("old"));
  calls[1].reject(new Error("new"));
  assert.equal(await first, null);
  await assert.rejects(second, /new/);
});

test("a lone call passes its reply through", async () => {
  const { fn, calls } = deferred();
  const only = fn();
  calls[0].resolve(7);
  assert.equal(await only, 7);
});
