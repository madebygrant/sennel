import { test } from "node:test";
import assert from "node:assert/strict";
import { copyFor, entryHints } from "./entrykeys.js";

test("an env entry copies its .env on p and passes the other keys on", () => {
  const env = { env: true, hasOtp: false, url: "" };
  assert.equal(copyFor("p", env), "env");
  for (const k of ["y", "U", "t"]) assert.equal(copyFor(k, env), null, k);
});

test("a login copies each field, and passes on a code or website it lacks", () => {
  const login = { env: false, hasOtp: false, url: "" };
  assert.equal(copyFor("p", login), "password");
  assert.equal(copyFor("y", login), "username");
  assert.equal(copyFor("t", login), null);
  assert.equal(copyFor("U", login), null);
  assert.equal(copyFor("t", { ...login, hasOtp: true }), "otp");
  assert.equal(copyFor("U", { ...login, url: "x.example" }), "url");
});

test("the footer offers what the keys do", () => {
  assert.deepEqual(entryHints({ env: true }).map(([k]) => k), ["p", "e", "/"]);
  assert.deepEqual(entryHints({ env: false, hasOtp: true }).map(([k]) => k), ["p", "y", "t", "e", "/"]);
});
