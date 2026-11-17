import { test } from "node:test";
import assert from "node:assert/strict";
import { fillable, samePage } from "./page.js";

test("a tab that navigated or changed is not the page the logins were for (R2)", () => {
  const asked = { id: 7, url: "https://site.example/login" };
  assert.equal(samePage(asked, { id: 7, url: "https://site.example/login" }), true);
  assert.equal(samePage(asked, { id: 7, url: "https://evil.example/login" }), false);
  assert.equal(samePage(asked, { id: 8, url: "https://site.example/login" }), false);
  assert.equal(samePage(null, asked), false);
  // The same page with a new query or fragment is still the page.
  assert.equal(samePage(asked, { id: 7, url: "https://site.example/login?next=%2F#step2" }), true);
  assert.equal(samePage(asked, { id: 7, url: "https://site.example/other" }), false);
  assert.equal(samePage(asked, { id: 7, url: "http://site.example/login" }), false);
});

test("only web pages are filled", () => {
  assert.equal(fillable("https://site.example/"), true);
  assert.equal(fillable("http://router.local/"), true);
  for (const url of ["chrome://settings", "about:addons", "file:///etc/passwd", "chrome-extension://x/popup.html", "nonsense"]) {
    assert.equal(fillable(url), false, url);
  }
});
