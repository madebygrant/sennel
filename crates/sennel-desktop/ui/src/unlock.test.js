import { test } from "node:test";
import assert from "node:assert/strict";
import { fits, pathNote } from "./unlock.js";

const at = (kind, more = {}) => ({ kind, full: "/v/work.kdbx", makes: null, kdbx: true, ...more });

test("open mode takes only an existing file, new mode only a free path", () => {
  assert.ok(fits("open", "vault") && !fits("open", "new"));
  assert.ok(fits("new", "new") && !fits("new", "vault"));
  for (const kind of ["empty", "folder", "blocked", "unreadable", "other-home"]) {
    assert.ok(!fits("open", kind) && !fits("new", kind), kind);
  }
});

test("a missing file in open mode offers to create it instead of creating it", () => {
  assert.deepEqual(pathNote("open", at("new")), {
    level: "warn",
    text: "No vault at /v/work.kdbx.",
    action: { label: "Create one here", to: "new" },
  });
});

test("an existing file in new mode offers to open it", () => {
  const note = pathNote("new", at("vault"));
  assert.equal(note.text, "work.kdbx already exists.");
  assert.deepEqual(note.action, { label: "Open it", to: "open" });
});

test("a new path names the folder it makes and a name that is not .kdbx", () => {
  const plain = pathNote("new", at("new"));
  assert.equal(plain.text, "Creates /v/work.kdbx.");
  assert.equal(plain.warn, null);
  const odd = pathNote("new", at("new", { full: "/v/a/notes.txt", makes: "/v/a", kdbx: false }));
  assert.equal(odd.text, "Creates /v/a/notes.txt, and the folder it goes in.");
  assert.match(odd.warn, /\.kdbx/);
});

test("an existing vault in open mode needs no note, and the problems are errors", () => {
  assert.equal(pathNote("open", at("vault")), null);
  assert.equal(pathNote("open", at("folder", { full: "/v" })).level, "warn");
  for (const kind of ["blocked", "unreadable", "other-home"]) assert.equal(pathNote("new", at(kind)).level, "error", kind);
  assert.equal(pathNote("new", null).level, "dim");
});
