import { test } from "node:test";
import assert from "node:assert/strict";
import { hasKids, parentOf, visibleGroups } from "./tree.js";

const groups = [
  { id: "root", depth: 0 },
  { id: "work", depth: 1 },
  { id: "servers", depth: 2 },
  { id: "keys", depth: 3 },
  { id: "finance", depth: 1 },
];
const names = (folded) => visibleGroups(groups, new Set(folded)).map((at) => groups[at].id);

test("a fold hides everything under the group, however deep", () => {
  assert.deepEqual(names([]), ["root", "work", "servers", "keys", "finance"]);
  assert.deepEqual(names(["work"]), ["root", "work", "finance"]);
});

test("a fold inside a folded group stays hidden with it", () => {
  assert.deepEqual(names(["servers", "work"]), ["root", "work", "finance"]);
  assert.deepEqual(names(["servers"]), ["root", "work", "servers", "finance"]);
});

test("folding the root leaves only the root", () => {
  assert.deepEqual(names(["root"]), ["root"]);
});

test("only groups with deeper rows after them have children", () => {
  assert.equal(hasKids(groups, 1), true);
  assert.equal(hasKids(groups, 3), false);
  assert.equal(hasKids(groups, 4), false);
});

test("a group's parent is the nearest shallower row above it", () => {
  assert.equal(parentOf(groups, 3).id, "servers");
  assert.equal(parentOf(groups, 4).id, "root");
  assert.equal(parentOf(groups, 0), undefined);
});
