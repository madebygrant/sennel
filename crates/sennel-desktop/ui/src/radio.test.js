import { test } from "node:test";
import assert from "node:assert/strict";
import { radioKeys } from "./radio.js";

function press(key, current, values = ["a", "b", "c"]) {
  const focused = [];
  let picked = null;
  let prevented = false;
  const event = {
    key,
    preventDefault: () => (prevented = true),
    currentTarget: { querySelectorAll: () => values.map((v) => ({ focus: () => focused.push(v) })) },
  };
  radioKeys(event, values, current, (v) => (picked = v));
  return { picked, focused, prevented };
}

test("arrows step through the group and wrap at both ends", () => {
  assert.deepEqual(press("ArrowRight", "a"), { picked: "b", focused: ["b"], prevented: true });
  assert.equal(press("ArrowDown", "c").picked, "a");
  assert.equal(press("ArrowLeft", "a").picked, "c");
  assert.equal(press("ArrowUp", "b").picked, "a");
});

test("with nothing checked an arrow picks the first", () => {
  assert.equal(press("ArrowRight", null).picked, "a");
});

test("other keys pass through untouched", () => {
  assert.deepEqual(press("Enter", "a"), { picked: null, focused: [], prevented: false });
});
