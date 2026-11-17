// Loads public/content.js the way the browser injects it, into a scope with a fake page.
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import vm from "node:vm";

const source = readFileSync(new URL("../public/content.js", import.meta.url), "utf8");

// A fake input: where it is, how it is styled, and its chain of parents.
function page(fields) {
  const win = { innerWidth: 1000, innerHeight: 800, location: { href: "https://site.example/login" } };
  const els = fields.map((f, i) => {
    const parent = { style: f.parent ?? {}, parentElement: null, contains: () => false };
    const el = {
      tagName: "INPUT",
      type: f.type ?? "text",
      getAttribute: (n) => (n === "type" ? (f.type ?? "text") : null),
      name: f.name ?? "",
      id: f.id ?? "",
      autocomplete: "",
      form: f.form ?? null,
      disabled: false,
      readOnly: false,
      style: f.style ?? {},
      parentElement: parent,
      rect: f.rect ?? { left: 100, top: 100 + i * 60, width: 200, height: 30 },
      value: "",
      getBoundingClientRect() {
        const r = this.rect;
        return { ...r, right: r.left + r.width, bottom: r.top + r.height };
      },
      contains: (x) => x === el,
      dispatchEvent: () => true,
      focus() {},
    };
    el.cover = f.covered ? { tagName: "DIV" } : el;
    el.label = f.label;
    return el;
  });
  win.getComputedStyle = (node) => ({ display: "block", visibility: "visible", opacity: "1", ...node.style });
  win.document = {
    querySelectorAll: () => els,
    elementFromPoint: (x, y) => {
      const e = els.find((e) => {
        const r = e.getBoundingClientRect();
        return x >= r.left && x <= r.right && y >= r.top && y <= r.bottom;
      });
      if (!e) return null;
      const r = e.getBoundingClientRect();
      const middle = Math.abs(x - (r.left + r.width / 2)) < 1;
      // A label drawn over the whole field, or only over its middle like a floating label.
      if (e.label === "full" || (e.label === "middle" && middle)) return { tagName: "LABEL", control: e };
      return e.cover;
    },
  };
  win.HTMLInputElement = { prototype: {} };
  win.Event = class {};
  const scope = { globalThis: {}, URL };
  vm.runInNewContext(source, scope);
  return { win, els, sennel: scope.globalThis.sennel };
}

test("a plain username and password pair is filled", () => {
  const { win, els, sennel } = page([{ name: "user" }, { type: "password" }]);
  const out = sennel.fill("ada", "hunter2", "https://site.example/login", win);
  assert.deepEqual([out.filled, els[0].value, els[1].value], [2, "ada", "hunter2"]);
});

test("each way of hiding a field keeps it empty (R4)", () => {
  const hidden = [
    { rect: { left: 100, top: 100, width: 0, height: 0 } },
    { rect: { left: -500, top: 100, width: 200, height: 30 } },
    { rect: { left: 100, top: 5000, width: 200, height: 30 } },
    { style: { visibility: "hidden" } },
    { style: { display: "none" } },
    { style: { opacity: "0.01" } },
    { parent: { opacity: "0" } },
    { parent: { display: "none" } },
    { covered: true },
    { label: "full" },
  ];
  for (const how of hidden) {
    const { win, els, sennel } = page([{ type: "password", ...how }]);
    sennel.fill("ada", "hunter2", "https://site.example/login", win);
    assert.equal(els[0].value, "", JSON.stringify(how));
  }
});

test("a hidden decoy before the real form is skipped for the visible pair", () => {
  const { win, els, sennel } = page([
    { name: "user", style: { opacity: "0" } },
    { type: "password", style: { opacity: "0" } },
    { name: "user" },
    { type: "password" },
  ]);
  sennel.fill("ada", "hunter2", "https://site.example/login", win);
  assert.deepEqual(els.map((e) => e.value), ["", "", "ada", "hunter2"]);
});

test("a page that moved since the logins were fetched gets nothing (R2)", () => {
  const { win, els, sennel } = page([{ name: "user" }, { type: "password" }]);
  const out = sennel.fill("ada", "hunter2", "https://site.example/other", win);
  assert.deepEqual([out.moved, els[1].value], [true, ""]);
});

test("the first page of a split login gets the username alone", () => {
  const { win, els, sennel } = page([{ type: "email", name: "email" }]);
  const out = sennel.fill("ada@example.com", "hunter2", "https://site.example/login", win);
  assert.deepEqual([out.filled, els[0].value], [1, "ada@example.com"]);
});

test("a floating label over the middle of a field does not hide it", () => {
  const { win, els, sennel } = page([{ name: "user", label: "middle" }, { type: "password", label: "middle" }]);
  sennel.fill("ada", "hunter2", "https://site.example/login", win);
  assert.deepEqual(els.map((e) => e.value), ["ada", "hunter2"]);
});

test("a new query or fragment on the same page is still the page", () => {
  const { win, els, sennel } = page([{ name: "user" }, { type: "password" }]);
  win.location.href = "https://site.example/login?next=%2F#two";
  sennel.fill("ada", "hunter2", "https://site.example/login", win);
  assert.equal(els[1].value, "hunter2");
});

test("a text field in another form is never taken for the username", () => {
  const search = { id: "search" };
  const login = { id: "login" };
  const { win, els, sennel } = page([{ name: "q", form: search }, { type: "password", form: login }]);
  sennel.fill("ada", "hunter2", "https://site.example/login", win);
  assert.deepEqual(els.map((e) => e.value), ["", "hunter2"]);
});

test("number fields are never login fields", () => {
  const { sennel } = page([]);
  const field = { tagName: "INPUT", getAttribute: (n) => (n === "type" ? "number" : null), autocomplete: "", name: "account_number", id: "" };
  assert.equal(sennel.kind(field), null);
});
