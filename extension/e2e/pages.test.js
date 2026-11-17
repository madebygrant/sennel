// The test pages in a real Chrome with the test build of the extension, which talks to the stand-in
// app in src/fake-app.js. Run with `npm run test:pages`.
import { after, before, test } from "node:test";
import assert from "node:assert/strict";
import { createServer } from "node:http";
import { readFile } from "node:fs/promises";
import { resolve } from "node:path";
import puppeteer from "puppeteer";

const root = resolve(import.meta.dirname, "..");
const SETTLE = 650;
let server;
let base;
let browser;

before(async () => {
  server = createServer(async (req, res) => {
    try {
      const name = new URL(req.url, "http://x").pathname.replace(/^\/+/, "") || "login.html";
      if (name.includes("..")) throw new Error("no");
      res.setHeader("content-type", "text/html; charset=utf-8");
      res.end(await readFile(resolve(root, "test", name)));
    } catch {
      res.statusCode = 404;
      res.end();
    }
  });
  await new Promise((done) => server.listen(0, "127.0.0.1", done));
  base = `http://localhost:${server.address().port}`;
  browser = await puppeteer.launch({
    headless: true,
    pipe: true,
    enableExtensions: [resolve(root, "dist/test-chrome")],
    // Ubuntu's runners refuse Chrome's user-namespace sandbox; the pages here are the repo's own.
    args: process.env.CI ? ["--no-sandbox"] : [],
  });
  // A saved pairing, as if the user had connected this browser from the toolbar popup.
  const worker = await (await browser.waitForTarget((t) => t.type() === "service_worker")).worker();
  await worker.evaluate(() => chrome.storage.local.set({ pairings: [{ id: "test", key: "k", hash: "h" }] }));
});

after(async () => {
  await browser?.close();
  server?.close();
});

const sleep = (ms) => new Promise((done) => setTimeout(done, ms));

// The fill button in `frame`, once it has settled; null when none appears.
async function button(frame) {
  try {
    await frame.waitForFunction(() => document.querySelector("sennel-fill")?.shadowRoot?.querySelector(".mark"), { timeout: 1500 });
  } catch {
    return null;
  }
  await sleep(SETTLE);
  return frame.evaluateHandle(() => document.querySelector("sennel-fill").shadowRoot.querySelector(".mark"));
}

async function rows(frame) {
  await frame.waitForFunction(() => document.querySelector("sennel-fill")?.shadowRoot?.querySelectorAll(".row").length > 0, { timeout: 3000 });
  await sleep(SETTLE);
  return frame.evaluateHandle(() => [...document.querySelector("sennel-fill").shadowRoot.querySelectorAll(".row")]);
}

async function pick(frame, index = 0) {
  const list = await rows(frame);
  const row = await list.evaluateHandle((all, i) => all[i], index);
  await row.asElement().click();
}

const panelOpen = (frame) =>
  frame.evaluate(() => {
    const panel = document.querySelector("sennel-fill")?.shadowRoot?.querySelector(".panel");
    return Boolean(panel && !panel.hidden);
  });

const values = (frame, selector = "input") => frame.$$eval(selector, (all) => all.map((i) => i.value));

// A fill finishes after a round trip to the worker, so wait for the value rather than read at once.
async function filled(frame, selector, value) {
  try {
    await frame.waitForFunction((s, v) => document.querySelector(s)?.value === v, { timeout: 3000 }, selector, value);
  } catch {
    // The assertion that follows reports what is there.
  }
}

async function open(path) {
  const page = await browser.newPage();
  await page.goto(`${base}/${path}`, { waitUntil: "load" });
  return page;
}

test("a plain login fills after a click on the button, and not before (R1)", async () => {
  const page = await open("login.html");
  await sleep(300);
  assert.deepEqual(await values(page), ["", ""], "nothing on load");
  await page.click("input[name=user]");
  assert.deepEqual(await values(page), ["", ""], "nothing on focus");
  await (await button(page)).click();
  await pick(page);
  await filled(page, "input[name=pass]", "hunter2");
  assert.deepEqual(await values(page), ["ada", "hunter2"]);
  await page.close();
});

test("a script's click on the button does nothing (R1)", async () => {
  const page = await open("login.html");
  await page.click("input[name=user]");
  const mark = await button(page);
  await mark.evaluate((b) => b.click());
  await sleep(300);
  assert.equal(await panelOpen(page), false);
  await page.close();
});

test("a click before the button has settled does nothing (R6)", async () => {
  const page = await open("login.html");
  await page.click("input[name=user]");
  await page.waitForFunction(() => document.querySelector("sennel-fill")?.shadowRoot?.querySelector(".mark"));
  const mark = await page.evaluateHandle(() => document.querySelector("sennel-fill").shadowRoot.querySelector(".mark"));
  await mark.click();
  await sleep(300);
  assert.equal(await panelOpen(page), false);
  await page.close();
});

test("a page that fades itself or the button gets nothing from a click (R6)", async () => {
  for (const fade of [
    () => (document.documentElement.style.opacity = "0.3"),
    () => document.querySelector("sennel-fill").style.setProperty("opacity", "0.01", "important"),
    () => (document.body.style.filter = "opacity(0)"),
  ]) {
    const page = await open("login.html");
    await page.click("input[name=user]");
    const mark = await button(page);
    await page.evaluate(fade);
    await mark.click();
    await sleep(300);
    assert.equal(await panelOpen(page), false, String(fade));
    await page.close();
  }
});

test("a button the page moves has to settle again before a click counts (R6)", async () => {
  const page = await open("login.html");
  await page.setViewport({ width: 800, height: 400 });
  await page.evaluate(() => (document.body.style.minHeight = "3000px"));
  await page.click("input[name=user]");
  const mark = await button(page);
  await page.evaluate(() => scrollBy(0, 20));
  await sleep(50);
  await mark.click();
  await sleep(300);
  assert.equal(await panelOpen(page), false);
  await page.close();
});

test("a page that opens its own popover over Sennel's gets nothing from a click (R6)", async () => {
  const page = await open("login.html");
  await page.click("input[name=user]");
  const mark = await button(page);
  await page.evaluate(() => {
    const cover = Object.assign(document.createElement("div"), { popover: "manual", textContent: "Accept cookies" });
    cover.style.cssText = "pointer-events: none; inset: 0; width: 100vw; height: 100vh; background: transparent";
    document.body.append(cover);
    cover.showPopover();
  });
  await mark.click();
  await sleep(300);
  assert.equal(await panelOpen(page), false);
  await page.close();
});

test("hidden and covered fields stay empty while the visible pair fills (R4)", async () => {
  const page = await open("hidden.html");
  await page.click("input[name=user]");
  await (await button(page)).click();
  await pick(page);
  await filled(page, "input[name=pass]", "hunter2");
  const got = await page.$$eval("input", (all) => Object.fromEntries(all.map((i) => [i.name, i.value])));
  assert.deepEqual([got.user, got.pass], ["ada", "hunter2"]);
  for (const name of ["u1", "p1", "u2", "p2", "u3", "p3", "u4", "p4", "u5", "p5"]) assert.equal(got[name], "", name);
  await page.close();
});

test("a login split over two steps fills each step", async () => {
  const page = await open("two-step.html");
  await page.click("input[name=email]");
  await (await button(page)).click();
  await pick(page);
  await filled(page, "input[name=email]", "ada");
  assert.equal(await page.$eval("input[name=email]", (i) => i.value), "ada");
  await page.click("#one button");
  await page.click("input[name=pass]");
  await (await button(page)).click();
  await pick(page);
  await filled(page, "input[name=pass]", "hunter2");
  assert.equal(await page.$eval("input[name=pass]", (i) => i.value), "hunter2");
  await page.close();
});

test("a form added after the page loaded fills", async () => {
  const page = await open("dynamic.html");
  await page.waitForSelector("input[name=user]");
  await page.click("input[name=user]");
  await (await button(page)).click();
  await pick(page);
  await filled(page, "input[name=pass]", "hunter2");
  assert.deepEqual(await values(page), ["ada", "hunter2"]);
  await page.close();
});

test("a form inside a shadow root fills", async () => {
  const page = await open("shadow.html");
  await page.click("pierce/input[name=user]");
  await (await button(page)).click();
  await pick(page);
  await page.waitForFunction(() => document.querySelector("login-box").shadowRoot.querySelector("input[name=pass]").value, { timeout: 3000 }).catch(() => {});
  const got = await page.evaluate(() => [...document.querySelector("login-box").shadowRoot.querySelectorAll("input")].map((i) => i.value));
  assert.deepEqual(got, ["ada", "hunter2"]);
  await page.close();
});

test("a same-origin frame gets the button and fills (R3)", async () => {
  const page = await open("iframe-same.html");
  const frame = await (await page.waitForSelector("#frame")).contentFrame();
  await frame.waitForSelector("input[name=user]");
  await frame.click("input[name=user]");
  await (await button(frame)).click();
  await pick(frame);
  await filled(frame, "input[name=pass]", "hunter2");
  assert.deepEqual(await values(frame), ["ada", "hunter2"]);
  await page.close();
});

test("a cross-origin frame gets no button (R3)", async () => {
  const page = await open("iframe-cross.html");
  const frame = await (await page.waitForSelector("#frame")).contentFrame();
  await frame.waitForSelector("input[name=user]");
  await frame.click("input[name=user]");
  assert.equal(await button(frame), null);
  await page.close();
});

test("a one-time code field gets the code of the login picked (R7)", async () => {
  const page = await open("otp.html");
  await page.click("input[name=otp]");
  await (await button(page)).click();
  await pick(page, 1);
  await filled(page, "input[name=otp]", "123456");
  assert.equal(await page.$eval("input[name=otp]", (i) => i.value), "123456");
  await page.close();
});
