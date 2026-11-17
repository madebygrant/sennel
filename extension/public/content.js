// Runs in every frame of every web page, and does nothing until a login field gets focus. Then it
// shows a small button out of the page's reach (R6); only a real click on it asks Sennel for
// anything (R1). A plain script, not a module: browsers load content scripts as classic scripts.
(() => {
  if (globalThis.sennel) return;
  // The test build turns this on: the shadow root opens so tests can look inside.
  const TESTING = false;
  const api = globalThis.browser ?? globalThis.chrome;

  // A click on the button or the list counts only after it has been on screen this long, so a
  // page cannot slide it under a click the user meant for something else.
  const SETTLE_MS = 500;

  function onScreen(rect, win) {
    return rect.bottom > 0 && rect.right > 0 && rect.top < win.innerHeight && rect.left < win.innerWidth;
  }

  // R4: a field counts only if the user could see it and something of it shows. Five points across
  // it are tried, so a floating label over the middle passes while a full cover does not.
  function visible(el, win) {
    const rect = el.getBoundingClientRect();
    if (rect.width < 2 || rect.height < 2 || !onScreen(rect, win)) return false;
    const own = win.getComputedStyle(el);
    if (own.visibility === "hidden" || own.visibility === "collapse") return false;
    for (let node = el; node; node = parent(node)) {
      const style = win.getComputedStyle(node);
      if (style.display === "none" || Number(style.opacity) < 0.1) return false;
    }
    const root = el.getRootNode?.() ?? win.document;
    const at = (x, y) => (root.elementFromPoint ?? win.document.elementFromPoint).call(root, x, y);
    const xs = [0.1, 0.5, 0.9].map((f) => rect.left + rect.width * f);
    const ys = [0.25, 0.5, 0.75].map((f) => rect.top + rect.height * f);
    const points = [[xs[1], ys[1]], [xs[0], ys[0]], [xs[2], ys[0]], [xs[0], ys[2]], [xs[2], ys[2]]];
    return points.some(([x, y]) => {
      if (x < 0 || y < 0 || x >= win.innerWidth || y >= win.innerHeight) return false;
      const hit = at(x, y);
      return hit === el || el.contains(hit);
    });
  }

  // Up through shadow roots too, so a hidden host hides what is inside it.
  function parent(node) {
    return node.parentElement ?? node.getRootNode?.().host ?? null;
  }

  function usable(el, win) {
    return !el.disabled && !el.readOnly && visible(el, win);
  }

  // Every input in the document and in open shadow roots, in document order.
  function inputs(root) {
    const found = [];
    const walk = (node) => {
      for (const el of node.querySelectorAll("*")) {
        if (el.tagName === "INPUT") found.push(el);
        if (el.shadowRoot) walk(el.shadowRoot);
      }
    };
    walk(root);
    return found;
  }

  const TEXT = new Set(["text", "email", "tel", ""]);
  const words = (el) => `${el.autocomplete} ${el.name} ${el.id} ${el.getAttribute("placeholder") ?? ""} ${el.getAttribute("aria-label") ?? ""}`;

  function kind(el) {
    if (el?.tagName !== "INPUT") return null;
    const type = (el.getAttribute("type") || "").toLowerCase();
    if (type === "password") return "password";
    if (!TEXT.has(type)) return null;
    const said = words(el);
    if (/one-time-code/i.test(el.autocomplete) || /\b(otp|totp|2fa|mfa)\b|one.?time|verification.?code|auth.?code|security.?code/i.test(said)) {
      return "otp";
    }
    if (type === "email" || /user|email|login|account|identifier/i.test(said)) return "username";
    return null;
  }

  // The fields a fill fills, found from one field: the password and the text field before it, in
  // the same form or else the same document or shadow root. A page with only a username field is
  // the first page of a login split over two.
  // `scroll` is off when only looking, so opening the popup never moves the page.
  function context(from, win, scroll = true) {
    const all = inputs(from?.form ?? from?.getRootNode?.() ?? win.document);
    const ok = scroll ? seen : usable;
    const secret = all.find((el) => el.type === "password" && ok(el, win));
    let user = null;
    if (secret) {
      // In the password's own form, or in no form when it has none: never a search box elsewhere.
      const before = all.slice(0, all.indexOf(secret)).reverse();
      user = before.find((el) => (el.form ?? null) === (secret.form ?? null) && TEXT.has((el.getAttribute("type") || "").toLowerCase()) && kind(el) !== "otp" && usable(el, win)) ?? null;
    } else {
      user = all.find((el) => kind(el) === "username" && ok(el, win)) ?? null;
    }
    const otp = all.find((el) => kind(el) === "otp" && usable(el, win)) ?? null;
    return { user, secret, otp };
  }

  // A field below the fold is scrolled to before it is judged; one hidden any other way is not.
  function seen(el, win) {
    if (!onScreen(el.getBoundingClientRect(), win)) el.scrollIntoView?.({ block: "nearest" });
    return usable(el, win);
  }

  function set(el, value, win) {
    // Through the prototype's setter, so pages whose framework tracks the value see the change.
    const setter = Object.getOwnPropertyDescriptor(win.HTMLInputElement.prototype, "value")?.set;
    if (setter) setter.call(el, value);
    else el.value = value;
    el.dispatchEvent(new win.Event("input", { bubbles: true, composed: true }));
    el.dispatchEvent(new win.Event("change", { bubbles: true, composed: true }));
  }

  function pageOf(href) {
    const u = new URL(href);
    return `${u.origin}${u.pathname}`;
  }

  function put(fields, login, password, win) {
    let filled = 0;
    if (fields.user && login) {
      set(fields.user, login, win);
      filled++;
    }
    if (fields.secret && password) {
      set(fields.secret, password, win);
      filled++;
    }
    return filled;
  }

  // The popup's fill. `expected` is the address the logins were fetched for (R2).
  function fill(login, password, expected, win = globalThis) {
    if (pageOf(win.location.href) !== pageOf(expected)) return { filled: 0, moved: true };
    const fields = context(null, win);
    const filled = put(fields, login, password, win);
    (fields.secret ?? fields.user)?.focus?.();
    return { filled, moved: false };
  }

  // What the popup needs to know about this frame: whether it has a login form, and where it is.
  function summary(win = globalThis) {
    const fields = context(null, win, false);
    let crossOrigin = false;
    try {
      crossOrigin = win.top !== win && !win.frameElement;
    } catch {
      crossOrigin = true;
    }
    return { url: win.location.href, fields: Boolean(fields.secret || fields.user), crossOrigin };
  }

  globalThis.sennel = { visible, fill, summary, kind, context };

  const MARK =
    '<svg viewBox="0 0 24 24" width="16" height="16" aria-hidden="true"><polygon points="12,2 21,7 21,17 12,22 3,17 3,7" fill="none" stroke="#e2a65a" stroke-width="2"/><circle cx="12" cy="10.5" r="2.4" fill="#e2a65a"/><rect x="10.8" y="11.5" width="2.4" height="5" rx="1" fill="#e2a65a"/></svg>';

  const STYLE = `
    :host { all: initial; }
    .box { font: 13px/1.35 system-ui, sans-serif; color: #ece8e1; }
    button { all: unset; box-sizing: border-box; cursor: pointer; }
    .mark { width: 24px; height: 24px; display: grid; place-items: center; border-radius: 6px; background: #141414; border: 1px solid #3a3a3a; }
    .mark:focus-visible, .row:focus-visible { outline: 2px solid #e2a65a; }
    .panel { margin-top: 4px; width: 260px; max-height: 240px; overflow: auto; background: #141414; border: 1px solid #3a3a3a; border-radius: 8px; padding: 4px; box-shadow: 0 8px 24px rgb(0 0 0 / 0.4); }
    .row { display: grid; width: 100%; padding: 6px 8px; border-radius: 6px; }
    .row:hover { background: #222; }
    .title { font-weight: 600; }
    .sub, .note { color: #9a948a; font-size: 12px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
    .note { padding: 6px 8px; white-space: normal; }
  `;

  let ui = null;

  function frameIsSafe(win) {
    // The in-page UI stays out of cross-origin frames (R3), where the parent could make the whole
    // frame transparent without this page being able to tell.
    if (win.top === win) return true;
    let frame;
    try {
      frame = win.frameElement;
    } catch {
      return false;
    }
    if (!frame) return false;
    for (let node = frame; node; node = parent(node)) {
      const style = frame.ownerDocument.defaultView.getComputedStyle(node);
      if (Number(style.opacity) < 1 || style.filter !== "none" || style.visibility !== "visible") return false;
    }
    return frameIsSafe(frame.ownerDocument.defaultView);
  }

  // Anything of the page's in the top layer could sit above Sennel's popover, since the last opened
  // is on top. Open shadow roots are searched too; a closed one cannot be, which is a known gap.
  function pageOnTop(win) {
    if (win.document.fullscreenElement) return true;
    const open = (root) =>
      [...root.querySelectorAll(":popover-open, dialog[open]")].some((el) => el !== ui.host) ||
      [...root.querySelectorAll("*")].some((el) => el.shadowRoot && open(el.shadowRoot));
    return open(win.document);
  }

  // R6: at the moment of a click the UI must be on top, opaque and untouched, and so must the page
  // around it. A page that fades or covers it to steer a click gets nothing.
  function trusted(event) {
    if (!event.isTrusted || !ui || performance.now() - ui.shownAt < SETTLE_MS) return false;
    const win = globalThis;
    if (!ui.host.isConnected || !ui.host.matches(":popover-open") || pageOnTop(win)) return false;
    for (const node of [ui.host, win.document.documentElement, win.document.body]) {
      if (!node) continue;
      const style = win.getComputedStyle(node);
      if (Number(style.opacity) < 1 || style.filter !== "none" || style.visibility !== "visible" || style.display === "none") {
        return false;
      }
    }
    return frameIsSafe(win);
  }

  function close() {
    ui?.host.remove();
    ui = null;
  }

  // A button that moves has to settle again, so a page cannot scroll it under a click.
  function place() {
    if (!ui) return;
    const rect = ui.field.getBoundingClientRect();
    if (!ui.field.isConnected || rect.width === 0 || !onScreen(rect, globalThis)) return close();
    const left = `${rect.right - 28}px`;
    const top = `${rect.top + (rect.height - 24) / 2}px`;
    const style = ui.host.style;
    if (style.left === left && style.top === top) return;
    style.setProperty("left", left, "important");
    style.setProperty("top", top, "important");
    ui.shownAt = performance.now();
  }

  function show(field) {
    close();
    const host = document.createElement("sennel-fill");
    host.setAttribute("popover", "manual");
    for (const [k, v] of Object.entries({ position: "fixed", inset: "auto", margin: "0", padding: "0", border: "0", background: "transparent", overflow: "visible", opacity: "1", filter: "none", visibility: "visible", display: "block", "z-index": "2147483647" })) {
      host.style.setProperty(k, v, "important");
    }
    const root = host.attachShadow({ mode: TESTING ? "open" : "closed" });
    root.innerHTML = `<style>${STYLE}</style><div class="box"><button class="mark" title="Fill from Sennel" aria-label="Fill from Sennel">${MARK}</button><div class="panel" hidden></div></div>`;
    document.documentElement.append(host);
    host.showPopover?.();
    ui = { host, root, field, shownAt: performance.now(), entries: [] };
    place();
    root.querySelector(".mark").addEventListener("click", (e) => {
      if (trusted(e)) open();
    });
  }

  function say(text) {
    const panel = ui.root.querySelector(".panel");
    panel.hidden = false;
    panel.replaceChildren(Object.assign(document.createElement("div"), { className: "note", textContent: text }));
  }

  const MESSAGES = {
    offline: "Sennel is not reachable. Open the Sennel app.",
    locked: "The vault is locked. Unlock it in Sennel.",
    unpaired: "This browser is not connected. Connect it from Sennel's toolbar button.",
    nopage: "Sennel does not fill this page.",
  };

  async function ask(message) {
    try {
      return await api.runtime.sendMessage(message);
    } catch (e) {
      return { stage: "error", note: e?.message ?? String(e) };
    }
  }

  async function open() {
    const asking = ui;
    say("Asking Sennel…");
    const reply = await ask({ op: "page-list" });
    if (ui !== asking) return;
    if (reply?.stage !== "list") {
      say(MESSAGES[reply?.stage] ?? reply?.note ?? "Something went wrong.");
      return;
    }
    if (!reply.entries.length) {
      say("No logins for this page.");
      return;
    }
    const otp = kind(ui.field) === "otp";
    const panel = ui.root.querySelector(".panel");
    panel.replaceChildren(
      ...reply.entries.map((entry) => {
        const row = document.createElement("button");
        row.className = "row";
        row.append(
          Object.assign(document.createElement("span"), { className: "title", textContent: entry.name || entry.login }),
          Object.assign(document.createElement("span"), { className: "sub", textContent: otp ? "one-time code" : entry.login }),
        );
        row.addEventListener("click", (e) => {
          if (trusted(e)) choose(entry, otp);
        });
        return row;
      }),
    );
    // The list is new on screen, so it has to settle before a click on it counts.
    ui.shownAt = performance.now();
  }

  async function choose(entry, otp) {
    const mine = ui;
    const field = ui.field;
    if (otp) {
      const reply = await ask({ op: "page-code", uuid: entry.uuid });
      // Dismissed or replaced while Sennel answered: the answer is for a list that is gone.
      if (ui !== mine) return;
      if (!reply?.totp) return say(reply?.note ?? MESSAGES[reply?.stage] ?? "No one-time code for this login.");
      close();
      set(field, reply.totp, globalThis);
      return;
    }
    const reply = await ask({ op: "page-fill", uuid: entry.uuid });
    if (ui !== mine) return;
    if (reply?.expired) {
      close();
      return;
    }
    if (!reply?.login && !reply?.password) {
      return say(reply?.moved ? "The page changed. Try again." : (MESSAGES[reply?.stage] ?? reply?.note ?? "Not filled."));
    }
    // Closed first: the open list can lie over the very fields whose visibility is judged next.
    close();
    const fields = context(field, globalThis);
    // The field the user started from is filled even when it is the only one on the page.
    if (!fields.user && !fields.secret) fields.user = field;
    put(fields, reply.login, reply.password, globalThis);
  }

  if (!api?.runtime?.id) return;

  document.addEventListener(
    "focusin",
    (e) => {
      const field = e.composedPath()[0];
      if (ui && field === ui.field) return;
      if (!kind(field) || !usable(field, globalThis) || !frameIsSafe(globalThis)) return;
      show(field);
    },
    true,
  );
  document.addEventListener(
    "pointerdown",
    (e) => {
      if (ui && !e.composedPath().includes(ui.host) && e.composedPath()[0] !== ui.field) close();
    },
    true,
  );
  document.addEventListener("keydown", (e) => e.key === "Escape" && close(), true);
  addEventListener("scroll", place, true);
  addEventListener("resize", place);
})();
