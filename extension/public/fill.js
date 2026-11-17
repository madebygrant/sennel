// Injected into the tab's top frame when the user clicks a login in the popup (rules R1, R3). A
// plain script, not a module, so the popup can inject the file as it is; tests load it the same way.
(() => {
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
    for (let node = el; node; node = node.parentElement) {
      const style = win.getComputedStyle(node);
      if (style.display === "none" || Number(style.opacity) < 0.1) return false;
    }
    const xs = [0.1, 0.5, 0.9].map((f) => rect.left + rect.width * f);
    const ys = [0.25, 0.5, 0.75].map((f) => rect.top + rect.height * f);
    const points = [[xs[1], ys[1]], [xs[0], ys[0]], [xs[2], ys[0]], [xs[0], ys[2]], [xs[2], ys[2]]];
    return points.some(([x, y]) => {
      if (x < 0 || y < 0 || x >= win.innerWidth || y >= win.innerHeight) return false;
      const hit = win.document.elementFromPoint(x, y);
      return hit === el || el.contains(hit);
    });
  }

  function usable(el, win) {
    return !el.disabled && !el.readOnly && visible(el, win);
  }

  const TEXT = new Set(["text", "email", "tel", ""]);

  function textField(el) {
    return el.tagName === "INPUT" && TEXT.has((el.getAttribute("type") || "").toLowerCase());
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
    el.dispatchEvent(new win.Event("input", { bubbles: true }));
    el.dispatchEvent(new win.Event("change", { bubbles: true }));
  }

  function pageOf(href) {
    const u = new URL(href);
    return `${u.origin}${u.pathname}`;
  }

  // `expected` is the address the logins were fetched for (R2). A page that moved since gets nothing.
  function fill(login, password, expected, win = globalThis) {
    if (pageOf(win.location.href) !== pageOf(expected)) return { filled: 0, moved: true };
    const doc = win.document;
    const inputs = [...doc.querySelectorAll("input")];
    const secret = inputs.find((el) => el.type === "password" && seen(el, win));
    let user;
    if (secret) {
      // The closest text field before the password, in the same form when there is one.
      const before = inputs.slice(0, inputs.indexOf(secret)).reverse();
      user = before.find((el) => textField(el) && (!secret.form || el.form === secret.form) && usable(el, win));
    } else {
      // The first page of a login split over two pages asks for the username alone.
      user = inputs.find((el) => textField(el) && /user|email|login/i.test(`${el.autocomplete} ${el.name} ${el.id} ${el.type}`) && seen(el, win));
    }
    let filled = 0;
    if (user && login) {
      set(user, login, win);
      filled++;
    }
    if (secret && password) {
      set(secret, password, win);
      filled++;
    }
    (secret ?? user)?.focus?.();
    return { filled, moved: false };
  }

  globalThis.sennel = { visible, fill };
})();
