// Runs the protocol for the popup and the in-page list, which only ask and show. Answers go back
// through sendResponse, which both Chrome and Firefox accept from a listener that returns true.
import { Disconnected } from "./client.js";
import { code, credentials, fill, frames, list, pair } from "./session.js";

const api = globalThis.browser ?? globalThis.chrome;

function describe(e) {
  if (e instanceof Disconnected) return { stage: "offline" };
  if (e?.code === "1") return { stage: "locked" };
  if (e?.code === "8") return { stage: "unpaired", note: "Sennel did not connect this browser." };
  return { stage: "error", note: e?.message ?? String(e) };
}

// From the extension's own popup. It names the tab and frame it means.
const popupOps = {
  list: ({ target }) => list(target),
  pair: ({ target }) => pair(target),
  fill: ({ target, uuid, current }) => fill(target, uuid, current),
  code: ({ target, uuid }) => code(target, uuid).then((totp) => ({ totp })),
  frames: ({ tabId }) => frames(tabId),
};

// From a content script. The target is the frame the browser says sent it, never what it claims.
const pageOps = {
  "page-list": (_, target) => list(target),
  "page-fill": ({ uuid }, target) => credentials(target, uuid),
  "page-code": ({ uuid }, target) => code(target, uuid).then((totp) => ({ totp })),
};

api.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (sender.id !== api.runtime.id) return false;
  let run;
  if (sender.tab) {
    const op = pageOps[message?.op];
    if (!op) return false;
    const target = { id: sender.tab.id, frameId: sender.frameId ?? 0, url: sender.url };
    run = () => op(message, target);
  } else {
    const op = popupOps[message?.op];
    if (!op) return false;
    run = () => op(message);
  }
  Promise.resolve()
    .then(run)
    .then(sendResponse, (e) => sendResponse(describe(e)));
  return true;
});
