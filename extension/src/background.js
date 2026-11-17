// Runs the protocol for the popup, which only asks and shows. Answers go back through
// sendResponse, which both Chrome and Firefox accept from a listener that returns true.
import { Disconnected } from "./client.js";
import { code, fill, list, pair } from "./session.js";

const api = globalThis.browser ?? globalThis.chrome;

function describe(e) {
  if (e instanceof Disconnected) return { stage: "offline" };
  if (e?.code === "1") return { stage: "locked" };
  if (e?.code === "8") return { stage: "unpaired", note: "Sennel did not connect this browser." };
  return { stage: "error", note: e?.message ?? String(e) };
}

const ops = {
  list: ({ tab }) => list(tab),
  pair: ({ tab }) => pair(tab),
  fill: ({ tab, uuid, current }) => fill(tab, uuid, current),
  code: ({ tab, uuid }) => code(tab, uuid).then((totp) => ({ totp })),
};

api.runtime.onMessage.addListener((message, sender, sendResponse) => {
  // Only this extension's own pages may ask; content scripts and other extensions may not.
  const op = ops[message?.op];
  if (!op || sender.id !== api.runtime.id || sender.tab) return false;
  op(message).then(sendResponse, (e) => sendResponse(describe(e)));
  return true;
});
