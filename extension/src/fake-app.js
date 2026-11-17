// A stand-in for the Sennel app, built only into the test extension (SENNEL_FAKE_APP=1). It speaks
// the same protocol as the real one, so the browser tests drive the extension end to end without a
// native messaging host.
import nacl from "tweetnacl";
import { b64, increment, unb64 } from "./client.js";

const LOGINS = [
  { uuid: "u1", name: "plain", login: "ada", password: "hunter2", totp: "" },
  { uuid: "u2", name: "with code", login: "bob", password: "pw-bob", totp: "123456" },
];

export function fakePort() {
  const host = nacl.box.keyPair();
  const listeners = { message: [], disconnect: [] };
  let client;
  const given = new Set();
  const deliver = (m) => setTimeout(() => listeners.message.forEach((f) => f(m)));
  const answer = (action, nonce, body) => {
    const sealed = nacl.box(new TextEncoder().encode(JSON.stringify({ ...body, nonce: b64(nonce), success: "true" })), nonce, client, host.secretKey);
    deliver({ action, message: b64(sealed), nonce: b64(nonce) });
  };
  return {
    onMessage: { addListener: (f) => listeners.message.push(f) },
    onDisconnect: { addListener: (f) => listeners.disconnect.push(f) },
    disconnect() {},
    postMessage(m) {
      const nonce = increment(unb64(m.nonce));
      if (m.action === "change-public-keys") {
        client = unb64(m.publicKey);
        deliver({ action: m.action, publicKey: b64(host.publicKey), nonce: b64(nonce), success: "true", sennel: 1 });
        return;
      }
      const inner = JSON.parse(new TextDecoder().decode(nacl.box.open(unb64(m.message), unb64(m.nonce), client, host.secretKey)));
      const fail = (code) => deliver({ action: m.action, error: "refused", errorCode: code });
      switch (inner.action) {
        case "test-associate":
          return inner.id === "test" ? answer(m.action, nonce, { id: "test", hash: "h" }) : fail("8");
        case "associate":
          return answer(m.action, nonce, { id: "test", hash: "h" });
        case "get-logins": {
          const host = new URL(inner.url).hostname;
          if (host !== "127.0.0.1" && host !== "localhost") return fail("15");
          LOGINS.forEach((l) => given.add(l.uuid));
          return answer(m.action, nonce, { count: LOGINS.length, entries: LOGINS.map(({ totp, ...l }) => l), hash: "h", id: "" });
        }
        case "get-totp": {
          const entry = LOGINS.find((l) => l.uuid === inner.uuid && given.has(l.uuid));
          return entry ? answer(m.action, nonce, { totp: entry.totp }) : fail("18");
        }
        default:
          return fail("12");
      }
    },
  };
}
