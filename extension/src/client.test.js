import { test } from "node:test";
import assert from "node:assert/strict";
import nacl from "tweetnacl";
import { Client, Disconnected, ProtocolError, b64, increment, unb64 } from "./client.js";

// A port wired to a fake app that speaks the protocol, with knobs to make it misbehave.
function fakeApp({ wrongNonce = false } = {}) {
  const host = nacl.box.keyPair();
  const listeners = { message: [], disconnect: [] };
  let clientKey;
  const deliver = (m) => queueMicrotask(() => listeners.message.forEach((f) => f(m)));
  const port = {
    onMessage: { addListener: (f) => listeners.message.push(f) },
    onDisconnect: { addListener: (f) => listeners.disconnect.push(f) },
    disconnect() {},
    postMessage(m) {
      const reply = increment(unb64(m.nonce));
      if (m.action === "change-public-keys") {
        clientKey = unb64(m.publicKey);
        deliver({ action: m.action, publicKey: b64(host.publicKey), nonce: b64(reply), success: "true", sennel: 1 });
        return;
      }
      const inner = JSON.parse(new TextDecoder().decode(nacl.box.open(unb64(m.message), unb64(m.nonce), clientKey, host.secretKey)));
      if (inner.action === "get-logins" && inner.url === "https://none.example/") {
        deliver({ action: m.action, error: "No logins found", errorCode: "15" });
        return;
      }
      const sent = wrongNonce ? nacl.randomBytes(24) : reply;
      const body = new TextEncoder().encode(JSON.stringify({ echo: inner, nonce: b64(sent), success: "true" }));
      deliver({ action: m.action, message: b64(nacl.box(body, sent, clientKey, host.secretKey)), nonce: b64(sent) });
    },
  };
  return { port, drop: () => listeners.disconnect.forEach((f) => f()), notice: deliver };
}

test("a request round-trips once keys are exchanged, and the app is recognised as Sennel", async () => {
  const app = fakeApp();
  const client = new Client(app.port);
  await client.exchange();
  assert.equal(client.sennel, true);
  const reply = await client.request("get-logins", { url: "https://site.example/" });
  assert.equal(reply.echo.url, "https://site.example/");
});

test("an error reply rejects with its code", async () => {
  const client = new Client(fakeApp().port);
  await client.exchange();
  await assert.rejects(client.request("get-logins", { url: "https://none.example/" }), (e) => e instanceof ProtocolError && e.code === "15");
});

test("a reply whose nonce is not the request's plus one is refused (R8)", async () => {
  const client = new Client(fakeApp({ wrongNonce: true }).port);
  await client.exchange();
  await assert.rejects(client.request("get-databasehash"), (e) => e.code === "nonce");
});

test("a dropped connection rejects what is pending and later requests, with no retry (R5)", async () => {
  const app = fakeApp();
  let keyPairs = 0;
  const realKeyPair = nacl.box.keyPair;
  nacl.box.keyPair = () => (keyPairs++, realKeyPair());
  try {
    const client = new Client(app.port);
    await client.exchange();
    app.port.postMessage = () => {};
    const pending = client.request("get-databasehash");
    app.drop();
    await assert.rejects(pending, Disconnected);
    await assert.rejects(client.request("get-databasehash"), Disconnected);
    assert.equal(keyPairs, 1, "one key pair for the connection");
  } finally {
    nacl.box.keyPair = realKeyPair;
  }
});

test("lock notices are not taken for replies", async () => {
  const app = fakeApp();
  const client = new Client(app.port);
  await client.exchange();
  app.notice({ action: "database-locked" });
  const reply = await client.request("get-logins", { url: "https://site.example/" });
  assert.equal(reply.echo.url, "https://site.example/");
});

test("an error naming no action still answers the pending request", async () => {
  const app = fakeApp();
  const client = new Client(app.port);
  await client.exchange();
  app.port.postMessage = () => app.notice({ action: "", error: "Incorrect action", errorCode: "12" });
  await assert.rejects(client.request("get-logins"), (e) => e.code === "12");
});

test("increment carries from the first byte", () => {
  assert.deepEqual([...increment(new Uint8Array([255, 1, 0]))], [0, 2, 0]);
  assert.deepEqual([...increment(new Uint8Array([255, 255]))], [0, 0]);
});
