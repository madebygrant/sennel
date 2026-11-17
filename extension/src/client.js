// The browser's side of the protocol: one key exchange per connection, then NaCl boxes whose reply
// nonce must be the request's plus one (rule R8). Written from the protocol document and the reply
// shapes recorded in crates/sennel-browser/SOURCES.md.
import nacl from "tweetnacl";

export const NATIVE_HOST = "app.sennel.browser";

// Long enough for the user to answer one of Sennel's dialogs, short enough that a request the app
// never answers does not hold the queue for good.
const WAIT_MS = 300_000;

export class ProtocolError extends Error {
  constructor(code, text) {
    super(text || `error ${code}`);
    this.code = String(code);
  }
}

export class Disconnected extends Error {
  constructor() {
    super("Sennel is not reachable");
  }
}

const b64 = (bytes) => btoa(String.fromCharCode(...bytes));
const unb64 = (text) => Uint8Array.from(atob(text), (c) => c.charCodeAt(0));

// The nonce a reply must carry: the request's plus one, as a little-endian number.
export function increment(nonce) {
  const next = Uint8Array.from(nonce);
  for (let i = 0; i < next.length; i++) {
    next[i] = (next[i] + 1) & 0xff;
    if (next[i] !== 0) break;
  }
  return next;
}

// `port` is what runtime.connectNative returns: postMessage, onMessage and onDisconnect.
export class Client {
  constructor(port, random = nacl.randomBytes) {
    this.port = port;
    this.random = random;
    // One key pair for the life of this connection (rule R5).
    this.keys = nacl.box.keyPair();
    this.id = b64(random(24));
    this.waiting = null;
    this.closed = false;
    this.sennel = false;
    port.onMessage.addListener((message) => this.#receive(message));
    port.onDisconnect.addListener(() => {
      this.closed = true;
      clearTimeout(this.waiting?.timer);
      this.waiting?.reject(new Disconnected());
      this.waiting = null;
    });
    // One request at a time, so a reply can only answer the request before it.
    this.queue = Promise.resolve();
  }

  #receive(message) {
    // Lock notices arrive unasked. The popup asks afresh each time it opens, so they are not needed.
    if (message?.action === "database-locked" || message?.action === "database-unlocked") return;
    const waiting = this.waiting;
    if (!waiting) return;
    // An error is the answer whatever action it names; the app names none for a request it could
    // not parse.
    if (message?.action !== waiting.action && !message?.errorCode) return;
    this.waiting = null;
    clearTimeout(waiting.timer);
    waiting.resolve(message);
  }

  #send(action, body) {
    if (this.closed) return Promise.reject(new Disconnected());
    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => {
        if (this.waiting?.timer !== timer) return;
        this.waiting = null;
        reject(new ProtocolError("timeout", "Sennel did not answer"));
      }, WAIT_MS);
      this.waiting = { action, resolve, reject, timer };
      try {
        this.port.postMessage(body);
      } catch {
        clearTimeout(timer);
        this.waiting = null;
        reject(new Disconnected());
      }
    });
  }

  #serial(work) {
    const run = this.queue.then(work, work);
    this.queue = run.catch(() => {});
    return run;
  }

  // Exchanges session keys. Also learns whether the app is Sennel, which marks its reply.
  exchange() {
    return this.#serial(async () => {
      const nonce = this.random(24);
      const reply = await this.#send("change-public-keys", {
        action: "change-public-keys",
        publicKey: b64(this.keys.publicKey),
        nonce: b64(nonce),
        clientID: this.id,
      });
      if (reply.errorCode) throw new ProtocolError(reply.errorCode, reply.error);
      if (reply.nonce !== b64(increment(nonce))) throw new ProtocolError("nonce", "reply does not match");
      this.server = unb64(reply.publicKey);
      this.sennel = Number(reply.sennel ?? 0) >= 1;
    });
  }

  // One encrypted request. Resolves with the decrypted reply, or rejects with its error.
  request(action, fields = {}) {
    return this.#serial(async () => {
      if (!this.server) throw new ProtocolError("keys", "keys were not exchanged");
      const nonce = this.random(24);
      const inner = new TextEncoder().encode(JSON.stringify({ action, ...fields }));
      const sealed = nacl.box(inner, nonce, this.server, this.keys.secretKey);
      const reply = await this.#send(action, {
        action,
        message: b64(sealed),
        nonce: b64(nonce),
        clientID: this.id,
      });
      if (reply.errorCode) throw new ProtocolError(reply.errorCode, reply.error);
      const expected = b64(increment(nonce));
      if (reply.nonce !== expected || !reply.message) throw new ProtocolError("nonce", "reply does not match");
      const opened = nacl.box.open(unb64(reply.message), unb64(reply.nonce), this.server, this.keys.secretKey);
      if (!opened) throw new ProtocolError("decrypt", "reply could not be read");
      const body = JSON.parse(new TextDecoder().decode(opened));
      if (body.nonce !== expected || body.success !== "true") throw new ProtocolError("nonce", "reply does not match");
      return body;
    });
  }

  publicKey() {
    return b64(this.keys.publicKey);
  }

  close() {
    this.closed = true;
    try {
      this.port.disconnect();
    } catch {
      // Already gone.
    }
  }
}

// A new identification key for pairing. The protocol only ever uses its public half.
export function identity() {
  return { key: b64(nacl.box.keyPair().publicKey) };
}

export { b64, unb64 };
