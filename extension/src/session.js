// The protocol steps, run in the background worker so they outlive the popup: Sennel's dialogs take
// focus, the browser closes the popup, and a pairing or an answer must not be lost with it.
// A target is one frame of one tab: { id, frameId, url }.
import { Client, Disconnected, NATIVE_HOST, identity } from "./client.js";
import { fakePort } from "./fake-app.js";
import { fillable, samePage } from "./page.js";

const api = globalThis.browser ?? globalThis.chrome;

// Pairings this browser made, newest first: the name Sennel gave, the public key and the vault's
// hash. The identification key's secret half is never used by the protocol, so it is not kept.
async function pairings() {
  const { pairings = [] } = await api.storage.local.get("pairings");
  return pairings;
}

async function remember(pairing) {
  const list = (await pairings()).filter((p) => p.hash !== pairing.hash);
  await api.storage.local.set({ pairings: [pairing, ...list] });
}

// The last list per frame, with the connection that fetched it: get-totp serves only entries that
// connection was given, and asking again should not ask the user again. Kept two minutes.
const KEEP_MS = 120_000;
const recent = new Map();
const keyOf = (target) => `${target.id}:${target.frameId ?? 0}`;

function forget(key) {
  const held = recent.get(key);
  if (!held) return;
  clearTimeout(held.timer);
  held.client.close();
  recent.delete(key);
}

function keep(target, client, pairing, entries) {
  const key = keyOf(target);
  forget(key);
  const timer = setTimeout(() => forget(key), KEEP_MS);
  recent.set(key, { target, client, pairing, entries, timer });
}

async function connect() {
  const port = __FAKE_APP__ ? fakePort() : api.runtime.connectNative(NATIVE_HOST);
  const client = new Client(port);
  await client.exchange();
  return client;
}

// Sennel gives the vault's hash only after a pairing is shown, so every saved pairing is tried. A
// KeePassXC-style app is asked for the hash first and only its own pairing is tried. Only "not
// paired" moves on to the next; a locked vault or a dropped connection is reported as it is.
async function prove(client) {
  let saved = await pairings();
  if (!client.sennel) {
    const { hash } = await client.request("get-databasehash");
    saved = saved.filter((p) => p.hash === hash);
  }
  for (const pairing of saved) {
    try {
      await client.request("test-associate", { id: pairing.id, key: pairing.key });
      return pairing;
    } catch (e) {
      if (e.code !== "8") throw e;
    }
  }
  return null;
}

async function fetchLogins(client, pairing, target) {
  try {
    const reply = await client.request("get-logins", { url: target.url, keys: [{ id: pairing.id, key: pairing.key }] });
    return reply.entries ?? [];
  } catch (e) {
    if (e.code === "15") return [];
    throw e;
  }
}

// What a list is shown as: never a password.
const shown = (entries) => entries.map(({ uuid, name, login }) => ({ uuid, name, login }));

function held(target) {
  const found = recent.get(keyOf(target));
  return found && samePage(found.target, target) && !found.client.closed ? found : null;
}

export async function list(target) {
  if (!fillable(target?.url)) return { stage: "nopage" };
  const cached = held(target);
  if (cached) return { stage: "list", entries: shown(cached.entries) };
  const client = await connect();
  const pairing = await prove(client);
  if (!pairing) {
    client.close();
    return { stage: "unpaired" };
  }
  const entries = await fetchLogins(client, pairing, target);
  keep(target, client, pairing, entries);
  return { stage: "list", entries: shown(entries) };
}

// Only from the toolbar popup: a page can never start a pairing.
export async function pair(target) {
  const client = await connect();
  const id = identity();
  const reply = await client.request("associate", { key: client.publicKey(), idKey: id.key });
  const pairing = { id: reply.id, key: id.key, hash: reply.hash };
  await remember(pairing);
  const entries = await fetchLogins(client, pairing, target);
  keep(target, client, pairing, entries);
  return { stage: "list", entries: shown(entries) };
}

// The login for one row, for the in-page list in the frame that showed it (R1: after a trusted
// click there). Only for the page and frame the list was fetched for (R2).
// A list that timed out or lost its connection is expired, not moved: the page closes it and the
// next click on its button lists again.
export function credentials(target, uuid) {
  const kept = recent.get(keyOf(target));
  if (kept && !samePage(kept.target, target)) return { moved: true };
  const entry = held(target)?.entries.find((e) => e.uuid === uuid);
  return entry ? { login: entry.login, password: entry.password } : { expired: true };
}

// The popup's fill: into one frame only (R3), the top one unless the user picked a frame by origin.
export async function fill(target, uuid, current) {
  const cached = held(target);
  const entry = cached?.entries.find((e) => e.uuid === uuid);
  if (!entry || !current || current.id !== target.id) return { filled: 0, moved: true };
  const where = { tabId: target.id, frameIds: [target.frameId ?? 0] };
  await api.scripting.executeScript({ target: where, files: ["content.js"] });
  const [result] = await api.scripting.executeScript({
    target: where,
    func: (login, password, expected) => globalThis.sennel.fill(login, password, expected),
    args: [entry.login, entry.password, cached.target.url],
  });
  return result?.result ?? { filled: 0, moved: false };
}

// R7: the code of the row the user picked, by its uuid, on the connection that listed it.
export async function code(target, uuid) {
  if (!held(target)) await list(target);
  const cached = held(target);
  if (!cached) throw new Disconnected();
  const { totp } = await cached.client.request("get-totp", { uuid });
  return totp || null;
}

// The frames of a tab that hold a login form, for the popup to offer by origin.
export async function frames(tabId) {
  const everywhere = { tabId, allFrames: true };
  try {
    await api.scripting.executeScript({ target: everywhere, files: ["content.js"] });
    const results = await api.scripting.executeScript({ target: everywhere, func: () => globalThis.sennel?.summary() });
    return results.map((r) => ({ frameId: r.frameId, ...r.result })).filter((f) => f.url && f.fields && fillable(f.url));
  } catch {
    return [];
  }
}
