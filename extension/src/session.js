// The protocol steps, run in the background worker so they outlive the popup: Sennel's dialogs take
// focus, the browser closes the popup, and a pairing or an answer must not be lost with it.
import { Client, Disconnected, NATIVE_HOST, identity } from "./client.js";
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

// The last list per tab, with the connection that fetched it: get-totp serves only entries that
// connection was given, and reopening the popup should not ask the user again. Kept two minutes.
const KEEP_MS = 120_000;
const recent = new Map();

function forget(tabId) {
  const held = recent.get(tabId);
  if (!held) return;
  clearTimeout(held.timer);
  held.client.close();
  recent.delete(tabId);
}

function keep(tab, client, pairing, entries) {
  forget(tab.id);
  const timer = setTimeout(() => forget(tab.id), KEEP_MS);
  recent.set(tab.id, { tab, client, pairing, entries, timer });
}

async function connect() {
  const client = new Client(api.runtime.connectNative(NATIVE_HOST));
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

async function fetchLogins(client, pairing, tab) {
  try {
    const reply = await client.request("get-logins", { url: tab.url, keys: [{ id: pairing.id, key: pairing.key }] });
    return reply.entries ?? [];
  } catch (e) {
    if (e.code === "15") return [];
    throw e;
  }
}

// What the popup is shown: never a password.
const shown = (entries) => entries.map(({ uuid, name, login }) => ({ uuid, name, login }));

export async function list(tab) {
  if (!fillable(tab?.url)) return { stage: "nopage" };
  const held = recent.get(tab.id);
  if (held && samePage(held.tab, tab) && !held.client.closed) {
    return { stage: "list", entries: shown(held.entries) };
  }
  const client = await connect();
  const pairing = await prove(client);
  if (!pairing) {
    client.close();
    return { stage: "unpaired" };
  }
  const entries = await fetchLogins(client, pairing, tab);
  keep(tab, client, pairing, entries);
  return { stage: "list", entries: shown(entries) };
}

export async function pair(tab) {
  const client = await connect();
  const id = identity();
  const reply = await client.request("associate", { key: client.publicKey(), idKey: id.key });
  const pairing = { id: reply.id, key: id.key, hash: reply.hash };
  await remember(pairing);
  const entries = await fetchLogins(client, pairing, tab);
  keep(tab, client, pairing, entries);
  return { stage: "list", entries: shown(entries) };
}

// R1 and R3: reached only from a click in the popup, and only into the top frame.
export async function fill(tab, uuid, current) {
  const held = recent.get(tab.id);
  const entry = held?.entries.find((e) => e.uuid === uuid);
  if (!entry || !samePage(held.tab, current)) return { filled: 0, moved: true };
  const target = { tabId: tab.id, allFrames: false };
  await api.scripting.executeScript({ target, files: ["fill.js"] });
  const [result] = await api.scripting.executeScript({
    target,
    func: (login, password, expected) => globalThis.sennel.fill(login, password, expected),
    args: [entry.login, entry.password, held.tab.url],
  });
  return result?.result ?? { filled: 0, moved: false };
}

// R7: the code of the row the user picked, by its uuid, on the connection that listed it.
export async function code(tab, uuid) {
  let held = recent.get(tab.id);
  if (!held || held.client.closed) {
    await list(tab);
    held = recent.get(tab.id);
  }
  if (!held) throw new Disconnected();
  const { totp } = await held.client.request("get-totp", { uuid });
  return totp || null;
}
