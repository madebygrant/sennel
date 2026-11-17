<script>
  import { onMount } from "svelte";

  const api = globalThis.browser ?? globalThis.chrome;

  // loading, nopage, offline, locked, unpaired, pairing, list, or error
  let stage = $state("loading");
  let note = $state("");
  let entries = $state([]);
  let host = $state("");
  let tab;

  async function activeTab() {
    const [t] = await api.tabs.query({ active: true, currentWindow: true });
    // The worker decides what may be filled; this only skips the browser's own pages.
    return t && /^https?:/.test(t.url ?? "") ? { id: t.id, url: t.url } : null;
  }

  // The background worker does the work, so a Sennel dialog that closes this popup loses nothing.
  async function ask(op, extra = {}) {
    try {
      return await api.runtime.sendMessage({ op, tab, ...extra });
    } catch (e) {
      return { stage: "error", note: e?.message ?? String(e) };
    }
  }

  function show(reply) {
    if (reply?.stage) stage = reply.stage;
    if (reply?.entries) entries = reply.entries;
    note = reply?.note ?? "";
  }

  async function load() {
    tab = await activeTab();
    if (!tab) {
      stage = "nopage";
      return;
    }
    host = new URL(tab.url).host;
    show(await ask("list"));
  }

  async function connectBrowser() {
    stage = "pairing";
    show(await ask("pair"));
  }

  async function choose(entry) {
    const out = await ask("fill", { uuid: entry.uuid, current: await activeTab() });
    if (out?.stage) show(out);
    else if (out?.moved) note = "The page changed since this list was made. Open Sennel's popup again.";
    else if (!out?.filled) note = "No visible login fields on this page.";
    else window.close();
  }

  async function code(entry) {
    const out = await ask("code", { uuid: entry.uuid });
    if (out?.stage) return show(out);
    if (!out?.totp) {
      note = "This login has no one-time code.";
      return;
    }
    await navigator.clipboard.writeText(out.totp);
    note = "Code copied.";
  }

  onMount(load);
</script>

<main>
  <header>
    <img src="icons/32.png" alt="" width="18" height="18" />
    <h1>Sennel</h1>
    {#if host}<span class="host">{host}</span>{/if}
  </header>

  {#if stage === "loading" || stage === "pairing"}
    <p class="dim">{stage === "pairing" ? "Confirm in the Sennel window…" : "Asking Sennel…"}</p>
  {:else if stage === "nopage"}
    <p class="dim">Open a web page to fill a login.</p>
  {:else if stage === "offline"}
    <p>Sennel is not reachable.</p>
    <p class="dim">Open the Sennel app, then open this popup again.</p>
  {:else if stage === "locked"}
    <p>The vault is locked.</p>
    <p class="dim">Unlock it in Sennel, then open this popup again.</p>
  {:else if stage === "unpaired"}
    <p>This browser is not connected to the open vault.</p>
    <button class="primary" onclick={connectBrowser}>Connect</button>
  {:else if stage === "list"}
    {#if entries.length}
      <ul>
        {#each entries as entry (entry.uuid)}
          <li>
            <button class="row" onclick={() => choose(entry)}>
              <span class="title">{entry.name || host}</span>
              <span class="dim">{entry.login}</span>
            </button>
            <button class="code" title="Copy the one-time code" onclick={() => code(entry)}>Code</button>
          </li>
        {/each}
      </ul>
    {:else}
      <p class="dim">No logins for {host}.</p>
    {/if}
  {:else}
    <p class="error">{note}</p>
  {/if}

  {#if note && stage !== "error"}<p class="note" role="status">{note}</p>{/if}
</main>
