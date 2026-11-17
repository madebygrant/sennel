<script>
  import { onMount, tick } from "svelte";

  const api = globalThis.browser ?? globalThis.chrome;

  // loading, nopage, offline, locked, unpaired, pairing, list, or error
  let stage = $state("loading");
  let note = $state("");
  let good = $state(false);
  let entries = $state([]);
  let host = $state("");
  let needle = $state("");
  // Cross-origin frames with a login form, offered by origin (R3).
  let others = $state([]);
  let list = $state();
  let search = $state();
  let target;

  // A filter only earns its place once a site has more logins than fit at a glance.
  const SEARCH_FROM = 4;
  const shown = $derived.by(() => {
    const words = needle.trim().toLowerCase().split(/\s+/).filter(Boolean);
    return entries.filter((e) => words.every((w) => `${e.name} ${e.login}`.toLowerCase().includes(w)));
  });

  async function activeTab() {
    const [t] = await api.tabs.query({ active: true, currentWindow: true });
    // The worker decides what may be filled; this only skips the browser's own pages.
    return t && /^https?:/.test(t.url ?? "") ? { id: t.id, frameId: 0, url: t.url } : null;
  }

  // The background worker does the work, so a Sennel dialog that closes this popup loses nothing.
  async function ask(op, extra = {}) {
    try {
      return await api.runtime.sendMessage({ op, target, ...extra });
    } catch (e) {
      return { stage: "error", note: e?.message ?? String(e) };
    }
  }

  async function show(reply) {
    if (reply?.stage) stage = reply.stage;
    if (reply?.entries) entries = reply.entries;
    say(reply?.note ?? "");
    if (stage === "list") {
      await tick();
      (search ?? list?.querySelector("button"))?.focus();
    }
  }

  function say(text, ok = false) {
    note = text;
    good = ok;
  }

  async function load() {
    target = await activeTab();
    if (!target) {
      stage = "nopage";
      return;
    }
    host = new URL(target.url).host;
    // Side by side: the frames are known at once, while the list may wait on a Sennel dialog.
    const framesAsked = ask("frames", { tabId: target.id }).then((found) => {
      if (Array.isArray(found)) others = found.filter((f) => f.crossOrigin);
    });
    await show(await ask("list"));
    await framesAsked;
  }

  // The user picked a frame by its origin: its logins are listed and filled there alone.
  async function useFrame(frame) {
    target = { id: target.id, frameId: frame.frameId, url: frame.url };
    host = new URL(frame.url).host;
    others = [];
    stage = "loading";
    await show(await ask("list"));
  }

  async function connectBrowser() {
    stage = "pairing";
    await show(await ask("pair"));
  }

  async function choose(entry) {
    const out = await ask("fill", { uuid: entry.uuid, current: await activeTab() });
    if (out?.stage) show(out);
    else if (out?.moved) say("The page changed since this list was made. Open Sennel again.");
    else if (!out?.filled) say("No visible login fields on this page.");
    else window.close();
  }

  async function code(entry) {
    const out = await ask("code", { uuid: entry.uuid });
    if (out?.stage) return show(out);
    if (!out?.totp) return say("This login has no one-time code.");
    await navigator.clipboard.writeText(out.totp);
    say(`Code for ${entry.name || entry.login} copied.`, true);
  }

  // Up and down move between logins, from the search box too; Enter in the box fills the first.
  function keys(e) {
    const rows = [...(list?.querySelectorAll(".fill") ?? [])];
    const at = rows.indexOf(document.activeElement);
    if (e.key === "ArrowDown" || e.key === "ArrowUp") {
      e.preventDefault();
      const next = e.key === "ArrowDown" ? Math.min(at + 1, rows.length - 1) : at - 1;
      (next < 0 ? search : rows[next])?.focus();
    } else if (e.key === "Enter" && e.target === search && shown.length) {
      e.preventDefault();
      choose(shown[0]);
    }
  }

  const initial = (entry) => (entry.name || entry.login || "?").trim().charAt(0).toUpperCase();

  onMount(load);
</script>

{#snippet message(title, hint)}
  <div class="state">
    <p class="title">{title}</p>
    {#if hint}<p class="hint">{hint}</p>{/if}
  </div>
{/snippet}

<svelte:window onkeydown={keys} />

<main>
  <header>
    <svg class="mark" viewBox="0 0 24 24" aria-hidden="true">
      <polygon points="12,2 21,7 21,17 12,22 3,17 3,7" fill="none" stroke="currentColor" stroke-width="2" />
      <circle cx="12" cy="10.5" r="2.4" fill="currentColor" />
      <rect x="10.8" y="11.5" width="2.4" height="5" rx="1" fill="currentColor" />
    </svg>
    <h1>Sennel</h1>
    {#if host}<span class="host" title={host}>{host}</span>{/if}
  </header>

  {#if stage === "loading"}
    <div class="state"><p class="hint pulse">Asking Sennel…</p></div>
  {:else if stage === "pairing"}
    {@render message("Confirm in Sennel", "Sennel is asking whether to connect this browser. Answer there, then open this again.")}
  {:else if stage === "nopage"}
    {@render message("Nothing to fill here", "Open a web page with a login form.")}
  {:else if stage === "offline"}
    {@render message("Sennel isn't running", "Open the Sennel app, then try again.")}
  {:else if stage === "locked"}
    {@render message("The vault is locked", "Unlock it in Sennel, then try again.")}
  {:else if stage === "unpaired"}
    <div class="state">
      <p class="title">Connect this browser</p>
      <p class="hint">Sennel asks you to confirm in the app. Logins stay in Sennel until you fill one.</p>
      <button class="primary" onclick={connectBrowser}>Connect</button>
    </div>
  {:else if stage === "list"}
    {#if entries.length >= SEARCH_FROM}
      <input class="search" type="search" placeholder="Search {entries.length} logins" aria-label="Search logins" bind:value={needle} bind:this={search} />
    {/if}
    {#if shown.length}
      <ul bind:this={list}>
        {#each shown as entry (entry.uuid)}
          <li>
            <button class="fill" title="Fill {entry.login}" onclick={() => choose(entry)}>
              <span class="badge" aria-hidden="true">{initial(entry)}</span>
              <span class="names">
                <span class="name">{entry.name || host}</span>
                <span class="login">{entry.login}</span>
              </span>
            </button>
            {#if entry.code !== false}
              <button class="code" title="Copy the one-time code" aria-label="Copy the one-time code for {entry.name || entry.login}" onclick={() => code(entry)}>
                <svg viewBox="0 0 24 24" aria-hidden="true"><circle cx="12" cy="13" r="8" fill="none" stroke="currentColor" stroke-width="2" /><path d="M12 9v4l2.5 2M9 2h6" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" /></svg>
              </button>
            {/if}
          </li>
        {/each}
      </ul>
    {:else if entries.length}
      {@render message("No match", `Nothing here matches “${needle}”.`)}
    {:else}
      {@render message("No logins for this site", `Add one in Sennel with the address ${host}.`)}
    {/if}
  {:else}
    {@render message("Something went wrong", note)}
  {/if}

  {#if others.length}
    <section class="frames">
      <h2>In a frame on this page</h2>
      {#each others as frame (frame.frameId)}
        <button class="frame" onclick={() => useFrame(frame)}>
          <span>Login form from</span>
          <strong>{new URL(frame.url).origin}</strong>
        </button>
      {/each}
    </section>
  {/if}

  {#if note && stage !== "error"}<p class="note" class:good role="status">{note}</p>{/if}
</main>
