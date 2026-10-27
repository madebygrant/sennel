<script>
  import { onMount } from "svelte";
  import { call } from "./api.js";
  import EntryForm from "./EntryForm.svelte";
  import Sheet from "./Sheet.svelte";

  let { status, say, refresh } = $props();

  let groups = $state([]);
  let group = $state(null);
  let needle = $state("");
  let rows = $state([]);
  let selected = $state(null);
  let detail = $state(null);
  // Set only on an explicit reveal and dropped on every change of entry.
  let revealed = $state(null);
  let form = $state(null);
  let sheet = $state(null);
  let prompt = $state(null);
  let searchBox;

  const current = $derived(groups.find((g) => g.id === group));

  async function loadTree() {
    groups = await call("tree");
    if (!groups.some((g) => g.id === group)) group = groups[0]?.id ?? null;
  }

  async function loadRows() {
    rows = await call("entries", { group, needle: needle || null });
    if (!rows.some((r) => r.id === selected)) await pick(rows[0]?.id ?? null);
  }

  async function pick(id) {
    selected = id;
    revealed = null;
    detail = id ? await call("entry", { id }).catch(() => null) : null;
  }

  async function reload() {
    await loadTree();
    await loadRows();
    if (selected) await pick(selected);
    await refresh();
  }

  async function act(cmd, args = {}) {
    try {
      const reply = await call(cmd, args);
      say(reply.notes ?? [reply]);
      await reload();
      return reply;
    } catch (why) {
      say([{ level: "error", text: String(why) }]);
    }
  }

  async function copy(field) {
    if (!selected) return;
    say([await call("copy", { id: selected, field })]);
    await refresh();
  }

  async function toggleReveal() {
    revealed = revealed === null ? await call("reveal", { id: selected }) : null;
  }

  async function saved(reply) {
    form = null;
    if (reply?.select) await pick(reply.select);
    await reload();
  }

  function askGroup(kind) {
    prompt = { kind, value: kind === "rename" ? current?.name ?? "" : "" };
  }

  async function submitPrompt(event) {
    event.preventDefault();
    const { kind, value, what, id } = prompt;
    prompt = null;
    if (kind === "delete") {
      await act(what === "entry" ? "delete_entry" : "delete_group", { id });
      return;
    }
    const reply =
      kind === "rename"
        ? await act("rename_group", { id: group, name: value })
        : await act("add_group", { parent: group, name: value });
    if (reply?.select) {
      group = reply.select;
      await loadRows();
    }
  }

  function confirmDelete(what) {
    const name = what === "entry" ? detail?.title : current?.name;
    const forever = what === "entry" ? detail?.recycled : current?.bin;
    prompt = { kind: "delete", what, id: what === "entry" ? selected : group, name, forever };
  }

  function dropOn(target, event) {
    event.preventDefault();
    const id = event.dataTransfer.getData("text/sennel-entry");
    if (id) act("move_entry", { id, group: target });
  }

  function keys(event) {
    if (form || sheet || prompt) return;
    const mod = event.metaKey || event.ctrlKey;
    // In a text box the usual editing keys keep their meaning; only search and lock stay global.
    const typing = event.target.closest?.("input, textarea");
    if (typing && !(mod && (event.key === "f" || event.key === "l"))) return;
    if (mod && event.key === "f") {
      event.preventDefault();
      searchBox?.focus();
    } else if (mod && event.key === "l") {
      event.preventDefault();
      act("lock");
    } else if (mod && event.key === "z") {
      event.preventDefault();
      act("undo");
    } else if (mod && event.key === "n") {
      event.preventDefault();
      form = { group };
    } else if (mod && event.key === "c" && selected && !window.getSelection()?.toString()) {
      event.preventDefault();
      copy("password");
    } else if (mod && event.key === "b" && selected) {
      event.preventDefault();
      copy("username");
    }
  }

  onMount(reload);
</script>

<svelte:window onkeydown={keys} />

<div class="shell">
  <header>
    <button class="primary" onclick={() => (form = { group })}>New entry</button>
    <button onclick={() => askGroup("add")}>New group</button>
    <span class="gap"></span>
    <button onclick={() => (sheet = { kind: "audit" })}>Audit</button>
    <button onclick={async () => (sheet = { kind: "generate", value: await call("generate") })}>Generate</button>
    <button onclick={() => act("undo")} disabled={!status.undo} title={status.undo ? `undo: ${status.undo}` : ""}>Undo</button>
    <button onclick={() => act("save")}>Save</button>
    <button onclick={() => act("lock")}>Lock</button>
  </header>

  {#if status.conflict}
    <div class="conflict level-error">
      The vault changed on disk and this session's changes were not written.
      <button onclick={() => act("merge")}>Merge both</button>
      <button onclick={() => act("save")}>Overwrite theirs</button>
      <button class="danger" onclick={() => act("reload")}>Reload theirs</button>
    </div>
  {/if}

  <nav aria-label="Groups">
    <ul>
      {#each groups as g (g.id)}
        <li>
          <button
            class="group depth-{Math.min(g.depth, 8)}"
            class:active={g.id === group}
            onclick={() => {
              group = g.id;
              needle = "";
              loadRows();
            }}
            ondragover={(e) => e.preventDefault()}
            ondrop={(e) => dropOn(g.id, e)}
          >
            <span>{g.bin ? "🗑 " : ""}{g.name}</span>
            <span class="dim">{g.entries || ""}</span>
          </button>
        </li>
      {/each}
    </ul>
    {#if current}
      <div class="group-actions">
        <button onclick={() => askGroup("rename")} disabled={current.depth === 0}>Rename</button>
        <button onclick={() => act("reparent", { id: group, deeper: true })} disabled={current.depth === 0} title="Into the group above">→</button>
        <button onclick={() => act("reparent", { id: group, deeper: false })} disabled={current.depth < 2} title="Out one level">←</button>
        <button class="danger" onclick={() => confirmDelete("group")} disabled={current.depth === 0}>Delete</button>
      </div>
    {/if}
  </nav>

  <section class="list" aria-label="Entries">
    <input bind:this={searchBox} bind:value={needle} oninput={loadRows} placeholder="Search the whole vault  ⌘F" spellcheck="false" />
    <ul>
      {#each rows as r (r.id)}
        <li>
          <button
            class="entry"
            class:active={r.id === selected}
            onclick={() => pick(r.id)}
            ondblclick={() => copy("password")}
            draggable="true"
            ondragstart={(e) => e.dataTransfer.setData("text/sennel-entry", r.id)}
          >
            <strong>{r.title || "(untitled)"}</strong>
            <span class="dim">{r.username}</span>
          </button>
        </li>
      {:else}
        <li class="empty dim">{needle ? "nothing matches" : "no entries here"}</li>
      {/each}
    </ul>
  </section>

  <article aria-label="Entry">
    {#if detail}
      <h2>{detail.title || "(untitled)"}</h2>
      <p class="dim">{detail.group || "Root"}{detail.recycled ? " · in the recycle bin" : ""}</p>
      <dl>
        <dt>Username</dt>
        <dd><span class="value">{detail.username}</span><button onclick={() => copy("username")} disabled={!detail.username}>Copy</button></dd>
        <dt>Password</dt>
        <dd>
          <!-- Not selectable: a native copy would skip the clipboard clear, so Copy is the way out. -->
          <span class="value mono secret">{revealed ?? (detail.hasPassword ? "••••••••••" : "")}</span>
          <button onclick={toggleReveal} disabled={!detail.hasPassword}>{revealed === null ? "Show" : "Hide"}</button>
          <button class="primary" onclick={() => copy("password")} disabled={!detail.hasPassword}>Copy</button>
        </dd>
        {#if detail.url}
          <dt>URL</dt>
          <dd><span class="value">{detail.url}</span><button onclick={() => copy("url")}>Copy</button></dd>
        {/if}
        {#if detail.hasOtp}
          <dt>One-time code</dt>
          <dd><span class="value dim">copied, never shown</span><button onclick={() => copy("otp")}>Copy</button></dd>
        {/if}
        {#if detail.tags}
          <dt>Tags</dt>
          <dd><span class="value">{detail.tags}</span></dd>
        {/if}
        {#if detail.expires}
          <dt>Expires</dt>
          <dd><span class="value">{detail.expires}</span></dd>
        {/if}
      </dl>
      {#if detail.notes}
        <pre class="notes">{detail.notes}</pre>
      {/if}
      <div class="entry-actions">
        <button onclick={() => (form = { id: detail.id, detail })}>Edit</button>
        <button onclick={() => (sheet = { kind: "fields", id: detail.id })}>Fields{detail.extras ? ` (${detail.extras})` : ""}</button>
        <button onclick={() => (sheet = { kind: "history", id: detail.id })}>History</button>
        <span class="gap"></span>
        <button class="danger" onclick={() => confirmDelete("entry")}>{detail.recycled ? "Delete for good" : "Delete"}</button>
      </div>
    {:else}
      <p class="dim empty">Select an entry</p>
    {/if}
  </article>
</div>

{#if form}
  <EntryForm {form} {say} close={saved} />
{/if}

{#if sheet}
  <Sheet {sheet} {say} {reload} close={() => (sheet = null)} open={(id) => { sheet = null; group = null; needle = ""; pick(id); }} />
{/if}

{#if prompt}
  <div class="scrim">
    <form class="prompt" onsubmit={submitPrompt}>
      {#if prompt.kind === "delete"}
        <p>
          {prompt.forever ? "Delete for good" : "Move to the recycle bin"}: <strong>{prompt.name || "(untitled)"}</strong>?
          {#if prompt.forever}<br /><span class="level-warn">This cannot be undone.</span>{/if}
        </p>
      {:else}
        <label>
          {prompt.kind === "rename" ? "Rename group" : `New group in ${current?.name ?? "Root"}`}
          <!-- svelte-ignore a11y_autofocus -->
          <input bind:value={prompt.value} autofocus />
        </label>
      {/if}
      <div class="row">
        <button type="button" onclick={() => (prompt = null)}>Cancel</button>
        <button class={prompt.kind === "delete" ? "danger" : "primary"} type="submit">{prompt.kind === "delete" ? "Delete" : "Save"}</button>
      </div>
    </form>
  </div>
{/if}

<style>
  .shell {
    height: calc(100% - 30px);
    display: grid;
    grid-template: auto auto 1fr / 220px minmax(240px, 1fr) minmax(300px, 1.3fr);
    grid-template-areas: "head head head" "warn warn warn" "nav list detail";
  }

  header {
    grid-area: head;
    display: flex;
    gap: 8px;
    padding: 10px 12px;
    border-bottom: 1px solid var(--line);
    background: var(--panel);
  }

  .gap {
    flex: 1;
  }

  .conflict {
    grid-area: warn;
    display: flex;
    gap: 10px;
    align-items: center;
    padding: 8px 12px;
    border-bottom: 1px solid var(--line);
  }

  nav,
  .list,
  article {
    overflow: auto;
    min-height: 0;
  }

  nav {
    grid-area: nav;
    border-right: 1px solid var(--line);
    padding: 8px 6px;
    display: flex;
    flex-direction: column;
  }

  ul {
    list-style: none;
    margin: 0;
    padding: 0;
  }

  .group,
  .entry {
    width: 100%;
    text-align: left;
    background: none;
    border: 1px solid transparent;
    display: flex;
    justify-content: space-between;
    gap: 8px;
  }

  .group.active,
  .entry.active {
    background: var(--raised);
    border-color: var(--line);
  }

  .depth-1 { padding-left: 22px; }
  .depth-2 { padding-left: 34px; }
  .depth-3 { padding-left: 46px; }
  .depth-4 { padding-left: 58px; }
  .depth-5 { padding-left: 70px; }
  .depth-6 { padding-left: 82px; }
  .depth-7 { padding-left: 94px; }
  .depth-8 { padding-left: 106px; }

  .group-actions {
    margin-top: auto;
    display: flex;
    gap: 4px;
    padding-top: 8px;
  }

  .group-actions button {
    padding: 4px 7px;
    font-size: 12px;
  }

  .list {
    grid-area: list;
    border-right: 1px solid var(--line);
    padding: 8px;
  }

  .list input {
    margin-bottom: 8px;
  }

  .entry {
    flex-direction: column;
    gap: 0;
  }

  .entry span {
    font-size: 12.5px;
  }

  .empty {
    padding: 12px;
  }

  article {
    grid-area: detail;
    padding: 16px 18px;
  }

  h2 {
    margin: 0;
    font-size: 19px;
  }

  article > p {
    margin: 2px 0 14px;
    font-size: 12.5px;
  }

  dl {
    display: grid;
    grid-template-columns: max-content 1fr;
    gap: 8px 14px;
    margin: 0;
    align-items: center;
  }

  dt {
    color: var(--dim);
    font-size: 12.5px;
  }

  dd {
    margin: 0;
    display: flex;
    gap: 6px;
    align-items: center;
    min-width: 0;
  }

  .value {
    flex: 1;
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
    -webkit-user-select: text;
    user-select: text;
  }

  .value.secret {
    -webkit-user-select: none;
    user-select: none;
  }

  .notes {
    margin: 16px 0 0;
    padding: 10px;
    background: var(--panel);
    border-radius: var(--radius);
    white-space: pre-wrap;
    font: 13px/1.5 var(--mono);
    -webkit-user-select: text;
    user-select: text;
  }

  .entry-actions {
    display: flex;
    gap: 8px;
    margin-top: 18px;
  }

  .scrim {
    position: fixed;
    inset: 0;
    background: rgb(0 0 0 / 0.45);
    display: grid;
    place-items: center;
  }

  .prompt {
    background: var(--panel);
    border: 1px solid var(--line);
    border-radius: 10px;
    padding: 18px;
    width: min(380px, 92vw);
    display: grid;
    gap: 14px;
  }

  .prompt label {
    display: grid;
    gap: 6px;
  }

  .prompt p {
    margin: 0;
  }

  .row {
    display: flex;
    justify-content: flex-end;
    gap: 8px;
  }
</style>
