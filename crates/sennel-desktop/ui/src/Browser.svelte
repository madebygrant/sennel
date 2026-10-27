<script>
  import { onMount } from "svelte";
  import {
    CalendarClock,
    Check,
    Copy,
    CornerDownRight,
    CornerLeftUp,
    Eye,
    EyeOff,
    Folder,
    FolderOpen,
    FolderPlus,
    Globe,
    Lock,
    Paperclip,
    Pencil,
    Plus,
    RefreshCw,
    RotateCcwClock,
    Save,
    Search,
    ShieldAlert,
    Tag,
    Timer,
    Trash2,
    TriangleAlert,
    Undo2,
    User,
    Vault,
    WandSparkles,
  } from "@lucide/svelte";
  import { call } from "./api.js";
  import { copyFeedback } from "./copied.svelte.js";
  import Cells, { kind } from "./Cells.svelte";
  import EntryForm from "./EntryForm.svelte";
  import HexField from "./HexField.svelte";
  import Modal from "./Modal.svelte";
  import OtpCells from "./OtpCells.svelte";
  import Sheet from "./Sheet.svelte";

  let { status, say, refresh, clears } = $props();

  let groups = $state([]);
  let group = $state(null);
  let needle = $state("");
  let rows = $state([]);
  let selected = $state(null);
  let detail = $state(null);
  // Set only on an explicit reveal and dropped on every change of entry.
  let revealed = $state(null);
  let issues = $state({});
  let form = $state(null);
  let sheet = $state(null);
  let prompt = $state(null);
  let searchBox;

  const fb = copyFeedback();

  // A brief closing beat once the countdown runs out and the clipboard is wiped.
  let cleared = $state(false);
  let lastLeft = 0;
  let clearedTimer;
  $effect(() => {
    const left = clears.left;
    if (lastLeft > 0 && left === 0) {
      cleared = true;
      clearTimeout(clearedTimer);
      clearedTimer = setTimeout(() => (cleared = false), 2500);
    }
    if (left > 0) cleared = false;
    lastLeft = left;
  });


  const current = $derived(groups.find((g) => g.id === group));
  const chars = $derived(revealed === null ? null : [...revealed]);
  const attention = $derived(Object.keys(issues).length);
  const STRIP = 12;
  const lit = $derived(clears.total ? Math.ceil((clears.left / clears.total) * STRIP) : 0);
  const NAMES = { password: "Password", username: "Username", url: "Website", otp: "One-time code" };
  const held = $derived(status.clipboard && (NAMES[status.clipboard] ?? status.clipboard.replace(/^the /, "").replace(/^./, (c) => c.toUpperCase())));
  // The entry and field this window last copied, so that field drains in step with the strip.
  let copiedFrom = $state(null);
  const holding = (field) => clears.left > 0 && copiedFrom?.id === detail?.id && copiedFrom?.field === field && copiedFrom?.copy === clears.copies;

  // CSSOM, since the CSP refuses style attributes.
  function meter(node, fraction) {
    const set = (f) => node.style.setProperty("--held", f);
    set(fraction);
    return { update: set };
  }

  async function loadTree() {
    groups = await call("tree");
    if (!groups.some((g) => g.id === group)) group = groups[0]?.id ?? null;
  }

  async function loadRows() {
    rows = await call("entries", { group, needle: needle || null });
    if (!rows.some((r) => r.id === selected)) await pick(rows[0]?.id ?? null);
  }

  async function loadIssues() {
    const found = {};
    for (const r of await call("audit")) found[r.id] = found[r.id] ? `${found[r.id]}, ${r.issue}` : r.issue;
    issues = found;
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
    await loadIssues();
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
    const note = await call("copy", { id: selected, field });
    say([note]);
    await refresh();
    if (note.level !== "error") {
      copiedFrom = { id: selected, field, copy: clears.copies };
      fb.mark(field);
    }
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
    // The search box hands arrows, Enter and an unselected ⌘C to the list, so ⌘F, type, Enter copies.
    // Other text boxes keep their usual keys; only search and lock stay global there.
    const inSearch = event.target === searchBox;
    const typing = !inSearch && event.target.closest?.("input, textarea");
    if (typing && !(mod && (event.key === "f" || event.key === "l"))) return;
    if (inSearch) {
      const marked = searchBox.selectionStart !== searchBox.selectionEnd;
      if (event.key === "Escape") {
        event.preventDefault();
        if (needle) {
          needle = "";
          loadRows();
        } else searchBox.blur();
        return;
      }
      if (event.key === "Enter") {
        event.preventDefault();
        if (selected) copy("password");
        return;
      }
      if (mod && (event.key === "z" || event.key === "a" || (event.key === "c" && marked))) return;
    }
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
    } else if (mod && event.key === "o" && detail?.hasOtp) {
      event.preventDefault();
      copy("otp");
    } else if (!mod && (event.key === "ArrowDown" || event.key === "ArrowUp") && rows.length) {
      event.preventDefault();
      const at = rows.findIndex((r) => r.id === selected);
      const to = event.key === "ArrowDown" ? Math.min(at + 1, rows.length - 1) : Math.max(at - 1, 0);
      pick(rows[to].id);
    }
  }

  onMount(reload);
</script>

<svelte:window onkeydown={keys} />

<div class="shell">
  <header>
    <label class="search">
      <Search />
      <input bind:this={searchBox} bind:value={needle} oninput={loadRows} placeholder="Search the vault, #tag" spellcheck="false" aria-label="Search the vault" />
      <kbd>⌘F</kbd>
    </label>
    <span class="gap"></span>
    {#if clears.left}
      <span class="clip">
        <span class="strip" aria-hidden="true">{#each { length: STRIP } as _, i}<i class:off={i >= lit}></i>{/each}</span>
        <span>{held ?? "Copied text"} on the clipboard, clears in {clears.left}s</span>
        <button class="clear" onclick={async () => { await call("clear_clipboard"); await refresh(); }}>Clear now</button>
      </span>
    {:else if cleared}
      <span class="clip cleared"><Check />Clipboard cleared</span>
    {/if}
    <span class="sr" role="status">{cleared ? "Clipboard cleared" : ""}</span>
    <button class="tool" onclick={() => (form = { group })} title="New entry  ⌘N" aria-label="New entry"><Plus /></button>
    <button class="tool" onclick={() => askGroup("add")} title="New group" aria-label="New group"><FolderPlus /></button>
    <button class="tool" onclick={async () => (sheet = { kind: "generate", value: await call("generate") })} title="Generate a password" aria-label="Generate a password"><WandSparkles /></button>
    <button class="tool" onclick={() => act("undo")} disabled={!status.undo} title={status.undo ? `Undo ${status.undo}  ⌘Z` : "Nothing to undo"} aria-label="Undo"><Undo2 /></button>
    <button class="tool" onclick={() => act("save")} title="Save" aria-label="Save"><Save /></button>
    <button class="tool" onclick={() => act("lock")} title="Lock  ⌘L" aria-label="Lock"><Lock /></button>
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
    <HexField />
    <button class="group smart" class:alert={attention} onclick={() => (sheet = { kind: "audit" })}>
      <ShieldAlert /><span>Needs attention</span>
      <span class="count">{attention || ""}</span>
    </button>
    <ul>
      {#each groups as g (g.id)}
        <li>
          <button
            class="group depth-{Math.min(g.depth, 8)}"
            class:active={g.id === group}
            class:bin={g.bin}
            aria-current={g.id === group ? "true" : undefined}
            onclick={() => {
              group = g.id;
              needle = "";
              loadRows();
            }}
            ondragover={(e) => e.preventDefault()}
            ondrop={(e) => dropOn(g.id, e)}
          >
            {#if g.bin}<Trash2 />{:else if g.depth === 0}<Vault />{:else if g.id === group}<FolderOpen />{:else}<Folder />{/if}
            <span class="name">{g.name}</span>
            <span class="count">{g.entries || ""}</span>
          </button>
        </li>
      {/each}
    </ul>
    {#if current}
      <div class="group-actions">
        <button onclick={() => askGroup("rename")} disabled={current.depth === 0}><Pencil />Rename</button>
        <button onclick={() => act("reparent", { id: group, deeper: true })} disabled={current.depth === 0} title="Into the group above" aria-label="Into the group above"><CornerDownRight /></button>
        <button onclick={() => act("reparent", { id: group, deeper: false })} disabled={current.depth < 2} title="Out one level" aria-label="Out one level"><CornerLeftUp /></button>
        <button class="danger" onclick={() => confirmDelete("group")} disabled={current.depth === 0} title="Delete group" aria-label="Delete group"><Trash2 /></button>
      </div>
    {/if}
  </nav>

  <section class="list" aria-label="Entries">
    <ul>
      {#each rows as r (r.id)}
        <li>
          <button
            class="entry"
            class:active={r.id === selected}
            aria-current={r.id === selected ? "true" : undefined}
            onclick={() => pick(r.id)}
            ondblclick={() => copy("password")}
            draggable="true"
            ondragstart={(e) => e.dataTransfer.setData("text/sennel-entry", r.id)}
          >
            <span class="initial">{(r.title || "?").slice(0, 1).toUpperCase()}</span>
            <span class="names">
              <strong>{r.title || "(untitled)"}</strong>
              <span>{r.username}</span>
            </span>
            {#if issues[r.id]}<span class="flag" title={issues[r.id]}></span>{/if}
          </button>
        </li>
      {:else}
        <li class="empty dim">{needle ? "Nothing matches. Try fewer letters, or #tag." : "No entries here. ⌘N adds one."}</li>
      {/each}
    </ul>
  </section>

  <article aria-label="Entry">
    {#if detail}
      <div class="head">
        <span class="initial big">{(detail.title || "?").slice(0, 1).toUpperCase()}</span>
        <div>
          <h2>{detail.title || "(untitled)"}</h2>
          <p><Folder />{detail.group || "Root"}{detail.recycled ? ", in the recycle bin" : ""}</p>
        </div>
      </div>

      {#if issues[detail.id]}
        <div class="issue">
          <TriangleAlert />
          <span>{issues[detail.id]}</span>
          <button onclick={() => (form = { id: detail.id, detail })}><RefreshCw />Change it</button>
        </div>
      {/if}

      {#if detail.hasPassword}
        <div class="password" class:held={holding("password")} use:meter={clears.total ? clears.left / clears.total : 0} use:fb.spot={"password"}>
          <!-- Out of the tab order: the Copy button and ⌘C already cover the keyboard. -->
          <button class="grab" tabindex="-1" onclick={() => copy("password")} title="Click to copy" aria-label="Copy the password" aria-describedby="password-text">
            <Cells value={revealed} length={detail.passwordLength} textId="password-text" />
          </button>
          <div class="bar">
            <span class="meta">
              {#if chars}
                {chars.length} characters, {chars.filter((c) => kind(c) === "digit").length} digits, {chars.filter((c) => kind(c) === "symbol").length} symbols
              {:else}
                {detail.passwordLength} characters, hidden
              {/if}
            </span>
            <button class="icon" onclick={toggleReveal} title={revealed === null ? "Show" : "Hide"} aria-label={revealed === null ? "Show the password" : "Hide the password"}>
              {#if revealed === null}<Eye />{:else}<EyeOff />{/if}
            </button>
            <button class="primary icon" onclick={() => copy("password")} title="Copy the password  ⌘C" aria-label={fb.copied === "password" ? "Copied" : "Copy the password"}>
              {#if fb.copied === "password"}<Check />{:else}<Copy />{/if}<kbd>⌘C</kbd>
            </button>
          </div>
        </div>
      {/if}

      <div class="fields">
        {#if detail.username}
          <button class="field" class:done={fb.copied === "username"} class:held={holding("username")} use:meter={clears.total ? clears.left / clears.total : 0} use:fb.spot={"username"} onclick={() => copy("username")}>
            <span class="label"><User />Username</span><span class="value lit">{detail.username}</span>
            <span class="hint">{#if fb.copied === "username"}<Check />Copied{:else}<Copy />⌘B{/if}</span>
          </button>
        {/if}
        {#if detail.url}
          <button class="field" class:done={fb.copied === "url"} class:held={holding("url")} use:meter={clears.total ? clears.left / clears.total : 0} use:fb.spot={"url"} onclick={() => copy("url")}>
            <span class="label"><Globe />Website</span><span class="value lit">{detail.url}</span>
            <span class="hint">{#if fb.copied === "url"}<Check />Copied{:else}<Copy />{/if}</span>
          </button>
        {/if}
        {#if detail.hasOtp}
          <button class="field" class:done={fb.copied === "otp"} class:held={holding("otp")} use:meter={clears.total ? clears.left / clears.total : 0} use:fb.spot={"otp"} onclick={() => copy("otp")} title="Copied, never shown">
            <span class="label"><Timer />One-time code</span>{#if detail.otp}<span class="value"><OtpCells period={detail.otp.period} digits={detail.otp.digits} /></span>{:else}<span class="value quiet">Can't read this code</span>{/if}
            <span class="hint">{#if fb.copied === "otp"}<Check />Copied{:else}<Copy />⌘O{/if}</span>
          </button>
        {/if}
        {#if detail.tags}
          <div class="field still">
            <span class="label"><Tag />Tags</span>
            <span class="tags">{#each detail.tags.split(",").map((t) => t.trim()).filter(Boolean) as t}<span>{t}</span>{/each}</span>
          </div>
        {/if}
        {#if detail.expires}
          <div class="field still"><span class="label"><CalendarClock />Expires</span><span class="value">{detail.expires}</span></div>
        {/if}
      </div>

      {#if detail.notes}
        <pre class="notes">{detail.notes}</pre>
      {/if}

      <div class="entry-actions">
        <button class="icon" onclick={() => (form = { id: detail.id, detail })} title="Edit" aria-label="Edit"><Pencil /></button>
        <button class="icon" onclick={() => (sheet = { kind: "fields", id: detail.id })} title="Fields and attachments" aria-label={`Fields and attachments${detail.extras ? `, ${detail.extras}` : ""}`}>
          <Paperclip />{#if detail.extras}<span class="badge">{detail.extras}</span>{/if}
        </button>
        <button class="icon" onclick={() => (sheet = { kind: "history", id: detail.id })} title="History" aria-label="History"><RotateCcwClock /></button>
        <span class="gap"></span>
        <button class="danger icon" onclick={() => confirmDelete("entry")} title={detail.recycled ? "Delete for good" : "Move to the recycle bin"} aria-label={detail.recycled ? "Delete for good" : "Move to the recycle bin"}><Trash2 /></button>
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
  <Sheet {sheet} {say} {reload} {refresh} close={() => (sheet = null)} open={(id) => { sheet = null; group = null; needle = ""; pick(id); }} />
{/if}

{#if prompt}
  <Modal label={prompt.kind === "delete" ? "Delete" : "Group name"} onclose={() => (prompt = null)}>
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
        <!-- svelte-ignore a11y_autofocus -->
        <button type="button" onclick={() => (prompt = null)} autofocus={prompt.kind === "delete"}>Cancel</button>
        <button class={prompt.kind === "delete" ? "danger" : "primary"} type="submit">
          {prompt.kind !== "delete" ? "Save" : prompt.forever ? "Delete for good" : "Move to bin"}
        </button>
      </div>
    </form>
  </Modal>
{/if}

<style>
  .shell {
    height: calc(100% - 30px);
    display: grid;
    grid-template: auto auto minmax(0, 1fr) / 210px minmax(240px, 0.9fr) minmax(360px, 1.4fr);
    grid-template-areas: "head head head" "warn warn warn" "nav list detail";
  }

  header {
    grid-area: head;
    display: flex;
    align-items: center;
    gap: 6px;
    padding: 8px 12px;
    border-bottom: 1px solid var(--line);
  }

  .search {
    display: flex;
    align-items: center;
    gap: 8px;
    width: min(340px, 40vw);
    padding: 0 10px;
    background: var(--panel);
    color: var(--faint);
    border-radius: var(--radius);
  }

  .search input {
    background: none;
    border: 0;
    padding: 6px 0;
    outline: none;
  }

  .search:focus-within {
    background: var(--raised);
    color: var(--accent-text);
    box-shadow: 0 0 0 1px color-mix(in oklab, var(--accent-text) 55%, transparent);
  }

  kbd {
    font: 11px var(--mono);
    color: inherit;
    opacity: 0.8;
  }

  .gap {
    flex: 1;
  }

  .tool {
    width: 32px;
    height: 32px;
    padding: 0;
    display: grid;
    place-items: center;
    background: none;
    color: var(--dim);
  }

  .tool:hover:not(:disabled) {
    background: var(--panel);
    color: var(--text);
  }

  .clip {
    display: flex;
    align-items: center;
    gap: 10px;
    padding: 5px 12px;
    margin-right: 6px;
    background: var(--panel);
    border-radius: var(--radius);
    font-size: 12.5px;
    font-variant-numeric: tabular-nums;
  }

  .clip.cleared {
    color: var(--ok);
    background: color-mix(in oklab, var(--ok) 12%, var(--bg));
  }

  .strip {
    display: flex;
    gap: 2px;
  }

  .strip i {
    width: 6px;
    height: 12px;
    border-radius: 1.5px;
    background: var(--accent);
    transition: background 300ms;
  }

  .strip i.off {
    background: var(--raised);
  }

  .clip .clear {
    padding: 2px 8px;
    font-size: 11.5px;
    background: var(--raised);
  }

  .password,
  .field {
    position: relative;
  }

  .held::before {
    content: "";
    position: absolute;
    left: 0;
    bottom: 0;
    height: 2px;
    width: calc(var(--held, 0) * 100%);
    background: var(--accent);
    border-radius: 1px;
    transition: width 1s linear;
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
    position: relative;
    background: var(--panel);
    padding: 10px 8px;
    display: flex;
    flex-direction: column;
    gap: 10px;
  }

  nav > ul,
  .smart,
  .group-actions {
    position: relative;
  }

  ul {
    list-style: none;
    margin: 0;
    padding: 0;
  }

  .group,
  .entry,
  .field {
    font-family: var(--font);
    font-weight: 400;
  }

  .group {
    width: 100%;
    border-radius: var(--radius);
    display: flex;
    align-items: center;
    gap: 8px;
    padding: 6px 10px;
    background: none;
    clip-path: none;
    color: var(--dim);
    text-align: left;
  }

  .group:hover {
    background: color-mix(in oklab, var(--raised) 60%, transparent);
  }

  .group .name,
  .group.smart > span:not(.count) {
    flex: 1;
    overflow: hidden;
    text-overflow: ellipsis;
  }

  .group.smart.alert > :global(svg) {
    color: var(--error);
  }

  .group.active {
    color: var(--text);
    background: var(--raised);
  }

  .group.active > :global(svg) {
    color: var(--accent-text);
  }

  .group.bin {
    color: var(--faint);
  }

  .count {
    color: var(--faint);
    font-size: 12px;
    font-variant-numeric: tabular-nums;
  }

  .depth-1 { padding-left: 24px; }
  .depth-2 { padding-left: 38px; }
  .depth-3 { padding-left: 52px; }
  .depth-4 { padding-left: 66px; }
  .depth-5 { padding-left: 80px; }
  .depth-6 { padding-left: 94px; }
  .depth-7 { padding-left: 108px; }
  .depth-8 { padding-left: 122px; }

  .flag {
    width: 7px;
    height: 7px;
    flex: none;
    background: var(--error);
    transform: rotate(45deg);
  }

  /* Solid, so the hex field never shows through the buttons. */
  .group-actions {
    margin: auto -8px -10px;
    padding: 8px;
    display: flex;
    gap: 4px;
    background: var(--panel);
    box-shadow: 0 -14px 14px var(--panel);
  }

  .group-actions button {
    padding: 4px 8px;
    font-size: 12px;
    color: var(--text);
  }

  .group-actions button.danger {
    color: var(--error);
  }

  /* Dimmed by colour: opacity would let the hexes through again. */
  .group-actions button:disabled {
    opacity: 1;
    color: var(--faint);
  }

  .list {
    grid-area: list;
    padding: 10px 8px;
    border-right: 1px solid var(--line);
  }

  .list ul {
    display: grid;
    gap: 2px;
  }

  .entry {
    width: 100%;
    display: flex;
    align-items: center;
    gap: 12px;
    padding: 8px 10px;
    background: none;
    text-align: left;
  }

  .entry:hover {
    background: var(--panel);
  }

  .entry.active {
    background: var(--raised);
  }

  .names {
    flex: 1;
    min-width: 0;
    display: grid;
  }

  .names strong,
  .names span {
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
  }

  .names strong {
    font-weight: 500;
  }

  .names span {
    font-family: var(--mono);
    font-size: 12px;
    color: var(--faint);
  }

  .entry.active .names span {
    color: var(--dim);
  }

  .initial {
    width: 30px;
    height: 30px;
    flex: none;
    display: grid;
    place-items: center;
    background: var(--raised);
    color: var(--dim);
    border-radius: var(--radius);
  }

  .entry.active .initial {
    background: var(--accent);
    color: var(--accent-ink);
  }

  .initial.big {
    width: 48px;
    height: 48px;
    font-size: 22px;
    background: var(--raised);
    color: var(--accent-text);
  }

  .empty {
    padding: 12px;
  }

  article {
    grid-area: detail;
    padding: 26px 28px;
    display: flex;
    flex-direction: column;
    gap: 18px;
  }

  .head {
    display: flex;
    align-items: center;
    gap: 14px;
  }

  h2 {
    margin: 0;
    font-family: var(--action);
    font-size: 28px;
    font-weight: 600;
    letter-spacing: -0.01em;
    line-height: 1.1;
  }

  .head p {
    margin: 4px 0 0;
    display: flex;
    align-items: center;
    gap: 6px;
    color: var(--data);
    font-size: 13px;
  }

  .head p > :global(svg) {
    width: 14px;
    height: 14px;
  }

  .issue {
    display: flex;
    align-items: center;
    gap: 12px;
    padding: 9px 12px;
    background: color-mix(in oklab, var(--error) 15%, var(--bg));
    border-radius: var(--radius);
  }

  .issue > span:nth-child(2) {
    flex: 1;
  }

  .issue > :global(svg) {
    color: var(--error);
  }

  .issue button {
    padding: 4px 10px;
  }

  .password {
    display: grid;
    gap: 12px;
    padding: 16px 18px;
    background: var(--panel);
    border: 1px solid var(--line);
    border-radius: var(--radius);
  }

  .grab {
    display: block;
    width: 100%;
    padding: 0;
    background: none;
    text-align: left;
  }

  .grab:hover :global(.cells b) {
    background: var(--raised);
  }

  .bar {
    display: flex;
    align-items: center;
    gap: 8px;
  }

  .meta {
    flex: 1;
    color: var(--faint);
    font-size: 12.5px;
  }

  .fields {
    display: grid;
    gap: 1px;
  }

  .field {
    display: grid;
    grid-template-columns: 120px minmax(0, 1fr) auto;
    align-items: center;
    gap: 12px;
    padding: 9px 12px;
    background: none;
    clip-path: none;
    text-align: left;
  }

  .field:hover:not(.still) {
    background: var(--panel);
  }

  .field.still {
    cursor: default;
  }

  .label {
    display: flex;
    align-items: center;
    gap: 8px;
    color: var(--data);
    font-size: 13px;
  }

  .label > :global(svg) {
    width: 15px;
    height: 15px;
  }

  .value {
    font-family: var(--mono);
    font-size: 13.5px;
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
  }

  .value.quiet {
    color: var(--faint);
  }

  .hint {
    display: flex;
    align-items: center;
    gap: 5px;
    font-size: 12px;
    color: var(--faint);
    opacity: 0;
    transition: opacity 120ms;
  }

  .field:hover .hint,
  .field:focus-visible .hint,
  .field.done .hint {
    opacity: 1;
  }

  .field.done .hint {
    color: var(--ok);
  }

  .hint > :global(svg) {
    width: 13px;
    height: 13px;
  }

  button.icon {
    padding: 6px 9px;
  }

  .badge {
    font: 11px var(--mono);
  }

  .tags {
    display: flex;
    flex-wrap: wrap;
    gap: 6px;
  }

  .tags span {
    padding: 0 8px;
    border: 1px solid color-mix(in oklab, var(--data) 45%, transparent);
    color: var(--data);
    font-size: 12.5px;
  }

  .notes {
    margin: 0;
    padding: 10px 12px;
    background: var(--panel);
    white-space: pre-wrap;
    font: 13px/1.5 var(--mono);
    color: var(--dim);
    -webkit-user-select: text;
    user-select: text;
  }

  .entry-actions {
    display: flex;
    gap: 8px;
  }

  .prompt {
    background: var(--panel);
    border: 1px solid var(--line);
    border-radius: var(--radius);
    box-shadow: 0 24px 60px -24px rgb(0 0 0 / 0.6);
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

  @media (prefers-reduced-motion: reduce) {
    .strip i,
    .held::before,
    .hint {
      transition: none;
    }
  }
</style>
