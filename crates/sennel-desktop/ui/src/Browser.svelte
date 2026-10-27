<script>
  import { onMount } from "svelte";
  import { call } from "./api.js";
  import EntryForm from "./EntryForm.svelte";
  import HexField from "./HexField.svelte";
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

  let copied = $state(null);
  let glitch = $state(null);
  let copiedTimer;

  // While decoding, each cell shows a passing glyph until its turn comes.
  let glyphs = $state(null);
  const GLYPHS = "ｱｲｳｴｵｶｷｸｹｺｻｼｽｾｿﾀﾁﾂﾃﾄ0123456789ABCDEF<>*=+";
  const still = matchMedia("(prefers-reduced-motion: reduce)").matches;

  const current = $derived(groups.find((g) => g.id === group));
  const chars = $derived(revealed === null ? null : [...revealed]);
  const attention = $derived(Object.keys(issues).length);
  const segments = $derived(clears.total ? Math.ceil((clears.left / clears.total) * 10) : 0);

  function kind(c) {
    if (/\d/.test(c)) return "digit";
    return /[\p{L}]/u.test(c) ? "" : "symbol";
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
    glyphs = null;
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
    if (note.level === "error") return;
    clearTimeout(copiedTimer);
    copied = field;
    copiedTimer = setTimeout(() => (copied = null), 1400);
    if (still) return;
    glitch = null;
    requestAnimationFrame(() => (glitch = field));
  }

  function decode() {
    if (still) return;
    const start = performance.now();
    const step = (now) => {
      if (chars === null) return;
      const next = chars.map((_, i) => (now - start < 180 + i * 45 ? GLYPHS[(Math.random() * GLYPHS.length) | 0] : null));
      glyphs = next.some(Boolean) ? next : null;
      if (glyphs) requestAnimationFrame(step);
    };
    requestAnimationFrame(step);
  }

  async function toggleReveal() {
    if (revealed !== null) {
      revealed = null;
      glyphs = null;
      return;
    }
    revealed = await call("reveal", { id: selected });
    decode();
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

{#snippet icon(path)}
  <svg viewBox="0 0 24 24" aria-hidden="true"><path d={path} /></svg>
{/snippet}

<div class="shell">
  <header>
    <label class="search">
      {@render icon("M11 4a7 7 0 1 0 0 14 7 7 0 0 0 0-14zM20 20l-4-4")}
      <input bind:this={searchBox} bind:value={needle} oninput={loadRows} placeholder="Search the vault, #tag" spellcheck="false" aria-label="Search the vault" />
      <kbd>⌘F</kbd>
    </label>
    <span class="gap"></span>
    {#if clears.left}
      <span class="clip" title="The clipboard clears itself">
        <span class="segs">{#each { length: 10 } as _, i}<i class:off={i >= segments}></i>{/each}</span>
        Clears in {clears.left}s
      </span>
    {/if}
    <button class="tool" onclick={() => (form = { group })} title="New entry  ⌘N" aria-label="New entry">{@render icon("M12 5v14M5 12h14")}</button>
    <button class="tool" onclick={() => askGroup("add")} title="New group" aria-label="New group">{@render icon("M3 6h7l2 2h9v11H3zM12 11v6M9 14h6")}</button>
    <button class="tool" onclick={async () => (sheet = { kind: "generate", value: await call("generate") })} title="Generate a password" aria-label="Generate a password">{@render icon("M4 20l9-9M14 4l1 3 3 1-3 1-1 3-1-3-3-1 3-1z")}</button>
    <button class="tool" onclick={() => act("undo")} disabled={!status.undo} title={status.undo ? `Undo ${status.undo}  ⌘Z` : "Nothing to undo"} aria-label="Undo">{@render icon("M9 14L4 9l5-5M4 9h10a6 6 0 0 1 0 12h-3")}</button>
    <button class="tool" onclick={() => act("save")} title="Save" aria-label="Save">{@render icon("M5 4h11l3 3v13H5zM8 4v5h7V4M8 20v-6h8v6")}</button>
    <button class="tool" onclick={() => act("lock")} title="Lock  ⌘L" aria-label="Lock">{@render icon("M6 11h12v9H6zM8 11V8a4 4 0 0 1 8 0v3")}</button>
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
    <button class="group smart" onclick={() => (sheet = { kind: "audit" })}>
      <span class:flag={attention}></span><span>Needs attention</span>
      <span class="count">{attention || ""}</span>
    </button>
    <ul>
      {#each groups as g (g.id)}
        <li>
          <button
            class="group depth-{Math.min(g.depth, 8)}"
            class:active={g.id === group}
            class:bin={g.bin}
            onclick={() => {
              group = g.id;
              needle = "";
              loadRows();
            }}
            ondragover={(e) => e.preventDefault()}
            ondrop={(e) => dropOn(g.id, e)}
          >
            <span>{g.name}</span>
            <span class="count">{g.entries || ""}</span>
          </button>
        </li>
      {/each}
    </ul>
    {#if current}
      <div class="group-actions">
        <button onclick={() => askGroup("rename")} disabled={current.depth === 0}>Rename</button>
        <button onclick={() => act("reparent", { id: group, deeper: true })} disabled={current.depth === 0} title="Into the group above" aria-label="Into the group above">→</button>
        <button onclick={() => act("reparent", { id: group, deeper: false })} disabled={current.depth < 2} title="Out one level" aria-label="Out one level">←</button>
        <button class="danger" onclick={() => confirmDelete("group")} disabled={current.depth === 0}>Delete</button>
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
          <p>{detail.group || "Root"}{detail.recycled ? ", in the recycle bin" : ""}</p>
        </div>
      </div>

      {#if issues[detail.id]}
        <div class="issue">
          <span class="flag"></span>
          <span>{issues[detail.id]}</span>
          <button onclick={() => (form = { id: detail.id, detail })}>Change it</button>
        </div>
      {/if}

      {#if detail.hasPassword}
        <div class="password" class:glitch={glitch === "password"}>
          <!-- Not selectable: a native copy would skip the clipboard clear, so Copy is the way out. -->
          <div class="cells" class:open={chars !== null}>
            {#each chars ?? Array(12).fill("•") as c, i}
              {#if i && i % 5 === 0}<span class="split"></span>{/if}
              <span class="cell">
                <b class={chars ? kind(c) : ""} class:scrambled={glyphs?.[i]}>{glyphs?.[i] ?? c}</b>
                <small>{chars ? i + 1 : ""}</small>
              </span>
            {/each}
          </div>
          <div class="bar">
            <span class="meta">
              {#if chars}
                {chars.length} characters, {chars.filter((c) => kind(c) === "digit").length} digits, {chars.filter((c) => kind(c) === "symbol").length} symbols
              {:else}
                Hidden
              {/if}
            </span>
            <button onclick={toggleReveal}>{revealed === null ? "Show" : "Hide"}</button>
            <button class="primary" onclick={() => copy("password")}>{copied === "password" ? "Copied" : "Copy"} <kbd>⌘C</kbd></button>
          </div>
        </div>
      {/if}

      <div class="fields">
        {#if detail.username}
          <button class="field" class:done={copied === "username"} class:glitch={glitch === "username"} onclick={() => copy("username")}>
            <span class="label">Username</span><span class="value">{detail.username}</span>
            <span class="hint">{copied === "username" ? "Copied" : "Copy ⌘B"}</span>
          </button>
        {/if}
        {#if detail.url}
          <button class="field" class:done={copied === "url"} class:glitch={glitch === "url"} onclick={() => copy("url")}>
            <span class="label">Website</span><span class="value">{detail.url}</span>
            <span class="hint">{copied === "url" ? "Copied" : "Copy"}</span>
          </button>
        {/if}
        {#if detail.hasOtp}
          <button class="field" class:done={copied === "otp"} class:glitch={glitch === "otp"} onclick={() => copy("otp")}>
            <span class="label">One-time code</span><span class="value quiet">Copied, never shown</span>
            <span class="hint">{copied === "otp" ? "Copied" : "Copy"}</span>
          </button>
        {/if}
        {#if detail.tags}
          <div class="field still">
            <span class="label">Tags</span>
            <span class="tags">{#each detail.tags.split(",").map((t) => t.trim()).filter(Boolean) as t}<span>{t}</span>{/each}</span>
          </div>
        {/if}
        {#if detail.expires}
          <div class="field still"><span class="label">Expires</span><span class="value">{detail.expires}</span></div>
        {/if}
      </div>

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

  svg {
    width: 16px;
    height: 16px;
    fill: none;
    stroke: currentColor;
    stroke-width: 1.8;
    stroke-linejoin: round;
    stroke-linecap: round;
    flex: none;
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
    box-shadow: inset 0 -2px var(--accent);
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
    background: color-mix(in oklab, var(--accent) 14%, var(--bg));
    border-radius: var(--radius);
    font-size: 12.5px;
    font-variant-numeric: tabular-nums;
  }

  .segs {
    display: flex;
    gap: 2px;
  }

  .segs i {
    width: 4px;
    height: 12px;
    background: var(--accent);
    transition: opacity 300ms;
  }

  .segs i.off {
    opacity: 0.15;
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

  .group > span:first-child {
    flex: 1;
    overflow: hidden;
    text-overflow: ellipsis;
  }

  .group.smart > span:nth-child(2) {
    flex: 1;
  }

  .group.smart > span:first-child {
    flex: none;
  }

  .group.active {
    color: var(--accent);
    box-shadow: inset 3px 0 var(--accent);
    background: color-mix(in oklab, var(--accent) 10%, transparent);
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

  .group-actions {
    margin-top: auto;
    display: flex;
    gap: 4px;
  }

  .group-actions button {
    padding: 4px 8px;
    font-size: 12px;
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
    background: var(--accent);
    color: var(--accent-ink);
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
    color: color-mix(in oklab, var(--accent-ink) 65%, var(--accent));
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
    background: var(--accent-ink);
    color: var(--accent);
  }

  .initial.big {
    width: 48px;
    height: 48px;
    font-size: 22px;
    background: var(--accent);
    color: var(--accent-ink);
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
    color: var(--data);
    font-size: 13px;
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

  .issue button {
    padding: 4px 10px;
  }

  .password {
    display: grid;
    gap: 12px;
    padding: 16px 18px;
    background: var(--panel);
    box-shadow: inset 3px 0 var(--accent);
    border-radius: var(--radius);
  }

  .cells {
    display: flex;
    flex-wrap: wrap;
    gap: 6px 2px;
    -webkit-user-select: none;
    user-select: none;
  }

  .split {
    width: 8px;
  }

  .cell {
    display: grid;
    gap: 4px;
    justify-items: center;
  }

  .cell b {
    width: 23px;
    height: 34px;
    display: grid;
    place-items: center;
    font-family: var(--mono);
    font-weight: 400;
    font-size: 17px;
    background: var(--bg);
    color: var(--faint);
  }

  .cell small {
    font-family: var(--mono);
    height: 12px;
    font-size: 10px;
    color: var(--faint);
  }

  .open .cell b {
    color: var(--text);
  }

  .open .cell b.digit {
    color: var(--accent);
  }

  .open .cell b.symbol {
    color: var(--data);
  }

  .open .cell b.scrambled {
    color: var(--dim);
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
    color: var(--data);
    font-size: 13px;
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

  .glitch {
    animation: glitch 300ms steps(2) both;
  }

  @keyframes glitch {
    0% { clip-path: inset(10% 0 60% 0); transform: translateX(-6px); }
    33% { clip-path: inset(55% 0 10% 0); transform: translateX(5px); }
    66% { clip-path: inset(30% 0 35% 0); transform: translateX(-2px); }
    100% { border-radius: var(--radius); transform: none; }
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

  .scrim {
    position: fixed;
    inset: 0;
    background: rgb(0 0 0 / 0.5);
    display: grid;
    place-items: center;
  }

  .prompt {
    background: var(--panel);
    border-left: 3px solid var(--accent);
    border-radius: var(--radius);
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
    .segs i,
    .hint {
      transition: none;
    }
  }
</style>
