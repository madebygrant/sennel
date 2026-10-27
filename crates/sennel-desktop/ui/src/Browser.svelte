<script>
  import { onMount, tick } from "svelte";
  import {
    CalendarClock,
    Check,
    ChevronDown,
    ChevronRight,
    Copy,
    CornerDownRight,
    CornerLeftUp,
    Eye,
    EyeOff,
    Folder,
    KeyRound,
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
  import { combo, dispatch, shown } from "./keys.js";
  import Cells, { kind } from "./Cells.svelte";
  import EntryForm from "./EntryForm.svelte";
  import HexField from "./HexField.svelte";
  import Modal from "./Modal.svelte";
  import OtpCells from "./OtpCells.svelte";
  import Rekey from "./Rekey.svelte";
  import { hasKids, parentOf, visibleGroups } from "./tree.js";
  import Sheet from "./Sheet.svelte";

  let { status, say, refresh, clears, hints = $bindable() } = $props();

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
  let navBox;
  let listBox;
  // Which list j, k and D act on. The selection in the other pane dims.
  let pane = $state("entries");
  // An entry picked up with X, waiting for V in another group.
  let cut = $state(null);
  let help = $state(false);
  let rekeying = $state(false);
  // Folded groups hide what is under them, for this session.
  let folded = $state(new Set());
  const ORDERS = { stored: "File order", name: "Name", recent: "Newest", updated: "Recently changed" };

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

  function selectGroup(id) {
    group = id;
    needle = "";
    loadRows();
  }

  const visible = $derived(visibleGroups(groups, folded));

  function fold(id, shut) {
    const next = new Set(folded);
    if (shut) next.add(id);
    else next.delete(id);
    folded = next;
    // A folded group's own child cannot stay selected out of sight.
    if (shut && !visible.some((at) => groups[at].id === group)) selectGroup(id);
  }

  // ← in the groups pane folds an open group, or climbs to its parent.
  function foldOrClimb() {
    const at = groups.findIndex((g) => g.id === group);
    if (at < 0) return;
    if (hasKids(groups, at) && !folded.has(group)) return fold(group, true);
    const parent = parentOf(groups, at);
    if (parent) selectGroup(parent.id);
  }

  async function cycleSort() {
    say([await call("cycle_sort")]);
    await refresh();
    await loadRows();
  }

  function step(by) {
    const list = pane === "groups" ? visible.map((at) => groups[at]) : rows;
    if (!list.length) return;
    const at = list.findIndex((r) => r.id === (pane === "groups" ? group : selected));
    const to = list[Math.min(list.length - 1, Math.max(0, at + by))].id;
    if (pane === "groups") selectGroup(to);
    else pick(to);
  }

  $effect(() => {
    [group, selected];
    tick().then(() => {
      navBox?.querySelector(".group.active")?.scrollIntoView({ block: "nearest" });
      listBox?.querySelector(".entry.active")?.scrollIntoView({ block: "nearest" });
    });
  });

  const COPIES = { y: "username", p: "password", U: "url", t: "otp" };
  // A clicked row keeps focus on Linux, yet the keys act on the selection, not on that row.
  const isRow = (el) => el?.matches?.(".group:not(.smart), .entry");

  // The terminal app's keys, from its BROWSER_KEYS table, in its order. The handler, the keys
  // overlay and the footer hints all read this list.
  const actions = [
    { name: "move", keys: "j k  ↑ ↓", what: "through the focused pane", on: ["j", "k", "ArrowDown", "ArrowUp"], repeats: true, run: (k) => step(k === "j" || k === "ArrowDown" ? 1 : -1) },
    { name: "ends", keys: "g G", what: "top, bottom of the pane", on: ["g", "G"], run: (k) => step(k === "g" ? -Infinity : Infinity) },
    {
      name: "panes",
      keys: "tab",
      what: "groups, entries",
      on: ["Tab"],
      run: () => {
        // Only while nothing but a row has focus, so Tab still walks the buttons for keyboard users.
        if (document.activeElement !== document.body && !isRow(document.activeElement)) return false;
        pane = pane === "groups" ? "entries" : "groups";
      },
    },
    {
      name: "fold",
      keys: "← →",
      what: "collapse, expand group · ← hops from entries",
      on: ["ArrowLeft", "ArrowRight"],
      run: (k) => {
        if (pane === "entries") {
          if (k === "ArrowRight") return false;
          pane = "groups";
        } else if (k === "ArrowLeft") foldOrClimb();
        else if (folded.has(group)) fold(group, false);
        else pane = "entries";
      },
    },
    { name: "open", keys: "enter", what: "group: its entries · entry: copy the password", on: ["Enter"], run: () => (pane === "groups" ? (pane = "entries") : selected ? copy("password") : false) },
    {
      name: "copy",
      keys: "y p U t",
      what: "username, password, website, one-time code",
      on: Object.keys(COPIES),
      when: () => selected,
      run: (k) => {
        const field = COPIES[k];
        if ((field === "otp" && !detail?.hasOtp) || (field === "url" && !detail?.url)) return false;
        copy(field);
      },
    },
    { name: "reveal", keys: "*", what: "show the password", on: ["*"], when: () => detail?.hasPassword, run: toggleReveal },
    {
      name: "edit",
      keys: "a e D",
      what: "add, edit, delete entry",
      on: ["a", "e", "D"],
      run: (k) => {
        if (k === "a") form = { group };
        else if (pane !== "entries" || !detail) return false;
        else if (k === "e") form = { id: detail.id, detail };
        else confirmDelete("entry");
      },
    },
    { name: "make", keys: "P", what: "generate a password, no entry needed", on: ["P"], run: async () => (sheet = { kind: "generate", value: await call("generate") }) },
    {
      name: "groups",
      keys: "A E D",
      what: "add, rename, delete group",
      on: ["A", "E", "D"],
      when: () => pane === "groups",
      run: (k) => {
        if (k === "A") askGroup("add");
        else if (!current?.depth) return false;
        else if (k === "E") askGroup("rename");
        else confirmDelete("group");
      },
    },
    {
      name: "cut",
      keys: "X V",
      what: "cut an entry, paste it into the current group",
      on: ["X", "V"],
      run: (k) => {
        if (k === "X" && detail) cut = { id: detail.id, title: detail.title || "(untitled)" };
        else if (k === "V" && cut) {
          act("move_entry", { id: cut.id, group });
          cut = null;
        } else return false;
      },
    },
    { name: "find", keys: "/  ^f", what: "search the vault", on: ["/", "^f"], run: () => searchBox?.focus() },
    { name: "undo", keys: "u", what: "one level", on: ["u"], run: () => act("undo") },
    { name: "order", keys: "o", what: "entries: file order, name, newest, recently changed", on: ["o"], run: cycleSort },
    { name: "save", keys: "^s", what: "save now", on: ["^s"], run: () => act("save") },
    { name: "lock", keys: "^l", what: "lock now", on: ["^l"], run: () => act("lock") },
    { name: "master", keys: "^p", what: "change the master password", on: ["^p"], run: () => (rekeying = true) },
    { name: "audit", keys: "!", what: "reused, weak, expired and empty passwords", on: ["!"], run: () => (sheet = { kind: "audit" }) },
    { name: "fields", keys: "F", what: "custom fields and attachments", on: ["F"], when: () => detail, run: () => (sheet = { kind: "fields", id: detail.id }) },
    { name: "history", keys: "H", what: "old versions", on: ["H"], when: () => detail, run: () => (sheet = { kind: "history", id: detail.id }) },
    {
      name: "back",
      keys: "esc",
      what: "drop the cut entry, then clear the search",
      on: ["Escape"],
      run: () => {
        if (cut) cut = null;
        else if (needle) {
          needle = "";
          loadRows();
        } else return false;
      },
    },
    { name: "keys", keys: "h ?", what: "this table", on: ["h", "?"], run: () => (help = true) },
  ];

  $effect(() => {
    const bar = cut
      ? [["V", `paste ${cut.title} here`], ["esc", "keep it where it is"]]
      : pane === "groups"
        ? [["j k", "move"], ["← →", "fold"], ["A", "add group"], ...(current?.depth ? [["E", "rename"]] : [])]
        : selected
          ? [["p", "password"], ["y", "user"], ...(detail?.hasOtp ? [["t", "code"]] : []), ["e", "edit"], ["/", "find"]]
          : [["a", "add"], ["/", "find"]];
    hints = status.singleKeys ? [...bar, ["h", "keys"]].map(([k, label]) => [shown(k), label]) : [];
  });

  function keys(event) {
    if (form || sheet || prompt || rekeying || event.altKey || event.defaultPrevented) return;
    if (help) {
      if (event.key === "h" || event.key === "?") help = false;
      return;
    }
    const key = combo(event);
    const target = event.target;
    // The search box hands arrows and Enter to the list, so /, type, Enter copies.
    // Text boxes keep their usual keys, ⌘C and ⌘Z included; only find, save and lock stay global there.
    if (target === searchBox) {
      if (key === "Escape") {
        event.preventDefault();
        if (needle) {
          needle = "";
          loadRows();
        } else searchBox.blur();
        return;
      }
      if (!["^f", "^s", "^l", "ArrowUp", "ArrowDown", "Enter"].includes(key)) return;
      if (key === "Enter" || key.startsWith("Arrow")) pane = "entries";
    } else if (target.closest?.("input, textarea")) {
      if (!["^f", "^s", "^l"].includes(key)) return;
    } else if (!isRow(target) && target.closest?.("button, a") && (key === "Enter" || key === " ")) {
      return;
    }
    if (dispatch(actions, event, { single: status.singleKeys })) event.preventDefault();
  }

  onMount(reload);
</script>

<svelte:window onkeydown={keys} />

<div class="shell">
  <header>
    <label class="search">
      <Search />
      <input bind:this={searchBox} bind:value={needle} oninput={loadRows} placeholder="Search the vault, #tag" spellcheck="false" aria-label="Search the vault" />
      <kbd>/</kbd>
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
    <button class="tool" onclick={() => (form = { group })} title="New entry  a" aria-label="New entry"><Plus /></button>
    <button class="tool" onclick={() => askGroup("add")} title="New group  A" aria-label="New group"><FolderPlus /></button>
    <button class="tool" onclick={async () => (sheet = { kind: "generate", value: await call("generate") })} title="Generate a password  P" aria-label="Generate a password"><WandSparkles /></button>
    <button class="tool" onclick={() => act("undo")} disabled={!status.undo} title={status.undo ? `Undo ${status.undo}  u` : "Nothing to undo"} aria-label="Undo"><Undo2 /></button>
    <button class="tool" onclick={() => act("save")} title="Save  ⌘S" aria-label="Save"><Save /></button>
    <button class="tool" onclick={() => (rekeying = true)} title="Change master password  ⌘P" aria-label="Change master password"><KeyRound /></button>
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

  <nav aria-label="Groups" class:focused={pane === "groups"} bind:this={navBox}>
    <HexField />
    <button class="group smart" class:alert={attention} onclick={() => (sheet = { kind: "audit" })}>
      <ShieldAlert /><span>Needs attention</span>
      <span class="count">{attention || ""}</span>
    </button>
    <ul>
      {#each visible as at (groups[at].id)}
        {@const g = groups[at]}
        <li>
          <button
            class="group depth-{Math.min(g.depth, 8)}"
            class:active={g.id === group}
            class:bin={g.bin}
            aria-current={g.id === group ? "true" : undefined}
            aria-expanded={hasKids(groups, at) ? !folded.has(g.id) : undefined}
            onclick={() => {
              pane = "groups";
              selectGroup(g.id);
            }}
            ondragover={(e) => e.preventDefault()}
            ondrop={(e) => dropOn(g.id, e)}
          >
            <!-- svelte-ignore a11y_click_events_have_key_events, a11y_no_static_element_interactions -->
            <span class="chevron" onclick={(e) => { e.stopPropagation(); if (hasKids(groups, at)) fold(g.id, !folded.has(g.id)); }}>
              {#if hasKids(groups, at)}{#if folded.has(g.id)}<ChevronRight />{:else}<ChevronDown />{/if}{/if}
            </span>
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

  <section class="list" aria-label="Entries" class:focused={pane === "entries"} bind:this={listBox}>
    <div class="listbar">
      <button class="order" onclick={cycleSort} title="Change the order  o">{ORDERS[status.sort] ?? "File order"}</button>
    </div>
    <ul>
      {#each rows as r (r.id)}
        <li>
          <button
            class="entry"
            class:active={r.id === selected}
            aria-current={r.id === selected ? "true" : undefined}
            onclick={() => {
              pane = "entries";
              pick(r.id);
            }}
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
            {#if cut?.id === r.id}<span class="cutmark">cut</span>{/if}
          </button>
        </li>
      {:else}
        <li class="empty dim">{needle ? "Nothing matches. Try fewer letters, or #tag." : "No entries here. a adds one."}</li>
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
          <!-- Out of the tab order: the Copy button and p already cover the keyboard. -->
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
            <button class="primary icon" onclick={() => copy("password")} title="Copy the password  p" aria-label={fb.copied === "password" ? "Copied" : "Copy the password"}>
              {#if fb.copied === "password"}<Check />{:else}<Copy />{/if}<kbd>p</kbd>
            </button>
          </div>
        </div>
      {/if}

      <div class="fields">
        {#if detail.username}
          <button class="field" class:done={fb.copied === "username"} class:held={holding("username")} use:meter={clears.total ? clears.left / clears.total : 0} use:fb.spot={"username"} onclick={() => copy("username")}>
            <span class="label"><User />Username</span><span class="value lit">{detail.username}</span>
            <span class="hint">{#if fb.copied === "username"}<Check />Copied{:else}<Copy />y{/if}</span>
          </button>
        {/if}
        {#if detail.url}
          <button class="field" class:done={fb.copied === "url"} class:held={holding("url")} use:meter={clears.total ? clears.left / clears.total : 0} use:fb.spot={"url"} onclick={() => copy("url")}>
            <span class="label"><Globe />Website</span><span class="value lit">{detail.url}</span>
            <span class="hint">{#if fb.copied === "url"}<Check />Copied{:else}<Copy />U{/if}</span>
          </button>
        {/if}
        {#if detail.hasOtp}
          <button class="field" class:done={fb.copied === "otp"} class:held={holding("otp")} use:meter={clears.total ? clears.left / clears.total : 0} use:fb.spot={"otp"} onclick={() => copy("otp")} title="Copied, never shown">
            <span class="label"><Timer />One-time code</span>{#if detail.otp}<span class="value"><OtpCells period={detail.otp.period} digits={detail.otp.digits} /></span>{:else}<span class="value quiet">Can't read this code</span>{/if}
            <span class="hint">{#if fb.copied === "otp"}<Check />Copied{:else}<Copy />t{/if}</span>
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

{#if rekeying}
  <Rekey {say} close={async () => { rekeying = false; await refresh(); }} />
{/if}

{#if help}
  <Modal label="Keys" onclose={() => (help = false)}>
    <section class="keys">
      <header>
        <h2>Keys</h2>
        <button onclick={() => (help = false)}>Close</button>
      </header>
      <dl>
        {#each actions as a}
          <dt>{a.name}</dt>
          <dd><kbd>{shown(a.keys)}</kbd></dd>
          <dd>{shown(a.what)}</dd>
        {/each}
      </dl>
      <p class="dim">Single keys work when the cursor is not in a text box. The same keys as the terminal app.</p>
    </section>
  </Modal>
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

  .chevron {
    width: 14px;
    flex: none;
    display: grid;
    place-items: center;
    margin-right: -4px;
    color: var(--faint);
  }

  .chevron > :global(svg) {
    width: 13px;
    height: 13px;
  }

  .listbar {
    display: flex;
    justify-content: flex-end;
    padding: 0 4px 6px;
  }

  .order {
    padding: 2px 8px;
    background: none;
    color: var(--faint);
    font: 12px var(--font);
  }

  .order:hover {
    color: var(--text);
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

  nav:not(.focused) .group.active {
    background: color-mix(in oklab, var(--raised) 50%, transparent);
  }

  nav:not(.focused) .group.active > :global(svg) {
    color: var(--dim);
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

  .list:not(.focused) .entry.active {
    background: color-mix(in oklab, var(--raised) 50%, transparent);
  }

  .list:not(.focused) .entry.active .initial {
    background: var(--raised);
    color: var(--accent-text);
  }

  .cutmark {
    font: 11px var(--mono);
    color: var(--accent-text);
    border: 1px dashed var(--accent-text);
    border-radius: 3px;
    padding: 0 5px;
  }

  .entry:has(.cutmark) {
    opacity: 0.7;
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

  .keys {
    background: var(--panel);
    border: 1px solid var(--line);
    border-radius: var(--radius);
    box-shadow: 0 24px 60px -24px rgb(0 0 0 / 0.6);
    padding: 16px 18px;
    width: min(760px, calc(100vw - 40px));
    max-height: calc(100vh - 40px);
    overflow: auto;
    display: grid;
    gap: 12px;
  }

  .keys header {
    grid-area: auto;
    padding: 0;
    border: 0;
    justify-content: space-between;
  }

  .keys h2 {
    font-size: 18px;
  }

  .keys dl {
    margin: 0;
    display: grid;
    grid-template-columns: auto auto minmax(0, 1fr);
    gap: 6px 18px;
    font-size: 13px;
  }

  .keys dt {
    color: var(--dim);
  }

  .keys dd {
    margin: 0;
  }

  .keys kbd {
    font: 12.5px var(--mono);
    color: var(--accent-text);
    opacity: 1;
    white-space: pre;
  }

  .keys p {
    margin: 0;
    font-size: 12.5px;
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
