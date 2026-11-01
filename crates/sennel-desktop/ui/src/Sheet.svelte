<script>
  import { onMount } from "svelte";
  import { call, secretCopy } from "./api.js";
  import Cells from "./Cells.svelte";
  import { copyFeedback } from "./copied.svelte.js";
  import { KINDS, STYLES, chosen, generate, resized, restyled } from "./generator.svelte.js";
  import GeneratorControls from "./GeneratorControls.svelte";
  import Modal from "./Modal.svelte";

  let { sheet, say, reload, refresh, close, open } = $props();

  let rows = $state(null);
  let adding = $state(null);
  let made = $state(null);

  const titles = { audit: "Needs attention", history: "History", fields: "Fields and attachments", generate: "Generated password" };

  async function load() {
    try {
      if (sheet.kind === "generate") await another();
      if (sheet.kind === "audit") rows = await call("audit");
      if (sheet.kind === "history") rows = await call("history", { id: sheet.id });
      if (sheet.kind === "fields") rows = await call("fields", { id: sheet.id });
    } catch (why) {
      say([{ level: "error", text: String(why) }]);
    }
  }

  async function act(cmd, args) {
    try {
      const reply = await call(cmd, args);
      say(reply.notes ?? [reply]);
      await load();
      await reload();
    } catch (why) {
      say([{ level: "error", text: String(why) }]);
    }
  }

  async function submitAdd(event) {
    event.preventDefault();
    const { file, name, from } = adding;
    adding = null;
    if (file) await act("attach", { id: sheet.id, name, path: from });
    else await act("add_field", { id: sheet.id, name, value: from });
  }

  const fb = copyFeedback();

  async function copyOut(key, cmd, args) {
    try {
      const note = await call(cmd, args);
      say([note]);
      await refresh();
      if (note.level !== "error") fb.mark(key);
    } catch (why) {
      say([{ level: "error", text: String(why) }]);
    }
  }

  async function another(kind, size, style) {
    try {
      made = (await generate(kind, size, style)) ?? made;
    } catch (why) {
      say([{ level: "error", text: String(why) }]);
    }
  }

  // The terminal app's generator keys: t kind, - + size, u d s a characters.
  function keys(event) {
    if (sheet.kind !== "generate" || event.metaKey || event.ctrlKey || event.altKey || !chosen.kind) return;
    const at = KINDS.findIndex(([k]) => k === chosen.kind);
    const run = { t: () => [KINDS[(at + 1) % KINDS.length][0]], "-": () => resized(-1), "+": () => resized(1), "=": () => resized(1), ...Object.fromEntries(STYLES.map(([style, key]) => [key, () => restyled(style)])) }[event.key];
    if (!run) return;
    event.preventDefault();
    const args = run();
    if (args) another(...args);
  }

  onMount(load);
</script>

<Modal label={titles[sheet.kind]} onclose={close}>
  <!-- svelte-ignore a11y_no_static_element_interactions -->
  <section onkeydown={keys}>
    <header>
      <h2>{titles[sheet.kind]}</h2>
      <button onclick={close}>Close</button>
    </header>

    {#if sheet.kind === "generate"}
      <div class="generate">
        <GeneratorControls {made} pick={another}>
          <div class="secret" use:fb.spot={"generated"}><Cells value={made.value} words={made.kind === "passphrase"} /></div>
        </GeneratorControls>
        <div class="row">
          <button onclick={() => another()}>Another</button>
          <button class="primary" disabled={!made} onclick={() => copyOut("generated", "copy_text", { label: "the generated password", text: made.value })}>
            {fb.copied === "generated" ? "Copied" : "Copy"}
          </button>
        </div>
        <p class="dim">[generator] in the config file sets where each kind starts. A kind, size or character set picked here, or with <kbd>t</kbd>, <kbd>-</kbd> <kbd>+</kbd> and <kbd>u</kbd> <kbd>d</kbd> <kbd>s</kbd> <kbd>a</kbd>, lasts until Sennel quits and is shared with Generate in the entry form.</p>
      </div>
    {:else if rows === null}
      <p class="dim">…</p>
    {:else if sheet.kind === "audit"}
      {#each rows as r}
        <button class="line" onclick={() => open(r.id)}>
          <strong>{r.title || "(untitled)"}</strong><span class="dim">{r.issue}</span>
        </button>
      {:else}
        <p class="dim">Nothing reused, weak, expired, empty or old.</p>
      {/each}
    {:else if sheet.kind === "history"}
      {#each rows as r}
        <div class="line"><span>{r.title} <span class="dim">{r.username}</span></span><span class="dim">{r.modified}</span></div>
      {:else}
        <p class="dim">No older versions.</p>
      {/each}
      {#if rows.length}
        <div class="row">
          <button class="danger" onclick={() => act("clear_history", { id: sheet.id })}>Clear all {rows.length}</button>
        </div>
      {/if}
    {:else if sheet.kind === "fields"}
      {#each rows as r}
        <div class="line" use:fb.spot={r.name}>
          <span>
            <strong>{r.name}</strong>
            {#if r.file}<span class="dim">{r.bytes} bytes</span>{:else}<span class="dim mono lit">{r.secret ? "••••••" : r.value}</span>{/if}
          </span>
          <span class="actions">
            {#if r.file}
              <button onclick={() => act("extract", { id: sheet.id, name: r.name })}>Save beside vault</button>
              <button onclick={() => act("agent_give", { id: sheet.id, name: r.name })}>To ssh-agent</button>
            {:else}
              <button onclick={() => copyOut(r.name, "copy_field", { id: sheet.id, name: r.name })}>{fb.copied === r.name ? "Copied" : "Copy"}</button>
            {/if}
            <button class="danger" onclick={() => act("remove_field", { id: sheet.id, name: r.name, file: r.file })}>Remove</button>
          </span>
        </div>
      {:else}
        <p class="dim">No custom fields or attachments.</p>
      {/each}
      {#if adding}
        <form class="add" onsubmit={submitAdd}>
          <input bind:value={adding.name} placeholder="Name" />
          <input
            class="mono"
            bind:value={adding.from}
            placeholder={adding.file ? "Path to the file" : "Value (stored protected)"}
            spellcheck="false"
            oncopy={adding.file ? undefined : secretCopy(adding.name || "the value", say)}
            oncut={adding.file ? undefined : secretCopy(adding.name || "the value", say)}
          />
          <button class="primary" type="submit">Add</button>
        </form>
      {:else}
        <div class="row">
          <button onclick={() => (adding = { file: false, name: "", from: "" })}>Add field</button>
          <button onclick={() => (adding = { file: true, name: "", from: "" })}>Attach file</button>
        </div>
      {/if}
    {/if}
  </section>
</Modal>

<style>
  section {
    background: var(--panel);
    border: 1px solid var(--line);
    border-radius: var(--radius);
    box-shadow: 0 24px 60px -24px rgb(0 0 0 / 0.6);
    padding: 16px 18px;
    width: min(620px, calc(100vw - 40px));
    max-height: calc(100vh - 40px);
    overflow: auto;
    display: grid;
    gap: 8px;
  }

  header {
    display: flex;
    justify-content: space-between;
    align-items: center;
  }

  h2 {
    margin: 0;
    font-family: var(--action);
    font-size: 18px;
    font-weight: 600;
  }

  .line {
    display: flex;
    justify-content: space-between;
    align-items: center;
    gap: 12px;
    padding: 6px 8px;
    background: var(--bg);
    border-radius: var(--radius);
    text-align: left;
    font-family: var(--font);
    font-weight: 400;
    width: 100%;
  }

  .line span {
    display: flex;
    gap: 8px;
    min-width: 0;
  }

  .actions button {
    padding: 3px 8px;
    font-size: 12px;
  }

  .generate {
    display: grid;
    gap: 8px;
  }

  .row {
    display: flex;
    gap: 8px;
    justify-content: flex-end;
  }

  .add {
    display: grid;
    grid-template-columns: 1fr 1.4fr auto;
    gap: 6px;
  }

  .secret {
    padding: 6px 0;
  }

  p {
    margin: 0;
    font-size: 13px;
  }
</style>
