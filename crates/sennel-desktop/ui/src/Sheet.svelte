<script>
  import { onMount, untrack } from "svelte";
  import { call, secretCopy } from "./api.js";
  import Cells from "./Cells.svelte";
  import { copyFeedback } from "./copied.svelte.js";
  import Modal from "./Modal.svelte";

  let { sheet, say, reload, close, open } = $props();

  let rows = $state(null);
  let adding = $state(null);
  let value = $state(untrack(() => sheet.value ?? ""));

  const titles = { audit: "Needs attention", history: "History", fields: "Fields and attachments", generate: "Generated password" };

  async function load() {
    try {
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
      if (note.level !== "error") fb.mark(key);
    } catch (why) {
      say([{ level: "error", text: String(why) }]);
    }
  }

  onMount(load);
</script>

<Modal label={titles[sheet.kind]} onclose={close}>
  <section>
    <header>
      <h2>{titles[sheet.kind]}</h2>
      <button onclick={close}>Close</button>
    </header>

    {#if sheet.kind === "generate"}
      <div class="secret" use:fb.spot={"generated"}><Cells {value} /></div>
      <div class="row">
        <button onclick={async () => (value = await call("generate"))}>Another</button>
        <button class="primary" onclick={() => copyOut("generated", "copy_text", { label: "the generated password", text: value })}>
          {fb.copied === "generated" ? "Copied" : "Copy"}
        </button>
      </div>
      <p class="dim">Length and style come from [generator] in the config file. Generate in the entry form puts one straight into the password box.</p>
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
