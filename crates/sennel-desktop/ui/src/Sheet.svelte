<script>
  import { onMount, untrack } from "svelte";
  import { call } from "./api.js";

  let { sheet, say, reload, close, open } = $props();

  let rows = $state(null);
  let adding = $state(null);
  let value = $state(untrack(() => sheet.value ?? ""));

  const titles = { audit: "Audit", history: "History", fields: "Fields and attachments", generate: "Generated password" };

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

  onMount(load);
</script>

<svelte:window onkeydown={(e) => e.key === "Escape" && close()} />

<div class="scrim">
  <section>
    <header>
      <h2>{titles[sheet.kind]}</h2>
      <button onclick={close}>Close</button>
    </header>

    {#if sheet.kind === "generate"}
      <p class="mono secret">{value}</p>
      <div class="row">
        <button onclick={async () => (value = await call("generate"))}>Another</button>
        <button class="primary" onclick={async () => say([await call("copy_text", { label: "the generated password", text: value })])}>Copy</button>
      </div>
      <p class="dim">Settings come from [generator] in the config file. New entry › generate puts one straight into the form.</p>
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
        <div class="line">
          <span>
            <strong>{r.name}</strong>
            {#if r.file}<span class="dim">{r.bytes} bytes</span>{:else}<span class="dim mono">{r.secret ? "••••••" : r.value}</span>{/if}
          </span>
          <span class="actions">
            {#if r.file}
              <button onclick={() => act("extract", { id: sheet.id, name: r.name })}>Save beside vault</button>
              <button onclick={() => act("agent_give", { id: sheet.id, name: r.name })}>To ssh-agent</button>
            {:else}
              <button onclick={async () => say([await call("copy_field", { id: sheet.id, name: r.name })])}>Copy</button>
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
          <input class="mono" bind:value={adding.from} placeholder={adding.file ? "Path to the file" : "Value (stored protected)"} spellcheck="false" />
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
</div>

<style>
  .scrim {
    position: fixed;
    inset: 0;
    background: rgb(0 0 0 / 0.45);
    display: grid;
    place-items: center;
    padding: 20px;
  }

  section {
    background: var(--panel);
    border: 1px solid var(--line);
    border-radius: 10px;
    padding: 16px 18px;
    width: min(620px, 100%);
    max-height: 100%;
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
    font-size: 17px;
  }

  .line {
    display: flex;
    justify-content: space-between;
    align-items: center;
    gap: 12px;
    padding: 6px 8px;
    border-radius: var(--radius);
    background: var(--bg);
    border: 1px solid var(--line);
    text-align: left;
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
    font-size: 18px;
    padding: 12px;
    background: var(--bg);
    border-radius: var(--radius);
    word-break: break-all;
    -webkit-user-select: none;
    user-select: none;
  }

  p {
    margin: 0;
    font-size: 13px;
  }
</style>
