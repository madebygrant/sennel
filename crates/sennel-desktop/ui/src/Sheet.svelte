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
  // What the field form is for: { file, kind, edit, secret }. `edit` names the field being edited.
  let adding = $state(null);
  // Bound apart from `adding`, so closing the form never leaves a binding reading through null.
  let formName = $state("");
  let formValue = $state("");
  let made = $state(null);

  const FIELD_KINDS = [
    ["text", "Text"],
    ["textarea", "Text area"],
    ["number", "Number"],
    ["password", "Password"],
  ];

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

  function openForm(meta, name = "", value = "") {
    adding = meta;
    formName = name;
    formValue = value;
  }

  function closeForm() {
    adding = null;
    formName = "";
    formValue = "";
  }

  // A protected field's value never reaches the window, so its box starts empty and empty keeps it.
  function editField(r) {
    openForm({ file: false, kind: r.kind, edit: r.name, secret: r.secret }, r.name, r.secret ? "" : (r.value ?? ""));
  }

  async function submitField(event) {
    event.preventDefault();
    const { file, kind, edit, secret } = adding;
    const name = formName;
    const value = formValue;
    closeForm();
    if (file) await act("attach", { id: sheet.id, name, path: value });
    else if (edit !== null) await act("edit_field", { id: sheet.id, name: edit, newName: name, value: secret && value === "" ? null : value, kind });
    else await act("add_field", { id: sheet.id, name, value, kind });
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
        {#if !r.file && adding?.edit === r.name}
          {@render fieldForm()}
        {:else}
          <div class="line" use:fb.spot={r.name}>
            <span>
              <strong>{r.name}</strong>
              {#if r.file}<span class="dim">{r.bytes} bytes</span>{:else}<span class="dim mono lit">{r.secret ? "••••••" : (r.shown ?? r.value)}</span>{/if}
            </span>
            <span class="actions">
              {#if r.file}
                <button onclick={() => act("extract", { id: sheet.id, name: r.name })}>Save to files folder</button>
                <button onclick={() => act("agent_give", { id: sheet.id, name: r.name })}>To ssh-agent</button>
              {:else}
                <button onclick={() => copyOut(r.name, "copy_field", { id: sheet.id, name: r.name })}>{fb.copied === r.name ? "Copied" : "Copy"}</button>
                {#if !adding}<button onclick={() => editField(r)}>Edit</button>{/if}
              {/if}
              <button class="danger" onclick={() => act("remove_field", { id: sheet.id, name: r.name, file: r.file })}>Remove</button>
            </span>
          </div>
        {/if}
      {:else}
        <p class="dim">No custom fields or attachments.</p>
      {/each}
      {#if adding && adding.edit === null}
        {@render fieldForm()}
      {:else if !adding}
        <div class="row">
          <button onclick={() => openForm({ file: false, kind: "password", edit: null, secret: false })}>Add field</button>
          <button onclick={() => openForm({ file: true, kind: null, edit: null, secret: false })}>Attach file</button>
        </div>
      {/if}
    {/if}
  </section>
</Modal>

{#snippet fieldForm()}
  <form class="add" class:wide={adding?.kind === "textarea"} onsubmit={submitField}>
    {#if !adding?.file}
      <div class="kinds" role="radiogroup" aria-label="Field type">
        {#each FIELD_KINDS as [kind, label]}
          <button type="button" role="radio" aria-checked={adding?.kind === kind} class:on={adding?.kind === kind} onclick={() => (adding.kind = kind)}>{label}</button>
        {/each}
      </div>
    {/if}
    <input bind:value={formName} placeholder="Name" />
    {#if adding?.file}
      <input class="mono" bind:value={formValue} placeholder="Path to the file" spellcheck="false" />
    {:else if adding?.kind === "textarea"}
      <textarea class="mono" rows="4" bind:value={formValue} placeholder={adding?.secret ? "Unchanged · type to replace" : "Value"} spellcheck="false" oncopy={secretCopy(formName || "the value", say)} oncut={secretCopy(formName || "the value", say)}></textarea>
    {:else}
      <input
        class="mono"
        type={adding?.kind === "password" ? "password" : "text"}
        inputmode={adding?.kind === "number" ? "decimal" : undefined}
        bind:value={formValue}
        placeholder={adding?.secret ? "Unchanged · type to replace" : adding?.kind === "password" ? "Value (stored protected)" : adding?.kind === "number" ? "Digits, like 0042 or 3.5" : "Value"}
        spellcheck="false"
        oncopy={secretCopy(formName || "the value", say)}
        oncut={secretCopy(formName || "the value", say)}
      />
    {/if}
    <div class="submit">
      <button type="button" onclick={closeForm}>Cancel</button>
      <button class="primary" type="submit">{adding?.edit === null ? "Add" : "Save"}</button>
    </div>
  </form>
{/snippet}

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

  .line .actions {
    flex-shrink: 0;
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

  .add .kinds {
    grid-column: 1 / -1;
    display: flex;
    gap: 4px;
  }

  .kinds button {
    padding: 3px 10px;
    font-size: 12.5px;
    color: var(--dim);
  }

  .kinds button.on {
    background: var(--accent);
    color: var(--accent-ink);
  }

  .add.wide {
    grid-template-columns: 1fr auto;
  }

  .submit {
    display: flex;
    gap: 6px;
  }

  .add.wide textarea {
    grid-column: 1 / -1;
    grid-row: 3;
    resize: vertical;
  }

  .secret {
    padding: 6px 0;
  }

  p {
    margin: 0;
    font-size: 13px;
  }
</style>
