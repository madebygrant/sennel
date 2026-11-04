<script>
  import { onMount, untrack } from "svelte";
  import { call } from "./api.js";
  import Modal from "./Modal.svelte";

  // `env.id` replaces that entry's variables; otherwise a new entry goes in `env.group`.
  let { env, say, close } = $props();

  let title = $state(untrack(() => env.title ?? ""));
  let text = $state("");
  let preview = $state(null);
  let busy = $state(false);
  let titleBox;
  let pasteBox;
  // Bumped per keystroke, so a slow preview never replaces the one for newer text.
  let asked = 0;
  let timer;

  onMount(() => (env.id ? pasteBox : titleBox)?.focus());

  function changed() {
    clearTimeout(timer);
    timer = setTimeout(async () => {
      const mine = ++asked;
      if (!text.trim()) {
        preview = null;
        return;
      }
      try {
        const got = await call("env_preview", { id: env.id ?? null, text });
        if (mine === asked) preview = got;
      } catch (why) {
        say([{ level: "error", text: String(why) }]);
      }
    }, 150);
  }

  // The paste holds every value, so it is cleared on the way out whatever happens.
  function done(reply) {
    clearTimeout(timer);
    text = "";
    close(reply);
  }

  async function submit(event) {
    event.preventDefault();
    busy = true;
    try {
      const reply = await call("save_env", { id: env.id ?? null, group: env.group ?? null, title, text });
      say(reply.notes);
      if (reply.ok) done(reply);
    } catch (why) {
      say([{ level: "error", text: String(why) }]);
    } finally {
      busy = false;
    }
  }

  const heading = $derived(env.id ? `Replace ${env.title ?? "variables"}` : "New environment variables");
  const sections = $derived.by(() => {
    const out = [];
    for (const r of preview?.rows ?? []) {
      const last = out.at(-1);
      if (last && last.name === (r.section ?? null)) last.rows.push(r);
      else out.push({ name: r.section ?? null, rows: [r] });
    }
    return out;
  });
  const blocked = $derived(!text.trim() || (preview?.refused.length ?? 0) > 0 || (!env.id && !title.trim()));
</script>

<Modal label={heading} onclose={() => done(null)}>
  <form onsubmit={submit}>
    <h2>{heading}</h2>
    {#if !env.id}
      <label>Title <input bind:this={titleBox} bind:value={title} placeholder="myapp development" /></label>
    {/if}
    <label>
      Paste the whole .env file
      <textarea
        bind:this={pasteBox}
        rows="8"
        class="mono"
        bind:value={text}
        oninput={changed}
        spellcheck="false"
        autocomplete="off"
        placeholder={"# Database\nDATABASE_URL=postgres://…"}
      ></textarea>
    </label>
    <p class="dim">Comments become labels. A commented-out variable is kept, protected, and left out of <code>sennel run</code>.{env.id ? " Variables missing from the paste are removed." : ""}</p>
    {#if preview}
      {#if preview.refused.length}
        <ul class="refused level-warn" role="alert">
          {#each preview.refused as r}<li>Line {r.line}: {r.why}</li>{/each}
        </ul>
      {/if}
      <div class="preview" aria-label="What saving does">
        {#each sections as s}
          {#if s.name}<h3>{s.name}</h3>{/if}
          {#each s.rows as r (r.field)}
            <div class="row" class:off={r.disabled} class:removed={r.status === "removed"}>
              <span class="name">{r.name}</span>
              <span class="label">{r.label ?? ""}{r.disabled ? " (commented out)" : ""}</span>
              <span class="status {r.status}">{r.status}</span>
            </div>
          {/each}
        {:else}
          <p class="dim">No variables yet.</p>
        {/each}
      </div>
    {/if}
    <div class="buttons">
      <span class="gap"></span>
      <button type="button" onclick={() => done(null)}>Cancel</button>
      <button class="primary" type="submit" disabled={busy || blocked}>{env.id ? "Replace" : "Add"}</button>
    </div>
  </form>
</Modal>

<style>
  form {
    background: var(--panel);
    border: 1px solid var(--line);
    border-radius: var(--radius);
    box-shadow: 0 24px 60px -24px rgb(0 0 0 / 0.6);
    padding: 18px 20px;
    width: min(620px, calc(100vw - 40px));
    max-height: calc(100vh - 40px);
    overflow: auto;
    display: grid;
    gap: 11px;
  }

  h2 {
    margin: 0 0 4px;
    font-family: var(--action);
    font-size: 18px;
    font-weight: 600;
  }

  h3 {
    margin: 8px 0 2px;
    font-size: 12px;
    font-weight: 600;
    color: var(--dim);
    text-transform: uppercase;
    letter-spacing: 0.04em;
  }

  label {
    display: grid;
    gap: 4px;
    color: var(--dim);
    font-size: 12.5px;
  }

  label :global(input),
  textarea {
    color: var(--text);
    font-size: 14px;
  }

  textarea {
    resize: vertical;
    font-family: var(--mono);
    font-size: 13px;
  }

  p {
    margin: 0;
    font-size: 12.5px;
  }

  .refused {
    margin: 0;
    padding-left: 18px;
    font-size: 12.5px;
  }

  .preview {
    border: 1px solid var(--line);
    border-radius: var(--radius);
    padding: 6px 10px;
    max-height: 240px;
    overflow: auto;
  }

  .row {
    display: grid;
    grid-template-columns: minmax(0, 1fr) minmax(0, 1fr) auto;
    gap: 10px;
    padding: 3px 0;
    font-size: 13px;
    align-items: baseline;
  }

  .row .name {
    font-family: var(--mono);
    overflow: hidden;
    text-overflow: ellipsis;
  }

  .row .label {
    color: var(--dim);
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
  }

  .row.off .name,
  .row.removed .name {
    color: var(--faint);
  }

  .row.removed .name {
    text-decoration: line-through;
  }

  .status {
    font-size: 11.5px;
    color: var(--faint);
  }

  .status.new {
    color: var(--accent-text);
  }

  .status.changed {
    color: var(--warn);
  }

  .status.removed {
    color: var(--error);
  }

  .buttons {
    display: flex;
    gap: 8px;
    margin-top: 4px;
  }

  .gap {
    flex: 1;
  }
</style>
