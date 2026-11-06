<script>
  import { onMount, tick } from "svelte";
  import { ChevronDown } from "@lucide/svelte";
  import { call } from "./api.js";
  import Modal from "./Modal.svelte";
  import { CLIPBOARD_PRESETS, LOCK_PRESETS, ORDERS, choices, spell } from "./settings.js";

  // `changed` runs after a setting the entries list shows, so it can redraw.
  let { say, refresh, changed, close } = $props();

  let prefs = $state(null);
  let box = $state();
  const field = { lock_timeout: "lockTimeout", clipboard_timeout: "clipboardTimeout", sort: "sort", single_keys: "singleKeys", backups: "backups", touch_id: "touchId" };

  onMount(async () => {
    prefs = await call("prefs");
    await tick();
    box?.querySelector("select")?.focus();
  });

  // Applied on pick, like a native settings pane: there is no Save to forget. Picks queue rather
  // than drop, and `value` may be a function of the settings as they are once its turn comes, so
  // two quick clicks on + add two.
  let queue = Promise.resolve();
  function set(key, value) {
    queue = queue.then(() => apply(key, value));
  }

  async function apply(key, given) {
    const value = typeof given === "function" ? given(prefs) : given;
    // Sort always goes through: `o` may have moved the list off the default it names.
    if (key !== "sort" && prefs[field[key]] === value) return;
    try {
      say([await call("set_pref", { key, value })]);
      prefs = await call("prefs");
      await refresh();
      if (key === "sort" || key === "single_keys") await changed?.();
    } catch (why) {
      say([{ level: "error", text: String(why) }]);
    }
  }
</script>

{#snippet seconds(key, id, current, presets)}
  <span class="pick">
    <select {id} value={current} onchange={(e) => set(key, Number(e.currentTarget.value))}>
      {#each choices(presets, current) as secs}
        <option value={secs}>{spell(secs)}</option>
      {/each}
    </select>
    <ChevronDown aria-hidden="true" />
  </span>
{/snippet}

{#snippet toggle(key, id, on, label)}
  <button type="button" {id} class="switch" role="switch" aria-label={label} aria-checked={on} class:on onclick={() => set(key, !on)}><span></span></button>
{/snippet}

<Modal label="Settings" onclose={close}>
  <section bind:this={box}>
    <header>
      <h2>Settings</h2>
      <button onclick={close}>Done</button>
    </header>

    {#if prefs}
      <h3>Security</h3>
      <div class="group">
        <div class="row">
          <div class="text">
            <label for="lock">Lock after</label>
            <p>Idle time before the vault locks and wipes its secrets.</p>
          </div>
          {@render seconds("lock_timeout", "lock", prefs.lockTimeout, LOCK_PRESETS)}
        </div>
        {#if !prefs.lockTimeout}
          <p class="caution">The vault stays open until you lock it. Only on a computer nobody else uses.</p>
        {/if}
        {#if prefs.touchId != null}
          <div class="row">
            <div class="text">
              <label for="touch">Touch ID</label>
              <p>After one password unlock, a fingerprint opens it until Sennel quits.</p>
            </div>
            {@render toggle("touch_id", "touch", prefs.touchId, "Touch ID")}
          </div>
        {/if}
        <div class="row">
          <div class="text">
            <label for="clip">Clear the clipboard after</label>
            <p>Applies from the next copy.</p>
          </div>
          {@render seconds("clipboard_timeout", "clip", prefs.clipboardTimeout, CLIPBOARD_PRESETS)}
        </div>
        {#if !prefs.clipboardTimeout}
          <p class="caution">Copies stay on the clipboard, where any app can read them.</p>
        {/if}
      </div>

      <h3>Entries</h3>
      <div class="group">
        <div class="row">
          <div class="text">
            <label for="order">Open the list in</label>
            <p><kbd>o</kbd> still changes the order for the session.</p>
          </div>
          <span class="pick">
            <select id="order" value={prefs.sort} onchange={(e) => set("sort", e.currentTarget.value)}>
              {#each ORDERS as [key, name]}<option value={key}>{name}</option>{/each}
            </select>
            <ChevronDown aria-hidden="true" />
          </span>
        </div>
        <div class="row">
          <div class="text">
            <label for="keys">Single-letter keys</label>
            <p><kbd>p</kbd>, <kbd>/</kbd> and the rest act outside text boxes. ⌘ keys always work.</p>
          </div>
          {@render toggle("single_keys", "keys", prefs.singleKeys, "Single-letter keys")}
        </div>
      </div>

      <h3>Backups</h3>
      <div class="group">
        <div class="row">
          <div class="text">
            <span class="name" id="backups">Copies to keep</span>
            <p>Earlier versions, written as the vault is saved. 0 keeps none.</p>
          </div>
          <div class="stepper" role="group" aria-labelledby="backups">
            <button type="button" aria-label="Fewer" disabled={prefs.backups <= 0} onclick={() => set("backups", (p) => Math.max(0, p.backups - 1))}>−</button>
            <output aria-live="polite">{prefs.backups}</output>
            <button type="button" aria-label="More" disabled={prefs.backups >= prefs.backupsMax} onclick={() => set("backups", (p) => Math.min(p.backupsMax, p.backups + 1))}>+</button>
          </div>
        </div>
      </div>

      <p class="where">
        {#if prefs.configFile}
          Saved to <code>{prefs.configFile}</code>. The terminal app uses it from its next start.
        {:else}
          There is no config file this run, so changes last until Sennel closes.
        {/if}
      </p>
    {/if}
  </section>
</Modal>

<style>
  section {
    background: var(--panel);
    border: 1px solid var(--line);
    border-radius: var(--radius);
    box-shadow: 0 24px 60px -24px rgb(0 0 0 / 0.6);
    padding: 18px 20px 16px;
    width: min(540px, calc(100vw - 40px));
    max-height: calc(100vh - 40px);
    overflow-y: auto;
  }

  header {
    display: flex;
    justify-content: space-between;
    align-items: center;
    margin-bottom: 6px;
  }

  h2 {
    margin: 0;
    font-family: var(--action);
    font-size: 18px;
    font-weight: 600;
  }

  h3 {
    margin: 16px 0 6px;
    font-size: 11.5px;
    font-weight: 600;
    letter-spacing: 0.06em;
    text-transform: uppercase;
    color: var(--faint);
  }

  .group {
    background: var(--bg);
    border: 1px solid var(--line);
    border-radius: var(--radius);
  }

  .row {
    display: flex;
    align-items: center;
    gap: 20px;
    padding: 10px 12px;
  }

  .group > * + * {
    border-top: 1px solid var(--line);
  }

  .text {
    flex: 1;
    min-width: 0;
    display: grid;
    gap: 2px;
  }

  label,
  .name {
    font-size: 13.5px;
    font-weight: 500;
  }

  p {
    margin: 0;
    font-size: 12px;
    color: var(--dim);
  }

  .caution {
    padding: 7px 12px;
    color: var(--warn);
  }

  kbd {
    font: 11.5px var(--mono);
    color: var(--accent-text);
  }

  .pick {
    position: relative;
    display: inline-flex;
    align-items: center;
    flex-shrink: 0;
  }

  select {
    appearance: none;
    font: inherit;
    font-size: 13px;
    color: var(--text);
    background: var(--raised);
    border: 1px solid var(--line);
    border-radius: var(--radius);
    padding: 5px 30px 5px 10px;
    width: 152px;
    cursor: pointer;
  }

  select:focus-visible {
    outline: 2px solid var(--accent);
    outline-offset: 1px;
  }

  .pick :global(svg) {
    position: absolute;
    right: 9px;
    pointer-events: none;
    color: var(--dim);
  }

  .switch {
    flex-shrink: 0;
    width: 40px;
    height: 24px;
    padding: 3px;
    border: 1px solid var(--line);
    border-radius: 12px;
    justify-content: flex-start;
  }

  .switch span {
    width: 16px;
    height: 16px;
    border-radius: 50%;
    background: var(--dim);
    transition: transform 0.15s var(--ease);
  }

  .switch.on {
    background: var(--accent);
    border-color: var(--accent);
  }

  .switch.on span {
    background: var(--accent-ink);
    transform: translateX(16px);
  }

  .stepper {
    flex-shrink: 0;
    display: flex;
    align-items: center;
    gap: 6px;
  }

  .stepper button {
    width: 28px;
    padding: 3px 0;
  }

  output {
    min-width: 3ch;
    text-align: center;
    font: 13px var(--mono);
  }

  .where {
    margin-top: 14px;
    font-size: 11.5px;
    color: var(--faint);
  }

  .where code {
    font: 11.5px var(--mono);
    overflow-wrap: anywhere;
  }
</style>
