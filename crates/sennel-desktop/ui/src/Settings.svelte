<script>
  import { onMount, tick } from "svelte";
  import { call } from "./api.js";
  import Modal from "./Modal.svelte";
  import { radioKeys } from "./radio.js";
  import { CLIPBOARD_PRESETS, LOCK_PRESETS, ORDERS, choices, spell } from "./settings.js";

  // `changed` runs after a setting the entries list shows, so it can redraw.
  let { say, refresh, changed, close } = $props();

  let prefs = $state(null);
  // Fixed while open: dropping an odd value once it is unpicked would shift the arrow keys' focus.
  let lockList = $state([]);
  let clipList = $state([]);
  let box = $state();
  const orderName = Object.fromEntries(ORDERS);
  const field = { lock_timeout: "lockTimeout", clipboard_timeout: "clipboardTimeout", sort: "sort", single_keys: "singleKeys", backups: "backups", touch_id: "touchId" };

  onMount(async () => {
    prefs = await call("prefs");
    lockList = choices(LOCK_PRESETS, prefs.lockTimeout);
    clipList = choices(CLIPBOARD_PRESETS, prefs.clipboardTimeout);
    await tick();
    box?.querySelector('[aria-checked="true"]')?.focus();
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

{#snippet radios(key, label, list, current, name)}
  <div class="choices" role="radiogroup" aria-label={label} tabindex="-1" onkeydown={(e) => radioKeys(e, list, current, (v) => set(key, v))}>
    {#each list as value}
      <button type="button" role="radio" aria-checked={value === current} tabindex={value === current ? 0 : -1} class:on={value === current} onclick={() => set(key, value)}>{name(value)}</button>
    {/each}
  </div>
{/snippet}

{#snippet toggle(key, label, on)}
  <button type="button" class="switch" role="switch" aria-checked={on} aria-label={label} class:on onclick={() => set(key, !on)}><span></span></button>
{/snippet}

<Modal label="Settings" onclose={close}>
  <section bind:this={box}>
    <header>
      <h2>Settings</h2>
      <button onclick={close}>Close</button>
    </header>

    {#if prefs}
      <h3>Locking</h3>
      <div class="setting">
        <span class="name">Lock after</span>
        <p class="dim">With no key or click for this long, the vault locks and its secrets are wiped from memory.</p>
        {@render radios("lock_timeout", "Lock after", lockList, prefs.lockTimeout, spell)}
        {#if !prefs.lockTimeout}
          <p class="level-warn">The vault stays open until you lock it. Only choose this on a computer nobody else uses.</p>
        {/if}
      </div>
      {#if prefs.touchId != null}
        <div class="setting row">
          <div>
            <span class="name">Touch ID</span>
            <p class="dim">Unlock with a fingerprint. It starts after the next unlock with the password and lasts until Sennel quits.</p>
          </div>
          {@render toggle("touch_id", "Touch ID", prefs.touchId)}
        </div>
      {/if}

      <h3>Clipboard</h3>
      <div class="setting">
        <span class="name">Clear copies after</span>
        <p class="dim">Takes effect from the next copy.</p>
        {@render radios("clipboard_timeout", "Clear copies after", clipList, prefs.clipboardTimeout, spell)}
        {#if !prefs.clipboardTimeout}
          <p class="level-warn">Copied passwords stay on the clipboard, where any app can read them.</p>
        {/if}
      </div>

      <h3>Entries</h3>
      <div class="setting">
        <span class="name">Open the list in</span>
        <p class="dim"><kbd>o</kbd> still changes the order for the session.</p>
        {@render radios("sort", "Open the list in", ORDERS.map(([k]) => k), prefs.sort, (k) => orderName[k])}
      </div>
      <div class="setting row">
        <div>
          <span class="name">Single-letter keys</span>
          <p class="dim">Keys like <kbd>p</kbd> and <kbd>/</kbd> act when the cursor is not in a text box. ⌘ keys work either way.</p>
        </div>
        {@render toggle("single_keys", "Single-letter keys", prefs.singleKeys)}
      </div>

      <h3>Backups</h3>
      <div class="setting row">
        <div>
          <span class="name">Copies to keep</span>
          <p class="dim">Earlier versions of the vault, written as it is saved. 0 keeps none.</p>
        </div>
        <div class="stepper">
          <button type="button" aria-label="Fewer" disabled={prefs.backups <= 0} onclick={() => set("backups", (p) => Math.max(0, p.backups - 1))}>−</button>
          <span aria-live="polite">{prefs.backups}</span>
          <button type="button" aria-label="More" disabled={prefs.backups >= prefs.backupsMax} onclick={() => set("backups", (p) => Math.min(p.backupsMax, p.backups + 1))}>+</button>
        </div>
      </div>

      <p class="dim where">
        {#if prefs.configFile}
          Saved to <code>{prefs.configFile}</code>, which the terminal app also uses from its next start.
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
    padding: 18px 20px;
    width: min(500px, calc(100vw - 40px));
    max-height: calc(100vh - 40px);
    overflow-y: auto;
    display: grid;
    gap: 12px;
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

  h3 {
    margin: 4px 0 0;
    padding-top: 12px;
    border-top: 1px solid var(--line);
    font-size: 11.5px;
    font-weight: 600;
    letter-spacing: 0.06em;
    text-transform: uppercase;
    color: var(--faint);
  }

  .setting {
    display: grid;
    gap: 6px;
  }

  .setting.row {
    grid-template-columns: 1fr auto;
    align-items: center;
    gap: 16px;
  }

  .row > div:first-child {
    display: grid;
    gap: 4px;
  }

  .name {
    font-weight: 600;
  }

  p {
    margin: 0;
    font-size: 12.5px;
  }

  kbd {
    font: 12px var(--mono);
    color: var(--accent-text);
  }

  .choices {
    display: flex;
    flex-wrap: wrap;
    gap: 4px;
  }

  .choices button {
    padding: 3px 10px;
    font-size: 12.5px;
    color: var(--dim);
  }

  .choices button.on {
    background: var(--accent);
    color: var(--accent-ink);
  }

  .switch {
    width: 40px;
    height: 24px;
    padding: 3px;
    border-radius: 11px;
    border: 1px solid var(--line);
    display: flex;
  }

  .switch span {
    width: 16px;
    height: 16px;
    border-radius: 50%;
    background: var(--dim);
    transition: transform 0.15s;
  }

  .switch.on {
    background: var(--accent);
  }

  .switch.on span {
    background: var(--accent-ink);
    transform: translateX(16px);
  }

  .stepper {
    display: flex;
    align-items: center;
    gap: 8px;
  }

  .stepper button {
    width: 26px;
    padding: 2px 0;
  }

  .stepper span {
    min-width: 2ch;
    text-align: center;
    font: 13px var(--mono);
  }

  .where {
    padding-top: 12px;
    border-top: 1px solid var(--line);
  }

  .where code {
    font: 12px var(--mono);
    overflow-wrap: anywhere;
  }
</style>
