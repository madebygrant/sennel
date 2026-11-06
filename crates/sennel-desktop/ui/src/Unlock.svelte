<script>
  import { onMount, tick, untrack } from "svelte";
  import { open as pickFile, save as pickSave } from "@tauri-apps/plugin-dialog";
  import { call, secretCopy } from "./api.js";
  import HexField from "./HexField.svelte";
  import Mark from "./Mark.svelte";
  import SecretInput from "./SecretInput.svelte";
  import { radioKeys } from "./radio.js";
  import { strength, typedBits } from "./strength.js";
  import { fits, pathNote } from "./unlock.js";

  let { status, say, refresh } = $props();

  const KDBX = [{ name: "KeePass vault", extensions: ["kdbx"] }];

  // Seeded once: what is typed here wins over later status refreshes.
  let path = $state(untrack(() => status.db ?? ""));
  // Creating is its own mode, so a typo in a path never quietly makes a second vault.
  let mode = $state(untrack(() => ((status.creates || (!status.db && !status.recent.length)) ? "new" : "open")));
  let check = $state(null);
  let password = $state("");
  let confirm = $state("");
  let keyFile = $state("");
  let reveal = $state(false);
  let busy = $state(false);
  // Shown under the password box, where the eye already is, instead of in the footer.
  let error = $state(null);
  let pathBox = $state();
  let passwordBox = $state();
  let confirmBox = $state();
  // Bumped per check, so a slow answer never replaces the one for newer text.
  let asked = 0;
  let timer;

  onMount(() => {
    checkNow();
    (path ? passwordBox : pathBox)?.focus();
  });

  async function checkNow() {
    clearTimeout(timer);
    const mine = ++asked;
    try {
      const got = await call("check_path", { path });
      if (mine === asked) check = got;
      return got;
    } catch (why) {
      say([{ level: "error", text: String(why) }]);
      return null;
    }
  }

  function typed() {
    error = null;
    clearTimeout(timer);
    timer = setTimeout(checkNow, 150);
  }

  // False when the path was refused, so nothing is unlocked against the vault aimed at before.
  async function choose(next) {
    path = next;
    checkNow();
    try {
      await call("choose", { path });
      await refresh();
      return true;
    } catch (why) {
      say([{ level: "warn", text: String(why) }]);
      return false;
    }
  }

  // From the arrow keys `stay` keeps focus on the radio, as a native radio group does.
  async function switchTo(next, stay = false) {
    if (mode === next) return;
    mode = next;
    error = null;
    confirm = "";
    // Starting a new vault from an existing one's path would only say it is taken.
    if (next === "new" && check?.kind === "vault") {
      path = "";
      await checkNow();
    } else if (next === "open" && !path && status.db) {
      path = status.db;
      await checkNow();
    }
    if (stay) return;
    await tick();
    (path ? passwordBox : pathBox)?.focus();
  }

  // A failed dialog would otherwise be an unhandled rejection, and the button would look dead.
  async function picking(show) {
    try {
      return await show();
    } catch (why) {
      say([{ level: "error", text: `the file dialog failed · ${why}` }]);
      return null;
    }
  }

  async function browse() {
    const picked = await picking(() =>
      mode === "new"
        ? pickSave({ title: "Save the new vault", defaultPath: check?.full ?? "vault.kdbx", filters: KDBX })
        : pickFile({ title: "Open a vault", multiple: false, directory: false, filters: KDBX, defaultPath: check?.full ?? undefined }),
    );
    if (picked && (await choose(picked))) passwordBox?.focus();
  }

  async function browseKey() {
    const picked = await picking(() => pickFile({ title: "Key file", multiple: false, directory: false }));
    if (picked) keyFile = picked;
  }

  async function submit(event) {
    event.preventDefault();
    if (busy) return;
    if ((status.db ?? "") !== path.trim() && !(await choose(path))) return;
    // Rechecked here: enter can land before the debounced check of the last keystroke.
    const now = await checkNow();
    if (!now || !fits(mode, now.kind)) return;
    if (mode === "new" && !confirm) {
      confirmBox?.focus();
      return;
    }
    busy = true;
    let notes = [];
    try {
      const keys = { keyFile: keyFile || null };
      const reply =
        mode === "open" && password === "" && status.quickReady
          ? await call("quick_unlock", keys)
          : await call("unlock", { password, confirm: mode === "new" ? confirm : null, ...keys });
      notes = reply.notes;
    } catch (why) {
      notes = [{ level: "error", text: String(why) }];
    } finally {
      // A JS string cannot be wiped, only dropped; this is the most the webview can do.
      password = "";
      confirm = "";
      busy = false;
      await refresh();
    }
    // A successful unlock can still warn (read-only, Touch ID off), and this screen is gone by then.
    if (status.open) {
      say(notes);
      return;
    }
    error = notes.filter((n) => n.level !== "info").at(-1)?.text ?? null;
    say(notes.filter((n) => n.level === "info"));
  }

  const bits = $derived(typedBits(password));
  // Quiet while the second box is still a prefix of the first, so it does not shout mid-word.
  const differs = $derived(confirm !== "" && !password.startsWith(confirm));
  const matches = $derived(confirm !== "" && confirm === password);
  const ready = $derived(
    !busy && (!check || fits(mode, check.kind)) && (mode === "open" || (password !== "" && matches)),
  );
  const note = $derived(pathNote(mode, check));
</script>

<main>
  <HexField />
  <form onsubmit={submit}>
    <h1>
      <Mark />
      Sennel
    </h1>

    {#if status.configError}
      <p class="error" role="alert">Config file not used: {status.configError}</p>
    {/if}

    <div class="modes" role="radiogroup" aria-label="Vault" tabindex="-1" onkeydown={(e) => radioKeys(e, ["open", "new"], mode, (next) => switchTo(next, true))}>
      {#each [["open", "Open vault"], ["new", "New vault"]] as [value, label]}
        <button type="button" role="radio" aria-checked={mode === value} tabindex={mode === value ? 0 : -1} class:on={mode === value} onclick={() => switchTo(value)}>{label}</button>
      {/each}
    </div>

    <div class="field">
      <label for="vault-path">{mode === "new" ? "Save the new vault as" : "Vault file"}</label>
      <div class="pick">
        <input
          id="vault-path"
          class="mono"
          bind:this={pathBox}
          bind:value={path}
          oninput={typed}
          onchange={() => choose(path)}
          placeholder={mode === "new" ? "~/Documents/vault.kdbx" : "~/vault.kdbx"}
          spellcheck="false"
          aria-describedby="path-note"
        />
        <button type="button" onclick={browse}>{mode === "new" ? "Choose…" : "Browse…"}</button>
      </div>
      <p id="path-note" class="note" aria-live="polite">
        {#if note}
          <span class={note.level === "dim" ? "dim" : `level-${note.level}`}>{note.text}</span>
          {#if note.action}<button type="button" class="link" onclick={() => switchTo(note.action.to)}>{note.action.label}</button>{/if}
          {#if note.after}<span class="dim">{note.after}</span>{/if}
          {#if note.warn}<span class="level-warn">{note.warn}</span>{/if}
        {/if}
      </p>
    </div>

    <label>
      <span>
        {mode === "new" ? "New master password" : "Master password"}
        <button type="button" class="small" onclick={() => (reveal = !reveal)}>{reveal ? "Hide" : "Show"}</button>
      </span>
      <SecretInput
        bind:box={passwordBox}
        bind:value={password}
        {reveal}
        hint={mode === "open" && status.quickReady ? "enter for Touch ID" : ""}
        autocomplete="off"
        oncopy={secretCopy("password", say)}
        oncut={secretCopy("password", say)}
        oninput={() => (error = null)}
        aria-label={mode === "new" ? "New master password" : "Master password"}
        aria-invalid={error ? "true" : undefined}
        aria-describedby={error ? "unlock-error" : mode === "new" ? "strength" : undefined}
      />
    </label>

    {#if mode === "new"}
      <p id="strength" class="note" aria-live="polite">
        {#if password}
          <span class="meter {strength(bits)}" style:--fill={`${Math.min(bits, 100)}%`}></span>
          <span class="{strength(bits)}">~{Math.round(bits)} bits · {strength(bits)}</span>
          {#if bits < 60}<span class="dim">A few random words go further than symbols.</span>{/if}
        {:else}
          <span class="dim">Nothing can recover the vault if you forget this.</span>
        {/if}
      </p>
    {/if}

    {#if error}
      <p id="unlock-error" class="error" role="alert">{error}</p>
    {/if}

    {#if mode === "new"}
      <label>
        <span>
          Again
          {#if matches}<em class="ok">matches</em>{:else if differs}<em class="level-warn">differs</em>{/if}
        </span>
        <SecretInput
          bind:box={confirmBox}
          bind:value={confirm}
          {reveal}
          autocomplete="off"
          oncopy={secretCopy("password", say)}
          oncut={secretCopy("password", say)}
          aria-invalid={differs ? "true" : undefined}
        />
      </label>
    {/if}

    <div class="field">
      <label for="key-file">Key file <em class="dim">optional</em></label>
      <div class="pick">
        <input id="key-file" class="mono" bind:value={keyFile} spellcheck="false" aria-describedby={mode === "new" && keyFile ? "key-note" : undefined} />
        <button type="button" onclick={browseKey}>Browse…</button>
      </div>
      {#if mode === "new" && keyFile}
        <p id="key-note" class="note level-warn">The vault will need this file every time it opens. Keep a copy apart from the vault.</p>
      {/if}
    </div>

    {#if status.yubikey}
      <p class="dim">YubiKey {status.yubikey}: touch it when it blinks</p>
    {/if}

    <button class="primary" type="submit" disabled={!ready}>
      {#if busy}{mode === "new" ? "creating…" : "unlocking…"}{:else if mode === "new"}Create vault{:else if password === "" && status.quickReady}Unlock with Touch ID{:else}Unlock{/if}
    </button>

    {#if status.recent.length}
      <section>
        <h2>Library</h2>
        <ul>
          {#each status.recent as row}
            <li>
              <button
                type="button"
                class="row mono"
                class:current={row === status.db}
                onclick={async () => {
                  mode = "open";
                  if (await choose(row)) passwordBox?.focus();
                }}>{row}</button
              >
            </li>
          {/each}
        </ul>
      </section>
    {/if}
  </form>
</main>

<style>
  main {
    position: relative;
    height: calc(100% - 30px);
    overflow: auto;
    display: grid;
    place-items: center;
    padding: 24px;
  }

  form {
    position: relative;
    width: min(460px, 100%);
    display: grid;
    gap: 14px;
  }

  h1 {
    display: flex;
    align-items: center;
    gap: 14px;
    margin: 0 0 6px;
    font-size: 34px;
    font-family: var(--action);
    font-weight: 600;
    color: var(--accent-text);
  }

  h2 {
    margin: 10px 0 6px;
    font-size: 12px;
    color: var(--dim);
  }

  label {
    display: grid;
    gap: 5px;
  }

  label > span {
    display: flex;
    justify-content: space-between;
    color: var(--dim);
    font-size: 12.5px;
  }

  .modes {
    display: flex;
    gap: 4px;
    padding: 3px;
    background: var(--panel);
    border-radius: var(--radius);
    justify-self: start;
  }

  .modes button {
    padding: 4px 14px;
    font-size: 13px;
    color: var(--dim);
    background: transparent;
  }

  .modes button.on {
    background: var(--accent);
    color: var(--accent-ink);
  }

  .field {
    display: grid;
    gap: 5px;
  }

  .field > label {
    display: flex;
    gap: 6px;
    color: var(--dim);
    font-size: 12.5px;
  }

  .pick {
    display: flex;
    gap: 6px;
  }

  .pick input {
    flex: 1;
    min-width: 0;
  }

  .note {
    display: flex;
    flex-wrap: wrap;
    align-items: center;
    gap: 2px 6px;
    margin-top: -6px;
    overflow-wrap: anywhere;
  }

  .link {
    padding: 0;
    border: 0;
    background: none;
    font-size: inherit;
    color: var(--accent-text);
    text-decoration: underline;
    cursor: pointer;
  }

  .meter {
    width: 64px;
    height: 4px;
    border-radius: 2px;
    background: linear-gradient(to right, currentColor var(--fill), var(--line) var(--fill));
  }

  .weak {
    color: var(--error);
  }

  .fair {
    color: var(--warn);
  }

  .good,
  .strong,
  .ok {
    color: var(--ok);
  }

  em {
    font-style: normal;
  }

  .small {
    padding: 1px 8px;
    font-size: 12px;
    color: var(--text);
  }

  .error {
    color: var(--error);
  }

  ul {
    list-style: none;
    margin: 0;
    padding: 0;
    display: grid;
    gap: 4px;
  }

  .row {
    display: block;
    width: 100%;
    text-align: left;
    overflow: hidden;
    text-overflow: ellipsis;
    font-size: 12.5px;
    background: var(--panel);
  }

  .row.current {
    color: var(--text);
    background: var(--raised);
  }

  p {
    margin: 0;
    font-size: 12.5px;
  }
</style>
