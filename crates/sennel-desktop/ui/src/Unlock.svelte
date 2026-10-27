<script>
  import { onMount, untrack } from "svelte";
  import { call, secretCopy } from "./api.js";
  import HexField from "./HexField.svelte";

  let { status, say, refresh } = $props();

  // Seeded once: what is typed here wins over later status refreshes.
  let path = $state(untrack(() => status.db ?? ""));
  let password = $state("");
  let confirm = $state("");
  let keyFile = $state("");
  let reveal = $state(false);
  let busy = $state(false);
  // Shown under the password box, where the eye already is, instead of in the footer.
  let error = $state(null);
  let passwordBox;

  onMount(() => passwordBox?.focus());

  // False when the path was refused, so nothing is unlocked against the vault aimed at before.
  async function choose(next) {
    path = next;
    try {
      await call("choose", { path });
      await refresh();
      return true;
    } catch (why) {
      say([{ level: "warn", text: String(why) }]);
      return false;
    }
  }

  async function submit(event) {
    event.preventDefault();
    if (busy) return;
    if ((status.db ?? "") !== path.trim() && !(await choose(path))) return;
    busy = true;
    let notes = [];
    try {
      const keys = { keyFile: keyFile || null };
      const reply =
        password === "" && status.touchId
          ? await call("quick_unlock", keys)
          : await call("unlock", { password, confirm: status.creates ? confirm : null, ...keys });
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
</script>

<main>
  <HexField />
  <form onsubmit={submit}>
    <h1>Sennel</h1>

    <label>
      <span>Vault file</span>
      <input class="mono" bind:value={path} onchange={() => choose(path)} placeholder="~/vault.kdbx" spellcheck="false" />
    </label>

    <label>
      <span>
        {status.creates ? "New master password" : "Master password"}
        <button type="button" class="small" onclick={() => (reveal = !reveal)}>{reveal ? "Hide" : "Show"}</button>
      </span>
      <input
        bind:this={passwordBox}
        bind:value={password}
        type={reveal ? "text" : "password"}
        autocomplete="off"
        oncopy={secretCopy("password", say)}
        oncut={secretCopy("password", say)}
        oninput={() => (error = null)}
        aria-invalid={error ? "true" : undefined}
        aria-describedby={error ? "unlock-error" : undefined}
        placeholder={status.touchId ? "enter for Touch ID" : ""}
      />
    </label>

    {#if error}
      <p id="unlock-error" class="error" role="alert">{error}</p>
    {/if}

    {#if status.creates}
      <label>
        <span>Again</span>
        <input
          bind:value={confirm}
          type={reveal ? "text" : "password"}
          autocomplete="off"
          oncopy={secretCopy("password", say)}
          oncut={secretCopy("password", say)}
        />
      </label>
    {/if}

    <label>
      <span>Key file <em class="dim">optional</em></span>
      <input class="mono" bind:value={keyFile} spellcheck="false" />
    </label>

    {#if status.yubikey}
      <p class="dim">YubiKey {status.yubikey}: touch it when it blinks</p>
    {/if}

    <button class="primary" type="submit" disabled={busy}>
      {#if busy}unlocking…{:else if status.creates}Create vault{:else if password === "" && status.touchId}Unlock with Touch ID{:else}Unlock{/if}
    </button>

    {#if status.recent.length}
      <section>
        <h2>Library</h2>
        <ul>
          {#each status.recent as row}
            <li>
              <button type="button" class="row mono" class:current={row === status.db} onclick={() => choose(row)}>{row}</button>
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
    margin: 0 0 6px;
    font-size: 34px;
    font-family: var(--action);
    font-weight: 600;
    color: var(--accent);
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
    color: var(--accent);
    background: color-mix(in oklab, var(--accent) 14%, var(--panel));
  }

  p {
    margin: 0;
    font-size: 12.5px;
  }
</style>
