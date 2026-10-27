<script>
  import { onMount, untrack } from "svelte";
  import { call, secretCopy } from "./api.js";

  let { status, say, refresh } = $props();

  // Seeded once: what is typed here wins over later status refreshes.
  let path = $state(untrack(() => status.db ?? ""));
  let password = $state("");
  let confirm = $state("");
  let keyFile = $state("");
  let reveal = $state(false);
  let busy = $state(false);
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
    try {
      const keys = { keyFile: keyFile || null };
      const reply =
        password === "" && status.touchId
          ? await call("quick_unlock", keys)
          : await call("unlock", { password, confirm: status.creates ? confirm : null, ...keys });
      say(reply.notes);
    } catch (why) {
      say([{ level: "error", text: String(why) }]);
    } finally {
      // A JS string cannot be wiped, only dropped; this is the most the webview can do.
      password = "";
      confirm = "";
      busy = false;
      await refresh();
    }
  }
</script>

<main>
  <form onsubmit={submit}>
    <h1>Sennel</h1>

    <label>
      <span>Vault file</span>
      <input class="mono" bind:value={path} onchange={() => choose(path)} placeholder="~/vault.kdbx" spellcheck="false" />
    </label>

    <label>
      <span>
        {status.creates ? "New master password" : "Master password"}
        <button type="button" class="link" onclick={() => (reveal = !reveal)}>{reveal ? "hide" : "show"}</button>
      </span>
      <input
        bind:this={passwordBox}
        bind:value={password}
        type={reveal ? "text" : "password"}
        autocomplete="off"
        oncopy={secretCopy("password", say)}
        oncut={secretCopy("password", say)}
        placeholder={status.touchId ? "enter for Touch ID" : ""}
      />
    </label>

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
    height: calc(100% - 30px);
    overflow: auto;
    display: grid;
    place-items: center;
    padding: 24px;
  }

  form {
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

  .link {
    background: none;
    border: none;
    padding: 0;
    color: var(--accent);
    font-size: 12.5px;
  }

  ul {
    list-style: none;
    margin: 0;
    padding: 0;
    display: grid;
    gap: 4px;
  }

  .row {
    width: 100%;
    text-align: left;
    overflow: hidden;
    text-overflow: ellipsis;
    font-size: 12.5px;
    background: var(--panel);
  }

  .row.current {
    box-shadow: inset 3px 0 var(--accent);
  }

  p {
    margin: 0;
    font-size: 12.5px;
  }
</style>
