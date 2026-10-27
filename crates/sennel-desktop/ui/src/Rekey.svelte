<script>
  import { onMount } from "svelte";
  import { call, secretCopy } from "./api.js";
  import Modal from "./Modal.svelte";
  import SecretInput from "./SecretInput.svelte";

  let { say, close } = $props();

  let password = $state("");
  let confirm = $state("");
  let reveal = $state(false);
  let busy = $state(false);
  let error = $state(null);
  let first = $state();

  onMount(() => first?.focus());

  function done(reply) {
    // A JS string cannot be wiped, only dropped; Rust wipes its own copies.
    password = "";
    confirm = "";
    close(reply);
  }

  async function submit(event) {
    event.preventDefault();
    if (busy) return;
    busy = true;
    try {
      const reply = await call("rekey", { password, confirm });
      if (reply.ok) {
        say(reply.notes);
        done(reply);
      } else {
        error = reply.notes.at(-1)?.text ?? null;
        confirm = "";
      }
    } catch (why) {
      error = String(why);
    } finally {
      busy = false;
    }
  }
</script>

<Modal label="Change master password" onclose={() => done(null)}>
  <form onsubmit={submit}>
    <h2>Change master password</h2>
    <label>
      <span class="split">New password <button type="button" class="small" onclick={() => (reveal = !reveal)}>{reveal ? "Hide" : "Show"}</button></span>
      <SecretInput bind:box={first} bind:value={password} {reveal} autocomplete="off" oninput={() => (error = null)} oncopy={secretCopy("password", say)} oncut={secretCopy("password", say)} />
    </label>
    <label>
      Again
      <SecretInput bind:value={confirm} {reveal} autocomplete="off" oninput={() => (error = null)} oncopy={secretCopy("password", say)} oncut={secretCopy("password", say)} />
    </label>
    {#if error}
      <p class="error" role="alert">{error}</p>
    {/if}
    <p class="dim">The vault is saved under the new password straight away. Nothing can recover it if you forget it, and backups made under the old one are deleted.</p>
    <div class="row">
      <button type="button" onclick={() => done(null)}>Cancel</button>
      <button class="primary" type="submit" disabled={busy || !password || !confirm}>{busy ? "Changing…" : "Change password"}</button>
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
    width: min(440px, calc(100vw - 40px));
    display: grid;
    gap: 12px;
  }

  h2 {
    margin: 0 0 4px;
    font-family: var(--action);
    font-size: 18px;
    font-weight: 600;
  }

  label {
    display: grid;
    gap: 4px;
    color: var(--dim);
    font-size: 12.5px;
  }

  .split {
    display: flex;
    justify-content: space-between;
  }

  .small {
    padding: 1px 8px;
    font-size: 12px;
    color: var(--text);
  }

  p {
    margin: 0;
    font-size: 12.5px;
  }

  .error {
    color: var(--error);
  }

  .row {
    display: flex;
    justify-content: flex-end;
    gap: 8px;
    margin-top: 4px;
  }
</style>
