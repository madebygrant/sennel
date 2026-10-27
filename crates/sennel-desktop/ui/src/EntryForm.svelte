<script>
  import { onMount, untrack } from "svelte";
  import { call, secretCopy } from "./api.js";

  // `form.id` edits that entry; otherwise a new one goes in `form.group`.
  let { form, say, close } = $props();

  // The boxes are seeded once and then belong to the user.
  const d = untrack(() => form.detail ?? {});
  let title = $state(d.title ?? "");
  let username = $state(d.username ?? "");
  let url = $state(d.url ?? "");
  let notes = $state(d.notes ?? "");
  let tags = $state(d.tags ?? "");
  let expires = $state(d.expires ?? "");
  // On an edit an untouched password or seed box keeps what is stored, so neither is prefilled.
  let password = $state("");
  let passwordTouched = $state(untrack(() => !form.id));
  let otp = $state("");
  let otpTouched = $state(false);
  let reveal = $state(false);
  let busy = $state(false);
  let titleBox;

  onMount(() => titleBox?.focus());

  async function generate() {
    try {
      password = await call("generate");
      passwordTouched = true;
      reveal = true;
    } catch (why) {
      say([{ level: "error", text: String(why) }]);
    }
  }

  async function submit(event) {
    event.preventDefault();
    busy = true;
    try {
      const reply = await call("save_entry", {
        id: form.id ?? null,
        group: form.group ?? null,
        form: {
          title,
          username,
          url,
          notes,
          tags,
          expires,
          password: passwordTouched ? password : null,
          otp: otpTouched ? otp : null,
        },
      });
      say(reply.notes);
      if (reply.ok) {
        password = "";
        otp = "";
        close(reply);
      }
    } catch (why) {
      say([{ level: "error", text: String(why) }]);
    } finally {
      busy = false;
    }
  }

  function cancel() {
    password = "";
    otp = "";
    close(null);
  }
</script>

<svelte:window onkeydown={(e) => e.key === "Escape" && cancel()} />

<div class="scrim">
  <form onsubmit={submit}>
    <h2>{form.id ? "Edit entry" : "New entry"}</h2>
    <label>Title <input bind:this={titleBox} bind:value={title} /></label>
    <label>Username <input bind:value={username} spellcheck="false" /></label>
    <label>
      <span class="split">
        Password
        <span>
          <button type="button" class="link" onclick={() => (reveal = !reveal)}>{reveal ? "hide" : "show"}</button>
          <button type="button" class="link" onclick={generate}>generate</button>
          <button type="button" class="link" onclick={async () => say([await call("copy_text", { label: "password", text: password })])}>copy</button>
        </span>
      </span>
      <input
        class="mono"
        type={reveal ? "text" : "password"}
        bind:value={password}
        oninput={() => (passwordTouched = true)}
        oncopy={secretCopy("password", say)}
        oncut={secretCopy("password", say)}
        placeholder={form.id && !passwordTouched ? "unchanged" : ""}
        autocomplete="off"
      />
    </label>
    <label>URL <input bind:value={url} spellcheck="false" /></label>
    <div class="pair">
      <label>Tags <input bind:value={tags} placeholder="work, banking" /></label>
      <label>Expires <input bind:value={expires} placeholder="YYYY-MM-DD" /></label>
    </div>
    <label>
      One-time code seed
      <input
        class="mono"
        type="password"
        bind:value={otp}
        oninput={() => (otpTouched = true)}
        oncopy={secretCopy("the seed", say)}
        oncut={secretCopy("the seed", say)}
        placeholder={form.detail?.hasOtp ? "unchanged · clear it to remove" : "base32 or otpauth:// URL"}
        autocomplete="off"
      />
    </label>
    <label>Notes <textarea rows="4" bind:value={notes}></textarea></label>
    <div class="row">
      {#if form.detail?.hasOtp && !otpTouched}
        <button type="button" class="danger" onclick={() => { otp = ""; otpTouched = true; }}>Remove code</button>
      {/if}
      <span class="gap"></span>
      <button type="button" onclick={cancel}>Cancel</button>
      <button class="primary" type="submit" disabled={busy}>{form.id ? "Save" : "Add"}</button>
    </div>
  </form>
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

  form {
    background: var(--panel);
    border-left: 3px solid var(--accent);
    border-radius: var(--radius);
    padding: 18px 20px;
    width: min(520px, 100%);
    max-height: 100%;
    overflow: auto;
    display: grid;
    gap: 11px;
  }

  h2 {
    margin: 0 0 4px;
    font-size: 17px;
  }

  label {
    display: grid;
    gap: 4px;
    color: var(--dim);
    font-size: 12.5px;
  }

  label :global(input),
  label textarea {
    color: var(--text);
    font-size: 14px;
  }

  .split {
    display: flex;
    justify-content: space-between;
  }

  .link {
    background: none;
    border: none;
    padding: 0 0 0 10px;
    color: var(--accent);
    font-size: 12.5px;
  }

  .pair {
    display: grid;
    grid-template-columns: 1fr 160px;
    gap: 10px;
  }

  .row {
    display: flex;
    gap: 8px;
    margin-top: 4px;
  }

  .gap {
    flex: 1;
  }

  textarea {
    resize: vertical;
    font-family: var(--mono);
  }
</style>
