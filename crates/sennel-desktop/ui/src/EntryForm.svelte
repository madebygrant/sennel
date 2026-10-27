<script>
  import { onMount, untrack } from "svelte";
  import { getCurrentWebview } from "@tauri-apps/api/webview";
  import { call, secretCopy } from "./api.js";
  import { copyFeedback } from "./copied.svelte.js";
  import { generate as makePassword } from "./generator.svelte.js";
  import Modal from "./Modal.svelte";
  import OtpCells from "./OtpCells.svelte";

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
  // The timing and account of a seed read from a QR, so it is clear which code was read.
  let scanned = $state(null);
  let dropping = $state(false);
  let reveal = $state(false);
  let busy = $state(false);
  let titleBox;

  onMount(() => {
    titleBox?.focus();
    // Tauri hands over a dropped file's path; the page itself never sees the file.
    const stop = getCurrentWebview().onDragDropEvent(({ payload }) => {
      dropping = payload.type === "enter" || payload.type === "over";
      if (payload.type === "drop" && payload.paths?.length) scan("scan_file", { path: payload.paths[0] });
    });
    return () => stop.then((f) => f());
  });

  async function scan(cmd, args = {}) {
    try {
      const found = await call(cmd, { ...args, title, username });
      otp = found.url;
      otpTouched = true;
      scanned = found.otp && { ...found.otp, label: found.label };
      say([{ level: "info", text: cmd === "scan_clipboard" ? "read the QR code · clipboard cleared" : "read the QR code" }]);
    } catch (why) {
      say([{ level: "warn", text: String(why) }]);
    }
  }

  // ⌘V of a screenshot into the seed box reads it like Paste QR; pasted text goes in as usual.
  function pasteSeed(event) {
    const types = [...(event.clipboardData?.types ?? [])];
    // Chrome reports a pasted screenshot as Files, WebKit may report its image type instead.
    if (types.includes("text/plain") || !types.some((t) => t === "Files" || t.startsWith("image/"))) return;
    event.preventDefault();
    scan("scan_clipboard");
  }

  async function generate() {
    try {
      const made = await makePassword();
      if (!made) return;
      password = made.value;
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

  const fb = copyFeedback();
  const dirty = $derived(
    title !== (d.title ?? "") ||
      username !== (d.username ?? "") ||
      url !== (d.url ?? "") ||
      notes !== (d.notes ?? "") ||
      tags !== (d.tags ?? "") ||
      expires !== (d.expires ?? "") ||
      password !== "" ||
      otpTouched,
  );
  // Set while asking whether to throw away what was typed.
  let confirming = $state(false);
  let keepButton = $state();
  $effect(() => keepButton?.focus());

  async function copyPassword() {
    const note = await call("copy_text", { label: "password", text: password });
    say([note]);
    if (note.level !== "error") fb.mark("password");
  }

  function cancel() {
    if (dirty && !confirming) {
      confirming = true;
      return;
    }
    password = "";
    otp = "";
    close(null);
  }
</script>

<Modal label={form.id ? "Edit entry" : "New entry"} onclose={() => (confirming ? (confirming = false) : cancel())}>
  <form onsubmit={submit}>
    <h2>{form.id ? "Edit entry" : "New entry"}</h2>
    <label>Title <input bind:this={titleBox} bind:value={title} /></label>
    <label>Username <input bind:value={username} spellcheck="false" /></label>
    <label>
      <span class="split">
        Password
        <span>
          <button type="button" class="small" onclick={() => (reveal = !reveal)}>{reveal ? "Hide" : "Show"}</button>
          <button type="button" class="small" onclick={generate}>Generate</button>
          <button type="button" class="small" onclick={copyPassword}>{fb.copied === "password" ? "Copied" : "Copy"}</button>
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
    <label class:dropping>
      <span class="split">
        One-time code seed
        <span><button type="button" class="small" onclick={() => scan("scan_clipboard")} title="Reads a screenshot of the QR code from the clipboard">Paste QR</button></span>
      </span>
      <input
        class="mono"
        type="password"
        bind:value={otp}
        oninput={() => {
          otpTouched = true;
          scanned = null;
        }}
        onpaste={pasteSeed}
        oncopy={secretCopy("the seed", say)}
        oncut={secretCopy("the seed", say)}
        placeholder={dropping ? "drop the QR image to read it" : form.detail?.hasOtp ? "unchanged · clear it to remove" : "base32, otpauth:// URL, or a QR screenshot"}
        autocomplete="off"
      />
      {#if scanned}
        <span class="scanned"><OtpCells period={scanned.period} digits={scanned.digits} />{scanned.label ? `for ${scanned.label}` : "read from the QR"}</span>
      {/if}
    </label>
    <label>Notes <textarea rows="4" bind:value={notes}></textarea></label>
    {#if confirming}
      <div class="row confirm" role="alert">
        <span>Discard your changes?</span>
        <span class="gap"></span>
        <button type="button" bind:this={keepButton} onclick={() => (confirming = false)}>Keep editing</button>
        <button type="button" class="danger" onclick={cancel}>Discard</button>
      </div>
    {:else}
      <div class="row">
        {#if form.detail?.hasOtp && !otpTouched}
          <button type="button" class="danger" onclick={() => { otp = ""; otpTouched = true; }}>Remove code</button>
        {/if}
        <span class="gap"></span>
        <button type="button" onclick={cancel}>Cancel</button>
        <button class="primary" type="submit" disabled={busy}>{form.id ? "Save" : "Add"}</button>
      </div>
    {/if}
  </form>
</Modal>

<style>
  form {
    background: var(--panel);
    border: 1px solid var(--line);
    border-radius: var(--radius);
    box-shadow: 0 24px 60px -24px rgb(0 0 0 / 0.6);
    padding: 18px 20px;
    width: min(520px, calc(100vw - 40px));
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

  .small {
    margin-left: 6px;
    padding: 1px 8px;
    font-size: 12px;
    color: var(--text);
  }

  label.dropping :global(input) {
    border-color: var(--accent-text);
    outline: 1px dashed var(--accent-text);
  }

  .scanned {
    display: flex;
    align-items: center;
    gap: 10px;
    color: var(--faint);
    font-size: 12px;
  }

  .confirm {
    align-items: center;
    color: var(--warn);
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
