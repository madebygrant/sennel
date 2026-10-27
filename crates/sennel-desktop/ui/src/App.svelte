<script>
  import { onMount } from "svelte";
  import { call, on } from "./api.js";
  import Unlock from "./Unlock.svelte";
  import Browser from "./Browser.svelte";
  import LockVeil from "./LockVeil.svelte";
  import Modal from "./Modal.svelte";

  let status = $state(null);
  let note = $state(null);
  let asking = $state(false);
  // Counted down here from the last status, so the clock needs no call into Rust each second.
  let clearsAt = $state(0);
  let clearsFrom = $state(0);
  // Counts fresh copies, so a field knows whether the clipboard still holds its copy.
  let copies = $state(0);
  let now = $state(Date.now());
  const clearsIn = $derived(Math.max(0, Math.ceil((clearsAt - now) / 1000)));
  let hints = $state([]);
  let lockAt = $state(0);
  const lockAfter = $derived(status?.lockAfter ?? 0);
  const locksIn = $derived(Math.max(0, Math.ceil((lockAt - now) / 1000)));

  async function refresh() {
    status = await call("status");
    const at = status.clearsIn ? Date.now() + status.clearsIn * 1000 : 0;
    // A later deadline means a fresh copy, so the countdown starts over from full.
    if (at > clearsAt + 1500) {
      clearsFrom = status.clearsIn;
      copies++;
    }
    clearsAt = at;
    lockAt = status.locksIn == null ? 0 : Date.now() + status.locksIn * 1000;
  }

  // Notes clear themselves so an old one never reads as news; problems stay up longer.
  let noteTimer;
  function say(notes) {
    if (!notes?.length) return;
    note = notes[notes.length - 1];
    clearTimeout(noteTimer);
    noteTimer = setTimeout(() => (note = null), note.level === "info" ? 4000 : 10000);
  }

  // Keys, clicks and pointer moves restart the idle clock, at most every two seconds. Focus does not.
  // macOS delivers scrolls and hovers to background windows, so those count only while focused.
  let lastTouch = 0;
  function activity(event) {
    if ((event.type === "pointermove" || event.type === "wheel") && !document.hasFocus()) return;
    const now = Date.now();
    if (now - lastTouch > 2000) {
      lastTouch = now;
      call("touch");
      if (lockAt) lockAt = now + lockAfter * 1000;
    }
  }

  onMount(() => {
    refresh();
    const stops = [
      on("locked", (notes) => {
        say(notes);
        refresh();
      }),
      on("prompt", (n) => say([n])),
      on("quit-asked", () => (asking = true)),
    ];
    const tick = setInterval(() => (now = Date.now()), 1000);
    return () => {
      stops.forEach((s) => s.then((f) => f()));
      clearInterval(tick);
    };
  });
</script>

<svelte:window onkeydown={activity} onmousedown={activity} onpointermove={activity} onwheel={activity} />

{#if status === null}
  <main class="loading dim">…</main>
{:else if status.open}
  <Browser {status} {say} {refresh} bind:hints clears={{ left: clearsIn, total: clearsFrom, copies }} />
  {#if lockAt && lockAfter}<LockVeil left={locksIn} total={lockAfter} />{/if}
{:else}
  <Unlock {status} {say} {refresh} />
{/if}

<footer class:level-warn={note?.level === "warn"} class:level-error={note?.level === "error"}>
  <span class="note" role="status">{note?.text ?? ""}</span>
  {#if clearsIn && !status?.open}
    <span class="dim">clipboard clears in {clearsIn}s</span>
  {/if}
  {#if status?.open}
    <span class="hints">
      {#each hints as [k, label]}<span><kbd>{k}</kbd>{label}</span>{/each}
    </span>
  {/if}
  {#if status?.open && lockAt && locksIn <= Math.min(30, lockAfter * 0.4)}
    <span class="level-warn">locks in {locksIn}s</span>
  {/if}
  {#if status?.vaultName}
    <span class="dim">{status.vaultName}</span>
  {/if}
</footer>

{#if asking}
  <Modal label="Quit" onclose={() => (asking = false)}>
    <div class="ask">
      <p>Some changes could not be saved. Quit and lose them?</p>
      <div class="row">
        <!-- svelte-ignore a11y_autofocus -->
        <button onclick={() => (asking = false)} autofocus>Stay</button>
        <button class="danger" onclick={() => call("quit")}>Quit</button>
      </div>
    </div>
  </Modal>
{/if}

<style>
  .ask {
    background: var(--panel);
    border: 1px solid var(--line);
    box-shadow: 0 24px 60px -24px rgb(0 0 0 / 0.6);
    border-radius: var(--radius);
    padding: 18px;
    width: min(380px, 92vw);
  }

  .ask p {
    margin: 0 0 14px;
  }

  .row {
    display: flex;
    justify-content: flex-end;
    gap: 8px;
  }

  .loading {
    display: grid;
    place-items: center;
    height: calc(100% - 30px);
  }

  footer {
    position: fixed;
    inset: auto 0 0 0;
    height: 30px;
    display: flex;
    gap: 18px;
    align-items: center;
    padding: 0 14px;
    border-top: 1px solid var(--line);
    background: var(--panel);
    font-size: 12.5px;
  }

  .hints {
    display: flex;
    gap: 14px;
    color: var(--faint);
    white-space: nowrap;
    overflow: hidden;
  }

  .hints span {
    display: flex;
    gap: 5px;
  }

  .hints kbd {
    font: 12px var(--mono);
    color: var(--accent-text);
  }

  .note {
    flex: 1;
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
  }
</style>
