<script>
  import { onMount } from "svelte";
  import { call, on } from "./api.js";
  import Unlock from "./Unlock.svelte";
  import Browser from "./Browser.svelte";

  let status = $state(null);
  let note = $state(null);
  let asking = $state(false);
  // Counted down here from the last status, so the clock needs no call into Rust each second.
  let clearsAt = $state(0);
  let clearsFrom = $state(0);
  let now = $state(Date.now());
  const clearsIn = $derived(Math.max(0, Math.ceil((clearsAt - now) / 1000)));

  async function refresh() {
    status = await call("status");
    const at = status.clearsIn ? Date.now() + status.clearsIn * 1000 : 0;
    // A later deadline means a fresh copy, so the countdown starts over from full.
    if (at > clearsAt + 1500) clearsFrom = status.clearsIn;
    clearsAt = at;
  }

  function say(notes) {
    if (notes?.length) note = notes[notes.length - 1];
  }

  // Keys and clicks restart the idle clock, at most every two seconds. Focus does not.
  let lastTouch = 0;
  function activity() {
    const now = Date.now();
    if (now - lastTouch > 2000) {
      lastTouch = now;
      call("touch");
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

<svelte:window onkeydown={activity} onmousedown={activity} />

{#if status === null}
  <main class="loading dim">…</main>
{:else if status.open}
  <Browser {status} {say} {refresh} clears={{ left: clearsIn, total: clearsFrom }} />
{:else}
  <Unlock {status} {say} {refresh} />
{/if}

<footer class:level-warn={note?.level === "warn"} class:level-error={note?.level === "error"}>
  <span class="note">{note?.text ?? ""}</span>
  {#if clearsIn && !status?.open}
    <span class="dim">clipboard clears in {clearsIn}s</span>
  {/if}
  {#if status?.vaultName}
    <span class="dim">{status.vaultName}</span>
  {/if}
</footer>

{#if asking}
  <div class="scrim">
    <div class="ask">
      <p>Some changes could not be saved. Quit and lose them?</p>
      <div class="row">
        <button onclick={() => (asking = false)}>Stay</button>
        <button class="danger" onclick={() => call("quit")}>Quit</button>
      </div>
    </div>
  </div>
{/if}

<style>
  .scrim {
    position: fixed;
    inset: 0;
    background: rgb(0 0 0 / 0.45);
    display: grid;
    place-items: center;
  }

  .ask {
    background: var(--panel);
    border-left: 3px solid var(--accent);
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

  .note {
    flex: 1;
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
  }
</style>
