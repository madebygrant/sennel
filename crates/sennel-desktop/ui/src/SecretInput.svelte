<script>
  import { kind } from "./Cells.svelte";

  // The real input sits invisible on top, so focus, paste and secure entry stay native.
  let { value = $bindable(""), box = $bindable(), reveal = false, hint = "", oninput, ...rest } = $props();

  const chars = $derived([...value]);
  let at = $state(0);
  let to = $state(0);
  let row;

  // In chars, not UTF-16 units, so an emoji is one cell like everywhere else.
  const count = (end) => [...value.slice(0, end ?? value.length)].length;
  function place() {
    at = count(box?.selectionStart);
    to = count(box?.selectionEnd);
  }

  $effect(() => {
    row.style.setProperty("--n", Math.max(chars.length, 1));
  });
</script>

<span class="secret" class:open={reveal}>
  <input
    bind:this={box}
    bind:value
    type={reveal ? "text" : "password"}
    spellcheck="false"
    oninput={(e) => {
      place();
      oninput?.(e);
    }}
    onkeyup={place}
    onclick={place}
    onselect={place}
    onmouseup={place}
    onfocus={place}
    placeholder={hint}
    {...rest}
  />
  <span class="row" bind:this={row} aria-hidden="true">
    {#each chars as c, i}
      {#if i === at && at === to}<span class="caret"></span>{/if}
      <b class={reveal ? kind(c) : ""} class:selected={i >= at && i < to}>{reveal ? c : "•"}</b>
    {/each}
    {#if at >= chars.length && at === to}<span class="caret"></span>{/if}
    {#if !chars.length && hint}<span class="hint">{hint}</span>{/if}
  </span>
</span>

<style>
  .secret {
    position: relative;
    display: block;
    border: 1px solid var(--line);
    border-radius: var(--radius);
    background: var(--bg);
    padding: 5px 6px;
    cursor: text;
  }

  .secret:focus-within {
    border-color: var(--accent-text);
    outline: 1px solid var(--accent-text);
    outline-offset: -1px;
  }

  input,
  input:focus {
    position: absolute;
    inset: 0;
    opacity: 0;
    border: 0;
    outline: none;
    padding: 0;
    cursor: text;
  }

  .row {
    container-type: inline-size;
    --cell: clamp(13px, (100cqw - 4px) / var(--n) - 2px, 21px);
    display: flex;
    flex-wrap: wrap;
    align-items: center;
    gap: 4px 2px;
    min-height: 28px;
  }

  b {
    flex: none;
    width: var(--cell);
    height: 28px;
    display: grid;
    place-items: center;
    border-radius: 3px;
    background: var(--raised);
    color: var(--dim);
    font: 400 max(11px, var(--cell) * 0.7) var(--mono);
    animation: land 260ms ease-out;
  }

  .open b {
    color: var(--text);
  }

  .open b.digit {
    color: var(--accent-text);
  }

  .open b.symbol {
    color: var(--data);
  }

  .secret:focus-within b.selected {
    background: color-mix(in oklab, var(--accent) 40%, var(--raised));
    color: var(--text);
  }

  .caret {
    flex: none;
    width: 2px;
    height: 22px;
    margin: 0 -1px;
    background: var(--accent-text);
    animation: blink 1s steps(1) infinite;
  }

  .secret:not(:focus-within) .caret {
    visibility: hidden;
  }

  .hint {
    padding-left: 6px;
    color: var(--dim);
    font-size: 13px;
  }

  @keyframes land {
    from {
      background: var(--accent);
      color: var(--accent-ink);
    }
  }

  @keyframes blink {
    50% {
      opacity: 0;
    }
  }

  @media (prefers-reduced-motion: reduce) {
    b,
    .caret {
      animation: none;
    }
  }
</style>
