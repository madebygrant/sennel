<script>
  import { KINDS, STYLES, resized, restyled } from "./generator.svelte.js";

  // `children` renders between the kinds and the size, once there is a result.
  let { made, pick, children } = $props();

  const resize = (by) => {
    const args = resized(by);
    if (args) pick(...args);
  };
  const restyle = (key) => {
    const args = restyled(key);
    if (args) pick(...args);
  };
</script>

<div class="kinds" role="radiogroup" aria-label="Kind">
  {#each KINDS as [kind, label]}
    <button type="button" role="radio" aria-checked={made?.kind === kind} class:on={made?.kind === kind} onclick={() => pick(kind)}>{label}</button>
  {/each}
</div>
{#if made}
  {@render children?.()}
  <div class="size">
    <button type="button" aria-label="Shorter" disabled={made.size <= made.min} onclick={() => resize(-1)}>−</button>
    <span>{made.amount}</span>
    <button type="button" aria-label="Longer" disabled={made.size >= made.max} onclick={() => resize(1)}>+</button>
    <span class="dim">~{Math.round(made.bits)} bits</span>
  </div>
  {#if made.kind === "complex"}
    <div class="styles" role="group" aria-label="Characters">
      {#each STYLES as [style, key, label, what]}
        <button type="button" aria-pressed={made.style[style]} class:on={made.style[style]} title={`${what}  ${key}`} onclick={() => restyle(style)}>{label}</button>
      {/each}
    </div>
  {/if}
{/if}

<style>
  .kinds {
    display: flex;
    gap: 4px;
  }

  .styles {
    display: flex;
    gap: 4px;
  }

  .styles button {
    padding: 2px 9px;
    font: 400 12px var(--mono);
    color: var(--dim);
  }

  .styles button.on {
    color: var(--text);
    box-shadow: inset 0 0 0 1px var(--accent);
  }

  .kinds button {
    padding: 3px 10px;
    font-size: 12.5px;
    color: var(--dim);
  }

  .kinds button.on {
    background: var(--accent);
    color: var(--accent-ink);
  }

  .size {
    display: flex;
    align-items: center;
    gap: 8px;
    font-size: 13px;
  }

  .size button {
    width: 26px;
    padding: 2px 0;
  }

  .size span:first-of-type {
    min-width: 76px;
    text-align: center;
  }

  .size .dim {
    margin-left: 4px;
  }
</style>
