<script>
  import Mark from "./Mark.svelte";

  // `left` and `total` in seconds. Purely a warning: the Rust timer does the locking.
  let { left, total } = $props();

  const span = $derived(Math.min(30, total * 0.4));
  // Held shut at zero: Rust checks once a second, and opening early would show the vault again.
  const closing = $derived(left <= span ? 1 - left / span : 0);
  let veil;

  // CSSOM, since the CSP refuses style attributes.
  $effect(() => {
    veil.style.setProperty("--veil-r", closing ? 120 * (1 - closing) : 140);
    veil.style.setProperty("--veil-mark", closing * 0.9);
  });
</script>

<div class="veil" class:on={closing > 0} bind:this={veil} aria-hidden="true">
  <span class="mark"><Mark width={64} height={74} closed={left <= 1} /></span>
</div>

<style>
  @property --veil-r {
    syntax: "<number>";
    inherits: false;
    initial-value: 140;
  }

  .veil {
    position: fixed;
    inset: 0;
    z-index: 50;
    pointer-events: none;
    display: grid;
    place-items: center;
    background: radial-gradient(
      farthest-corner at 50% 50%,
      transparent calc(var(--veil-r) * 1%),
      color-mix(in oklab, var(--bg) 94%, transparent) calc(var(--veil-r) * 1% + 28%)
    );
    transition: --veil-r 1s linear;
  }

  .veil:not(.on) {
    transition-duration: 300ms;
  }

  .mark {
    opacity: var(--veil-mark, 0);
    transition: opacity 1s linear;
  }

  @media (prefers-reduced-motion: reduce) {
    .veil,
    .mark {
      transition: none;
    }
  }
</style>
