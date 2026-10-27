<script module>
  export function kind(c) {
    if (/\d/.test(c)) return "digit";
    return /\p{L}/u.test(c) ? "" : "symbol";
  }
</script>

<script>
  // `value` is null while hidden, and `length` dots stand in, so revealing swaps each in place.
  let { value, length = 12, textId } = $props();

  // Each cell rolls through its own kind of character, so the row's makeup shows before it settles.
  const POOLS = { "": "abcdefghijkmnpqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ", digit: "0123456789", symbol: "!#$%&*+-=?@^_~" };
  const STEP = 30;
  const FLASH = 140;
  const still = matchMedia("(prefers-reduced-motion: reduce)").matches;
  const chars = $derived(value === null ? null : [...value]);

  // While settling, each cell shows a passing glyph until its turn, then flashes once as it lands.
  let glyphs = $state(null);
  let landing = $state(null);
  let row;

  // Cells narrow so most passwords keep to one line; CSSOM, since the CSP refuses style attributes.
  $effect(() => {
    const n = chars?.length ?? length;
    row.style.setProperty("--n", n);
    row.style.setProperty("--splits", Math.floor((n - 1) / 5));
  });

  $effect(() => {
    glyphs = null;
    if (chars === null || still) return;
    const n = chars.length;
    const start = performance.now();
    let frame;
    const step = (now) => {
      const t = now - start;
      glyphs = chars.map((c, i) => {
        if (t >= 180 + i * STEP) return null;
        const pool = POOLS[kind(c)];
        return pool[(Math.random() * pool.length) | 0];
      });
      landing = chars.map((_, i) => t >= 180 + i * STEP && t < 180 + i * STEP + FLASH);
      if (t < 180 + n * STEP + FLASH) frame = requestAnimationFrame(step);
      else glyphs = landing = null;
    };
    frame = requestAnimationFrame(step);
    return () => {
      cancelAnimationFrame(frame);
      landing = null;
    };
  });
</script>

<!-- Not selectable: a native copy would skip the clipboard clear, so Copy is the way out. -->
<div class="cells" bind:this={row} class:open={chars !== null} aria-hidden="true">
  {#each chars ?? Array(length).fill("•") as c, i}
    {#if i && i % 5 === 0}<span class="split"></span>{/if}
    <span class="cell">
      <b class={chars ? kind(c) : ""} class:scrambled={glyphs?.[i]} class:landing={landing?.[i]}>{glyphs?.[i] ?? c}</b>
      <small>{chars ? i + 1 : ""}</small>
    </span>
  {/each}
</div>
<span class="sr" id={textId}>{chars === null ? "Password hidden" : `Password: ${value}`}</span>

<style>
  .cells {
    container-type: inline-size;
    --cell: clamp(14px, (100cqw - var(--splits) * 10px + 2px) / var(--n) - 2px, 23px);
    display: flex;
    flex-wrap: wrap;
    gap: 6px 2px;
    -webkit-user-select: none;
    user-select: none;
  }

  .split {
    width: 8px;
  }

  .cell {
    display: grid;
    gap: 4px;
    justify-items: center;
  }

  b {
    width: var(--cell);
    height: 34px;
    display: grid;
    place-items: center;
    font: 400 max(12px, var(--cell) * 0.74) var(--mono);
    background: var(--bg);
    border-radius: 3px;
    color: var(--faint);
  }

  small {
    height: 12px;
    font: 10px var(--mono);
    color: var(--faint);
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

  .open b.scrambled {
    color: var(--dim);
  }

  b {
    transition: background 260ms ease-out, color 260ms ease-out;
  }

  .open b.landing {
    background: var(--accent);
    color: var(--accent-ink);
    transition: none;
  }

  @media (prefers-reduced-motion: reduce) {
    b {
      transition: none;
    }
  }
</style>
