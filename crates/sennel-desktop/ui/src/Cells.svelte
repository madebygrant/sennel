<script module>
  export function kind(c) {
    if (/\d/.test(c)) return "digit";
    return /\p{L}/u.test(c) ? "" : "symbol";
  }
</script>

<script>
  import { groupCells } from "./cells.js";

  // `value` is null while hidden, and `length` dots stand in, so revealing swaps each in place.
  // `words` reads the value as a passphrase: a group per word, with the dashes drawn between them. It
  // applies once revealed, so the hidden row doesn't give the passphrase away, and the row reflows then.
  let { value, length = 12, textId, words = false } = $props();

  // Each cell rolls through its own kind of character, so the row's makeup shows before it settles.
  const POOLS = { "": "abcdefghijkmnpqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ", digit: "0123456789", symbol: "!#$%&*+-=?@^_~" };
  const STEP = 30;
  const FLASH = 140;
  const still = matchMedia("(prefers-reduced-motion: reduce)").matches;
  const chars = $derived(value === null ? null : [...value]);
  const shown = $derived(chars ?? Array(length).fill("•"));
  // Indexes into `shown`, so settling still runs left to right across the groups.
  const groups = $derived(groupCells(shown, words && chars !== null));

  // While settling, each cell shows a passing glyph until its turn, then flashes once as it lands.
  let glyphs = $state(null);
  let landing = $state(null);
  let row;

  // Cells narrow so most passwords keep to one line; CSSOM, since the CSP refuses style attributes.
  $effect(() => {
    row.style.setProperty("--n", groups.reduce((n, g) => n + g.length, 0));
    row.style.setProperty("--splits", groups.length - 1);
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
  {#each groups as group, g}
    <span class="group">
      {#each group as i}
        <span class="cell">
          <b class={chars ? kind(shown[i]) : ""} class:scrambled={glyphs?.[i]} class:landing={landing?.[i]}>{glyphs?.[i] ?? shown[i]}</b>
          {#if !(words && chars)}<small>{chars ? i + 1 : ""}</small>{/if}
        </span>
      {/each}
      <!-- Only passphrases have more than one group. The dash rides at the end of its word, so a wrapped line never starts with one. -->
      {#if g < groups.length - 1}<span class="split">-</span>{/if}
    </span>
  {/each}
</div>
<span class="sr" id={textId}>{chars === null ? "Password hidden" : `Password: ${value}`}</span>

<style>
  .cells {
    container-type: inline-size;
    --cell: clamp(14px, (100cqw - var(--splits) * 18px + 2px) / var(--n) - 2px, 23px);
    display: flex;
    flex-wrap: wrap;
    gap: 6px 2px;
    -webkit-user-select: none;
    user-select: none;
  }

  .group {
    display: flex;
    flex-wrap: wrap;
    gap: 6px 2px;
  }

  /* A passphrase is typed as words, so the dash sits between them as a plain mark, not a cell. */
  .split {
    width: 16px;
    height: 34px;
    display: grid;
    place-items: center;
    font: 500 16px var(--mono);
    color: var(--dim);
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
