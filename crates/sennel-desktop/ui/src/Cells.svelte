<script module>
  export function kind(c) {
    if (/\d/.test(c)) return "digit";
    return /\p{L}/u.test(c) ? "" : "symbol";
  }
</script>

<script>
  // `value` is null while hidden, and a fixed row of dots stands in so the length stays private.
  let { value } = $props();

  const GLYPHS = "ｱｲｳｴｵｶｷｸｹｺｻｼｽｾｿﾀﾁﾂﾃﾄ0123456789ABCDEF<>*=+";
  const still = matchMedia("(prefers-reduced-motion: reduce)").matches;
  const chars = $derived(value === null ? null : [...value]);

  // While decoding, each cell shows a passing glyph until its turn comes.
  let glyphs = $state(null);
  let row;
  let before = 0;

  // A password too long for one line still wraps, so the box eases open instead of jumping.
  $effect.pre(() => {
    chars;
    before = row?.offsetHeight ?? 0;
  });
  $effect(() => {
    // Cells narrow so most passwords keep to one line; CSSOM, since the CSP refuses style attributes.
    // Set before measuring, or `after` is taken at the old widths.
    const n = chars?.length ?? 12;
    row.style.setProperty("--n", n);
    row.style.setProperty("--splits", Math.floor((n - 1) / 5));
    const after = row.offsetHeight;
    if (still || !before || before === after) return;
    row.animate([{ height: `${before}px`, overflow: "clip" }, { height: `${after}px`, overflow: "clip" }], {
      duration: 300,
      easing: "cubic-bezier(0.2, 0.8, 0.2, 1)",
    });
  });

  $effect(() => {
    glyphs = null;
    if (chars === null || still) return;
    const n = chars.length;
    const start = performance.now();
    let frame;
    const step = (now) => {
      const next = Array.from({ length: n }, (_, i) => (now - start < 180 + i * 45 ? GLYPHS[(Math.random() * GLYPHS.length) | 0] : null));
      glyphs = next.some(Boolean) ? next : null;
      if (glyphs) frame = requestAnimationFrame(step);
    };
    frame = requestAnimationFrame(step);
    return () => cancelAnimationFrame(frame);
  });
</script>

<!-- Not selectable: a native copy would skip the clipboard clear, so Copy is the way out. -->
<div class="cells" bind:this={row} class:open={chars !== null} aria-hidden="true">
  {#each chars ?? Array(12).fill("•") as c, i}
    {#if i && i % 5 === 0}<span class="split"></span>{/if}
    <span class="cell">
      <b class={chars ? kind(c) : ""} class:scrambled={glyphs?.[i]}>{glyphs?.[i] ?? c}</b>
      <small>{chars ? i + 1 : ""}</small>
    </span>
  {/each}
</div>
<span class="sr">{chars === null ? "Password hidden" : `Password: ${value}`}</span>

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
    color: var(--accent);
  }

  .open b.symbol {
    color: var(--data);
  }

  .open b.scrambled {
    color: var(--dim);
  }
</style>
