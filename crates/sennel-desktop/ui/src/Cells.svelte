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
<div class="cells" class:open={chars !== null} aria-hidden="true">
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
    width: 23px;
    height: 34px;
    display: grid;
    place-items: center;
    font: 400 17px var(--mono);
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
