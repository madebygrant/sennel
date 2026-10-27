<script>
  // The code never reaches the window, only its timing; codes roll over on multiples of the period.
  let { period = 30, digits = 6 } = $props();

  const LATE = 5;
  const still = matchMedia("(prefers-reduced-motion: reduce)").matches;
  let row;
  let left = $state(0);
  let fresh = $state(false);

  $effect(() => {
    let frame;
    let last = Infinity;
    let freshTimer;
    const step = () => {
      const into = (Date.now() / 1000) % period;
      const remaining = period - into;
      left = Math.ceil(remaining);
      // A jump up means a new code started.
      if (remaining > last + 1 && !still) {
        fresh = true;
        clearTimeout(freshTimer);
        freshTimer = setTimeout(() => (fresh = false), 300);
      }
      last = remaining;
      [...row.children].forEach((cell, i) => {
        cell.style.setProperty("--fill", Math.min(1, Math.max(0, (remaining / period) * digits - i)));
      });
      frame = still ? setTimeout(step, 1000) : requestAnimationFrame(step);
    };
    step();
    return () => {
      cancelAnimationFrame(frame);
      clearTimeout(frame);
      clearTimeout(freshTimer);
    };
  });
</script>

<span class="otp" class:late={left <= LATE} class:fresh>
  <span class="row" bind:this={row} aria-hidden="true">
    {#each { length: digits } as _, i}
      <b class:gap={digits % 2 === 0 && i === digits / 2}><i></i>•</b>
    {/each}
  </span>
  <span class="left">next in {left}s</span>
</span>

<style>
  .otp {
    display: inline-flex;
    align-items: center;
    gap: 12px;
  }

  .row {
    display: inline-flex;
    gap: 2px;
  }

  b {
    position: relative;
    width: 17px;
    height: 24px;
    display: grid;
    place-items: center;
    overflow: hidden;
    border-radius: 3px;
    background: var(--bg);
    color: var(--faint);
    font: 400 13px var(--mono);
  }

  b.gap {
    margin-left: 6px;
  }

  i {
    position: absolute;
    inset: 0;
    background: color-mix(in oklab, var(--accent) 30%, transparent);
    transform-origin: bottom;
    transform: scaleY(var(--fill, 0));
  }

  .late i {
    background: color-mix(in oklab, var(--warn) 34%, transparent);
  }

  .fresh b {
    animation: fresh 300ms ease-out;
  }

  @keyframes fresh {
    from {
      background: var(--accent);
      color: var(--accent-ink);
    }
  }

  .left {
    font: 12px var(--mono);
    color: var(--faint);
    font-variant-numeric: tabular-nums;
  }

  .late .left {
    color: var(--warn);
  }
</style>
