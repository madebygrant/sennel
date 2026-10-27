<script>
  import { onMount } from "svelte";

  const R = 13;
  const LIFE = 4500;
  let canvas;

  onMount(() => {
    const ctx = canvas.getContext("2d");
    const grid = document.createElement("canvas");
    const still = matchMedia("(prefers-reduced-motion: reduce)").matches;
    let cells = [], low = [], lit = [], next = 0, last = 0, frame = 0, w = 0, h = 0;

    const tone = (name) => getComputedStyle(canvas).getPropertyValue(name).trim();
    const hex = (c, x, y) => {
      c.beginPath();
      for (let k = 0; k < 6; k++) {
        const a = (Math.PI / 3) * k + Math.PI / 6;
        c.lineTo(x + R * Math.cos(a), y + R * Math.sin(a));
      }
      c.closePath();
    };

    // The faint grid is drawn once per size; frames only paint the lit cells over it.
    function layout() {
      const dpr = devicePixelRatio || 1;
      w = canvas.clientWidth;
      h = canvas.clientHeight;
      for (const c of [canvas, grid]) {
        c.width = w * dpr;
        c.height = h * dpr;
      }
      const g = grid.getContext("2d");
      g.setTransform(dpr, 0, 0, dpr, 0, 0);
      ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
      g.globalAlpha = 0.07;
      g.strokeStyle = tone("--accent");
      cells = [];
      const step = Math.sqrt(3) * R;
      for (let row = 0; row * R * 1.5 < h + R; row++) {
        for (let x = row % 2 ? step / 2 : 0; x < w + step; x += step) {
          cells.push([x, row * R * 1.5]);
          hex(g, x, row * R * 1.5);
          g.stroke();
        }
      }
      low = cells.flatMap((c, i) => (c[1] > h / 2 ? [i] : []));
      lit = [];
      paint(performance.now());
    }

    function paint(t) {
      ctx.clearRect(0, 0, w, h);
      ctx.drawImage(grid, 0, 0, w, h);
      for (const l of lit) {
        const b = Math.sin((Math.PI * (t - l.t0)) / LIFE);
        hex(ctx, ...cells[l.i]);
        ctx.globalAlpha = 0.16 * b;
        ctx.fillStyle = l.color;
        ctx.fill();
        ctx.globalAlpha = 0.6 * b;
        ctx.strokeStyle = l.color;
        ctx.stroke();
      }
      ctx.globalAlpha = 1;
    }

    function tick(t) {
      frame = requestAnimationFrame(tick);
      if (document.hidden || t - last < 50) return;
      last = t;
      if (t > next && low.length) {
        const color = tone(Math.random() < 0.25 ? "--data" : "--accent");
        lit.push({ i: low[(Math.random() * low.length) | 0], t0: t, color });
        next = t + 1400 + Math.random() * 1200;
      }
      lit = lit.filter((l) => t - l.t0 < LIFE);
      paint(t);
    }

    const sizes = new ResizeObserver(layout);
    sizes.observe(canvas);
    const scheme = matchMedia("(prefers-color-scheme: light)");
    scheme.addEventListener("change", layout);
    if (!still) frame = requestAnimationFrame(tick);
    return () => {
      cancelAnimationFrame(frame);
      sizes.disconnect();
      scheme.removeEventListener("change", layout);
    };
  });
</script>

<canvas bind:this={canvas} aria-hidden="true"></canvas>

<style>
  canvas {
    position: absolute;
    inset: 0;
    width: 100%;
    height: 100%;
    pointer-events: none;
    -webkit-mask: linear-gradient(to bottom, transparent 40%, #000 75%);
    mask: linear-gradient(to bottom, transparent 40%, #000 75%);
  }
</style>
