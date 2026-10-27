// The one copy treatment: the copied thing says "Copied" for a moment while a band of light crosses it.
// The one source for the sweep length: app.css reads it as --sweep.
const DURATION = 500;
const timers = new WeakMap();

export function copyFeedback() {
  let copied = $state(null);
  let timer;
  const spots = new Map();
  const still = matchMedia("(prefers-reduced-motion: reduce)").matches;

  function sweep(el) {
    // The band is one box wide and runs from -W to +W, so it is centred over x at (x + W/2) / 2W of the run.
    const box = el.getBoundingClientRect();
    for (const t of el.querySelectorAll(".cells b, .lit")) {
      const r = t.getBoundingClientRect();
      const at = (r.left - box.left + r.width / 2 + box.width / 2) / (2 * box.width);
      t.style.setProperty("--lit-at", `${Math.round(at * DURATION)}ms`);
    }
    el.style.setProperty("--sweep", `${DURATION}ms`);
    el.classList.remove("sweep");
    void el.offsetWidth;
    el.classList.add("sweep");
    clearTimeout(timers.get(el));
    timers.set(el, setTimeout(() => el.classList.remove("sweep"), DURATION * 1.6));
  }

  return {
    get copied() {
      return copied;
    },
    mark(key) {
      clearTimeout(timer);
      copied = key;
      timer = setTimeout(() => (copied = null), 1400);
      const el = spots.get(key);
      if (el && !still) sweep(el);
    },
    // `use:fb.spot={key}` names the element that lights up when `key` is copied.
    spot(node, key) {
      spots.set(key, node);
      return {
        update(next) {
          if (spots.get(key) === node) spots.delete(key);
          spots.set((key = next), node);
        },
        destroy() {
          if (spots.get(key) === node) spots.delete(key);
        },
      };
    },
  };
}
