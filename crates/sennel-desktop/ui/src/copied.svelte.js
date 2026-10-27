// The one copy treatment: the copied thing says "Copied" for a moment and glitches once.
export function copyFeedback() {
  let copied = $state(null);
  let glitch = $state(null);
  let timer;
  const still = matchMedia("(prefers-reduced-motion: reduce)").matches;
  return {
    get copied() {
      return copied;
    },
    get glitch() {
      return glitch;
    },
    mark(key) {
      clearTimeout(timer);
      copied = key;
      timer = setTimeout(() => (copied = null), 1400);
      if (still) return;
      // Cleared first so a second copy of the same thing replays the animation.
      glitch = null;
      requestAnimationFrame(() => (glitch = key));
    },
  };
}
