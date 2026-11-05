// Arrow keys move through a radio group and pick as they go, as native radio buttons do. The
// group is one tab stop: give the checked button tabindex 0 and the rest -1.
const STEPS = { ArrowRight: 1, ArrowDown: 1, ArrowLeft: -1, ArrowUp: -1 };

export function radioKeys(event, values, current, pick) {
  const step = STEPS[event.key];
  if (!step || event.altKey || event.metaKey || event.ctrlKey) return;
  event.preventDefault();
  const at = values.indexOf(current);
  const next = (Math.max(at, 0) + (at < 0 ? 0 : step) + values.length) % values.length;
  pick(values[next]);
  event.currentTarget.querySelectorAll('[role="radio"]')[next]?.focus();
}
