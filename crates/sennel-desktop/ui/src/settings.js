// Seconds; 0 is never. The config file can hold any number, so `choices` keeps an odd one listed.
export const LOCK_PRESETS = [60, 120, 300, 600, 900, 1800, 3600, 0];
export const CLIPBOARD_PRESETS = [10, 15, 20, 30, 45, 60, 90, 120, 0];

export const ORDERS = [
  ["stored", "File order"],
  ["name", "Name"],
  ["recent", "Newest"],
  ["updated", "Recently changed"],
];

export function spell(secs) {
  if (!secs) return "Never";
  const [n, unit] = secs % 3600 === 0 ? [secs / 3600, "hour"] : secs % 60 === 0 ? [secs / 60, "minute"] : [secs, "second"];
  return `${n} ${unit}${n === 1 ? "" : "s"}`;
}

export function choices(presets, current) {
  if (presets.includes(current)) return presets;
  const timed = [...presets.filter(Boolean), current].sort((a, b) => a - b);
  return [...timed, 0];
}
