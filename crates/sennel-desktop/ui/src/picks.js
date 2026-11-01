// These build on what was last asked for, not on the shown result, which lags while a reply is in flight.
// Each returns the arguments for generate(), or null when nothing would change.
export function resized(chosen, by) {
  const kind = chosen.kind;
  const [min, max] = chosen.bounds[kind] ?? [];
  const size = chosen.sizes[kind];
  if (size == null || min == null) return null;
  const want = Math.min(max, Math.max(min, size + by));
  return want === size ? null : [kind, want];
}

export function restyled(chosen, key) {
  if (chosen.kind !== "complex" || !chosen.style) return null;
  return ["complex", undefined, { ...chosen.style, [key]: !chosen.style[key] }];
}
