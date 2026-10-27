import { call } from "./api.js";
import { latestOnly } from "./latest.js";

// The config's [generator] is only the default: picks last until Sennel quits, and the entry form follows them.
export const KINDS = [
  ["complex", "Password"],
  ["passphrase", "Passphrase"],
  ["pin", "PIN"],
];
// The terminal app's keys and labels for the classes that shape a complex password.
export const STYLES = [
  ["upper", "u", "A–Z", "Capitals"],
  ["digits", "d", "0–9", "Digits"],
  ["symbols", "s", "!@#", "Symbols"],
  ["noLookalikes", "a", "No l1IO0", "Leave out lookalike characters"],
];
export const chosen = $state({ kind: null, sizes: {}, bounds: {}, style: null });

const ask = latestOnly((pick) => call("generate", { pick }));

// Picks are recorded before the reply so a held key counts every press, and put back if the newest one fails.
export async function generate(kind = chosen.kind, size, style = chosen.style) {
  const before = { kind: chosen.kind, size: chosen.sizes[kind], style: chosen.style };
  if (kind) chosen.kind = kind;
  if (kind && size != null) chosen.sizes[kind] = size;
  if (style) chosen.style = style;
  let made;
  try {
    made = await ask({ kind, size: size ?? chosen.sizes[kind] ?? null, style });
  } catch (why) {
    chosen.kind = before.kind;
    if (kind) chosen.sizes[kind] = before.size;
    chosen.style = before.style;
    throw why;
  }
  if (!made) return null;
  chosen.kind = made.kind;
  chosen.sizes[made.kind] = made.size;
  chosen.bounds[made.kind] = [made.min, made.max];
  chosen.style = made.style;
  return made;
}
