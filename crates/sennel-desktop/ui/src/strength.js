// The same estimate as `generator::typed_bits` and `strength` in sennel-core, done here so a
// password being typed is not sent to Rust on every keystroke. Both test suites check one table.
const SYMBOLS = 26;

export function typedBits(password) {
  const chars = [...password];
  if (!chars.length) return 0;
  let alphabet = 0;
  if (chars.some((c) => /[a-z]/.test(c))) alphabet += 26;
  if (chars.some((c) => /[A-Z]/.test(c))) alphabet += 26;
  if (chars.some((c) => /[0-9]/.test(c))) alphabet += 10;
  if (chars.some((c) => /[!-/:-@[-`{-~ ]/.test(c))) alphabet += SYMBOLS;
  if (chars.some((c) => c.codePointAt(0) > 0x7f)) alphabet += 100;
  return chars.length * Math.log2(Math.max(alphabet, 2));
}

export const strength = (bits) => (bits < 40 ? "weak" : bits < 60 ? "fair" : bits < 80 ? "good" : "strong");
