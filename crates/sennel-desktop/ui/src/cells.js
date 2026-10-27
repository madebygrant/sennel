// Indexes into `chars`: one group, or one per word with the dashes left out.
export function groupCells(chars, words) {
  const out = [[]];
  chars.forEach((c, i) => {
    if (words && c === "-") out.push([]);
    else out.at(-1).push(i);
  });
  return out;
}

// The vault doesn't record how a password was made; the generator's passphrases are lowercase words and dashes.
export const looksLikePassphrase = (value) => /^[a-z]+(-[a-z]+)+$/.test(value ?? "");
