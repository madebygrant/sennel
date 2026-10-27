// The group tree arrives depth-first, so a group's children are the rows after it that sit deeper.
export const hasKids = (groups, at) => (groups[at + 1]?.depth ?? -1) > groups[at].depth;

// Indexes into `groups` of the rows a fold leaves showing.
export function visibleGroups(groups, folded) {
  const out = [];
  let below = Infinity;
  groups.forEach((g, at) => {
    if (g.depth > below) return;
    below = folded.has(g.id) ? g.depth : Infinity;
    out.push(at);
  });
  return out;
}

export function parentOf(groups, at) {
  return groups.slice(0, at).findLast((g) => g.depth < groups[at].depth);
}
