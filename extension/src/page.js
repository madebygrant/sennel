// R2: a fill goes only to the tab and page the logins were fetched for. The query and fragment may
// change on the same page, as single-page logins do; the origin and path may not.
export function samePage(asked, now) {
  if (!asked || !now || asked.id !== now.id) return false;
  return pageOf(asked.url) !== null && pageOf(asked.url) === pageOf(now.url);
}

export function pageOf(url) {
  try {
    const u = new URL(url);
    return `${u.origin}${u.pathname}`;
  } catch {
    return null;
  }
}

// Pages a password never goes to: the browser's own, other extensions', and local files.
export function fillable(url) {
  try {
    const { protocol } = new URL(url);
    return protocol === "https:" || protocol === "http:";
  } catch {
    return false;
  }
}
