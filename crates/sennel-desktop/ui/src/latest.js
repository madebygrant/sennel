// Wraps an async call so only the newest one counts: an overtaken call resolves to null, even if it failed.
export function latestOnly(fn) {
  let latest = 0;
  return async (...args) => {
    const ticket = ++latest;
    try {
      const reply = await fn(...args);
      return ticket === latest ? reply : null;
    } catch (why) {
      if (ticket !== latest) return null;
      throw why;
    }
  };
}
