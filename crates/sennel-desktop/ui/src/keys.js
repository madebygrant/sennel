// Written as in the terminal app's tables: `^` is ⌘ on macOS and Ctrl elsewhere.
const MAC = /Mac/.test(navigator.platform);

// A non-Latin layout types another letter on these keys, so it falls back to the key's QWERTY
// position. Latin layouts such as AZERTY keep what they type, as the terminal app does.
function letter(event) {
  const k = event.key;
  if (k.length === 1 && /\p{L}/u.test(k) && !/[a-z]/i.test(k) && /^Key[A-Z]$/.test(event.code)) {
    const c = event.code.slice(3);
    return event.shiftKey ? c : c.toLowerCase();
  }
  return k;
}

export function combo(event) {
  return event.metaKey || event.ctrlKey ? `^${letter(event).toLowerCase()}` : letter(event);
}

// Runs the first available action that takes the key, handing it the key as `combo` reads it;
// one returning false passes it on. A held key
// repeats only actions marked `repeats`, so holding p copies once.
export function dispatch(actions, event, { single = true } = {}) {
  const key = combo(event);
  if (!single && key.length === 1) return false;
  return actions.some(
    (a) => a.on.includes(key) && (!event.repeat || a.repeats) && (a.when?.() ?? true) && a.run(key) !== false,
  );
}

export const shown = (keys) => keys.replace(/\^(\w)/g, (_, k) => (MAC ? "⌘" : "Ctrl+") + k.toUpperCase());
