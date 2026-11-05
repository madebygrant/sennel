// What the copy keys do for the selected entry. `env` comes from the list row, which changes in the
// same tick as the selection; the detail arrives a moment later and may still be the last entry's.
export const COPIES = { y: "username", p: "password", U: "url", t: "otp" };

// The field to copy, "env" for an env entry's whole file, or null to pass the key on.
export function copyFor(key, { env, hasOtp, url }) {
  const field = COPIES[key];
  if (env) return field === "password" ? "env" : null;
  if ((field === "otp" && !hasOtp) || (field === "url" && !url)) return null;
  return field;
}

export function entryHints({ env, hasOtp }) {
  return env
    ? [["p", ".env file"], ["e", "edit"], ["/", "find"]]
    : [["p", "password"], ["y", "user"], ...(hasOtp ? [["t", "code"]] : []), ["e", "edit"], ["/", "find"]];
}
