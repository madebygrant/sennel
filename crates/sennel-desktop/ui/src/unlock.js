// What the line under the unlock screen's vault path says, for each mode and each kind that
// `check_path` reports. Kept out of the markup so the tests can reach it.
export const fits = (mode, kind) => kind === (mode === "new" ? "new" : "vault");

const name = (full) => full?.split("/").pop() ?? "";

export function pathNote(mode, check) {
  const fresh = mode === "new";
  switch (check?.kind ?? "empty") {
    case "empty":
      return {
        level: "dim",
        text: fresh ? "Pick a folder and a name. Sync folders such as Dropbox work." : "A .kdbx file from Sennel, KeePassXC or any KeePass app.",
      };
    case "other-home":
      return { level: "error", text: "Another user's ~ can't be resolved. Type the full path." };
    case "folder":
      return { level: "warn", text: `That's a folder. Add a file name, such as ${check.full}/vault.kdbx.` };
    case "blocked":
      return { level: "error", text: "Part of that path is a file, not a folder." };
    case "unreadable":
      return { level: "error", text: "Sennel can't read a folder on that path." };
    case "vault":
      return fresh ? { level: "warn", text: `${name(check.full)} already exists.`, action: { label: "Open it", to: "open" }, after: "or pick another name." } : null;
    case "new":
      return fresh
        ? { level: "dim", text: `Creates ${check.full}${check.makes ? ", and the folder it goes in" : ""}.`, warn: check.kdbx ? null : "KeePass apps look for a .kdbx name." }
        : { level: "warn", text: `No vault at ${check.full}.`, action: { label: "Create one here", to: "new" } };
    default:
      return null;
  }
}
