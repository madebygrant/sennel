import { invoke } from "@tauri-apps/api/core";
import { listen } from "@tauri-apps/api/event";

// Every call goes over Tauri's in-process IPC. Errors come back as strings from Rust.
export const call = (cmd, args = {}) => invoke(cmd, args);
// Copy and cut out of a box holding a secret go through Rust's board, so they clear like any other
// copy. A cut copies without cutting: the box is still the user's to edit.
export const secretCopy = (label, say) => async (event) => {
  const box = event.currentTarget;
  const text = box.value.slice(box.selectionStart ?? 0, box.selectionEnd ?? 0);
  event.preventDefault();
  if (text) say([await invoke("copy_text", { label, text })]);
};

export const on = (event, fn) => listen(event, (e) => fn(e.payload));
