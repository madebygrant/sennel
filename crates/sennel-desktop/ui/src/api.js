import { invoke } from "@tauri-apps/api/core";
import { listen } from "@tauri-apps/api/event";

// Every call goes over Tauri's in-process IPC. Errors come back as strings from Rust.
export const call = (cmd, args = {}) => invoke(cmd, args);
export const on = (event, fn) => listen(event, (e) => fn(e.payload));
