// Declares the app's own commands, so the capability file has to grant each one by name. Without
// this every command is open to every window.
const COMMANDS: &[&str] = &[
    "status",
    "choose",
    "touch",
    "unlock",
    "quick_unlock",
    "lock",
    "tree",
    "entries",
    "entry",
    "reveal",
    "copy",
    "copy_field",
    "copy_text",
    "generate",
    "save_entry",
    "delete_entry",
    "move_entry",
    "move_group",
    "reparent",
    "add_group",
    "rename_group",
    "delete_group",
    "undo",
    "save",
    "merge",
    "reload",
    "audit",
    "history",
    "clear_history",
    "fields",
    "add_field",
    "attach",
    "remove_field",
    "extract",
    "agent_give",
    "quit",
];

fn main() {
    tauri_build::try_build(
        tauri_build::Attributes::new()
            .app_manifest(tauri_build::AppManifest::new().commands(COMMANDS)),
    )
    .expect("tauri build step failed");
}
