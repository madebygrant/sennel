fn main() {
    // Before any secret exists in this process.
    sennel_core::harden::harden();
    sennel_desktop::run(tauri::generate_context!());
}
