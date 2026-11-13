fn main() {
    // Before any secret exists in this process.
    let refused = sennel_core::harden::harden();
    sennel_desktop::run(tauri::generate_context!(), refused);
}
