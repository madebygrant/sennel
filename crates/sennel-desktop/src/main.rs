fn main() {
    // Started by a browser through native messaging: relay to the running window and never open one.
    let args: Vec<String> = std::env::args().collect();
    if let Some(host) = sennel_browser::proxy::host_from_args(&args) {
        std::process::exit(sennel_browser::proxy::run(host));
    }
    // Before any secret exists in this process.
    let refused = sennel_core::harden::harden();
    sennel_desktop::run(tauri::generate_context!(), refused);
}
