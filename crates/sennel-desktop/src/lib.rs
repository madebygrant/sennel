// Sennel in a native window. The webview talks to this process over Tauri's in-process IPC: no
// HTTP server, no port. Every command runs on the blocking pool, never the main thread, since any
// of them can wait on the session while it derives a key or waits for a touch.

pub mod desk;
pub mod settings;

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, OnceLock};
use std::time::{Duration, Instant};

use desk::{
    AuditRow, Desk, EntryForm, EntryRow, EntryView, EnvPreview, FieldRow, Generated, GroupRow,
    Note, PathCheck, Pick, PrefValue, Prefs, Reply, Scanned, Status, VersionRow,
};
use tauri::{AppHandle, Emitter, Manager, State};
use zeroize::Zeroizing;

type Shared<'a> = State<'a, Arc<Desk>>;

async fn off_main<T: Send + 'static>(
    desk: &Shared<'_>,
    work: impl FnOnce(&Desk) -> T + Send + 'static,
) -> Result<T, String> {
    let desk = Arc::clone(desk.inner());
    tauri::async_runtime::spawn_blocking(move || work(&desk))
        .await
        .map_err(|e| e.to_string())
}

// Set by the quit command once the window has asked, so the second close goes through.
struct Leaving(AtomicBool);

#[tauri::command]
async fn status(desk: Shared<'_>) -> Result<Status, String> {
    off_main(&desk, Desk::status).await
}

#[tauri::command]
async fn choose(desk: Shared<'_>, path: String) -> Result<Status, String> {
    off_main(&desk, move |d| d.choose(&path)).await?
}

// Off the main thread: a path on a sleeping network drive can take seconds to stat.
#[tauri::command]
async fn check_path(desk: Shared<'_>, path: String) -> Result<PathCheck, String> {
    off_main(&desk, move |_| Desk::check_path(&path)).await
}

// Keys, clicks and pointer moves over the window. Focus and blur never call this, so a window
// left in the background ages toward the lock like an idle one.
#[tauri::command]
async fn touch(desk: Shared<'_>) -> Result<(), String> {
    off_main(&desk, Desk::touch).await
}

#[tauri::command]
async fn unlock(
    desk: Shared<'_>,
    password: String,
    key_file: Option<String>,
    confirm: Option<String>,
) -> Result<Reply, String> {
    off_main(&desk, move |d| d.unlock(password, key_file, confirm)).await
}

#[tauri::command]
async fn quick_unlock(desk: Shared<'_>, key_file: Option<String>) -> Result<Reply, String> {
    off_main(&desk, move |d| d.quick_unlock(key_file)).await
}

#[tauri::command]
async fn lock(desk: Shared<'_>) -> Result<Reply, String> {
    off_main(&desk, Desk::lock).await
}

#[tauri::command]
async fn prefs(desk: Shared<'_>) -> Result<Prefs, String> {
    off_main(&desk, Desk::prefs).await
}

#[tauri::command]
async fn set_pref(
    app: AppHandle,
    desk: Shared<'_>,
    key: String,
    value: PrefValue,
) -> Result<Note, String> {
    // Asked here, natively, not by the page: a script there could answer its own question.
    off_main(&desk, move |d| {
        // Locked, set_pref refuses it anyway, so the question would have no point.
        let question = d
            .lowers_protection(&key, &value)
            .filter(|_| d.session().is_open());
        if let Some(question) = question {
            use tauri_plugin_dialog::{DialogExt, MessageDialogButtons};
            let yes = app
                .dialog()
                .message(question)
                .buttons(MessageDialogButtons::OkCancel)
                .blocking_show();
            if !yes {
                return Ok(desk::info("unchanged"));
            }
        }
        d.set_pref(&key, value)
    })
    .await?
}

#[tauri::command]
async fn tree(desk: Shared<'_>) -> Result<Vec<GroupRow>, String> {
    off_main(&desk, Desk::tree).await
}

#[tauri::command]
async fn entries(
    desk: Shared<'_>,
    group: Option<String>,
    needle: Option<String>,
) -> Result<Vec<EntryRow>, String> {
    off_main(&desk, move |d| {
        d.entries(group.as_deref(), needle.as_deref())
    })
    .await?
}

#[tauri::command]
async fn entry(desk: Shared<'_>, id: String) -> Result<EntryView, String> {
    off_main(&desk, move |d| d.entry(&id)).await?
}

#[tauri::command]
async fn reveal(desk: Shared<'_>, id: String) -> Result<Zeroizing<String>, String> {
    off_main(&desk, move |d| d.reveal(&id)).await?
}

#[tauri::command]
async fn copy(desk: Shared<'_>, id: String, field: String) -> Result<Note, String> {
    off_main(&desk, move |d| d.copy(&id, &field)).await
}

#[tauri::command]
async fn copy_field(desk: Shared<'_>, id: String, name: String) -> Result<Note, String> {
    off_main(&desk, move |d| d.copy_field(&id, &name)).await
}

#[tauri::command]
async fn copy_text(desk: Shared<'_>, label: String, text: String) -> Result<Note, String> {
    off_main(&desk, move |d| d.copy_text(&label, text)).await
}

#[tauri::command]
async fn scan_clipboard(
    desk: Shared<'_>,
    title: String,
    username: String,
) -> Result<Scanned, String> {
    off_main(&desk, move |d| d.scan_clipboard(&title, &username)).await?
}

#[tauri::command]
async fn scan_file(
    desk: Shared<'_>,
    path: String,
    title: String,
    username: String,
) -> Result<Scanned, String> {
    off_main(&desk, move |d| d.scan_file(&path, &title, &username)).await?
}

#[tauri::command]
async fn cycle_sort(desk: Shared<'_>) -> Result<Note, String> {
    off_main(&desk, Desk::cycle_sort).await
}

// The password arrives as a JS string, which cannot be wiped on that side; Rust wipes its copies.
#[tauri::command]
async fn rekey(
    desk: Shared<'_>,
    current: String,
    password: String,
    confirm: String,
) -> Result<Reply, String> {
    off_main(&desk, move |d| d.rekey(current, password, confirm)).await
}

#[tauri::command]
async fn clear_clipboard(desk: Shared<'_>) -> Result<(), String> {
    off_main(&desk, Desk::clear_clipboard).await
}

#[tauri::command]
async fn generate(desk: Shared<'_>, pick: Pick) -> Result<Generated, String> {
    off_main(&desk, move |d| d.generate(&pick)).await?
}

#[tauri::command]
async fn save_entry(
    desk: Shared<'_>,
    id: Option<String>,
    group: Option<String>,
    form: EntryForm,
) -> Result<Reply, String> {
    off_main(&desk, move |d| {
        d.save_entry(id.as_deref(), group.as_deref(), &form)
    })
    .await?
}

#[tauri::command]
async fn delete_entry(desk: Shared<'_>, id: String) -> Result<Reply, String> {
    off_main(&desk, move |d| d.delete_entry(&id)).await?
}

#[tauri::command]
async fn move_entry(desk: Shared<'_>, id: String, group: String) -> Result<Reply, String> {
    off_main(&desk, move |d| d.move_entry(&id, &group)).await?
}

#[tauri::command]
async fn move_group(desk: Shared<'_>, id: String, group: String) -> Result<Reply, String> {
    off_main(&desk, move |d| d.move_group(&id, &group)).await?
}

#[tauri::command]
async fn reparent(desk: Shared<'_>, id: String, deeper: bool) -> Result<Reply, String> {
    off_main(&desk, move |d| d.reparent(&id, deeper)).await?
}

#[tauri::command]
async fn add_group(desk: Shared<'_>, parent: String, name: String) -> Result<Reply, String> {
    off_main(&desk, move |d| d.add_group(&parent, &name)).await?
}

#[tauri::command]
async fn rename_group(desk: Shared<'_>, id: String, name: String) -> Result<Reply, String> {
    off_main(&desk, move |d| d.rename_group(&id, &name)).await?
}

#[tauri::command]
async fn delete_group(desk: Shared<'_>, id: String) -> Result<Reply, String> {
    off_main(&desk, move |d| d.delete_group(&id)).await?
}

#[tauri::command]
async fn undo(desk: Shared<'_>) -> Result<Reply, String> {
    off_main(&desk, Desk::undo).await
}

#[tauri::command]
async fn save(desk: Shared<'_>) -> Result<Reply, String> {
    off_main(&desk, Desk::save).await
}

#[tauri::command]
async fn merge(desk: Shared<'_>) -> Result<Reply, String> {
    off_main(&desk, Desk::merge).await
}

#[tauri::command]
async fn reload(desk: Shared<'_>) -> Result<Reply, String> {
    off_main(&desk, Desk::reload).await
}

#[tauri::command]
async fn audit(desk: Shared<'_>) -> Result<Vec<AuditRow>, String> {
    off_main(&desk, Desk::audit).await
}

#[tauri::command]
async fn history(desk: Shared<'_>, id: String) -> Result<Vec<VersionRow>, String> {
    off_main(&desk, move |d| d.history(&id)).await?
}

#[tauri::command]
async fn clear_history(desk: Shared<'_>, id: String) -> Result<Reply, String> {
    off_main(&desk, move |d| d.clear_history(&id)).await?
}

#[tauri::command]
async fn fields(desk: Shared<'_>, id: String) -> Result<Vec<FieldRow>, String> {
    off_main(&desk, move |d| d.fields(&id)).await?
}

#[tauri::command]
async fn add_field(
    desk: Shared<'_>,
    id: String,
    name: String,
    value: String,
    kind: String,
) -> Result<Reply, String> {
    // Wiped once used, as `edit_field`'s is: a new field defaults to the password kind.
    let value = Zeroizing::new(value);
    off_main(&desk, move |d| d.add_field(&id, &name, &value, &kind)).await?
}

#[tauri::command]
async fn edit_field(
    desk: Shared<'_>,
    id: String,
    name: String,
    new_name: String,
    value: Option<String>,
    kind: String,
) -> Result<Reply, String> {
    // Wiped once the edit lands, like the entry form's password.
    let value = value.map(Zeroizing::new);
    off_main(&desk, move |d| {
        d.edit_field(
            &id,
            &name,
            &new_name,
            value.as_ref().map(|v| v.as_str()),
            &kind,
        )
    })
    .await?
}

#[tauri::command]
async fn reveal_field(
    desk: Shared<'_>,
    id: String,
    name: String,
) -> Result<Zeroizing<String>, String> {
    off_main(&desk, move |d| d.reveal_field(&id, &name)).await?
}

#[tauri::command]
async fn env_preview(
    desk: Shared<'_>,
    id: Option<String>,
    text: String,
) -> Result<EnvPreview, String> {
    off_main(&desk, move |d| d.env_preview(id.as_deref(), text)).await?
}

#[tauri::command]
async fn save_env(
    desk: Shared<'_>,
    id: Option<String>,
    group: Option<String>,
    title: String,
    text: String,
) -> Result<Reply, String> {
    off_main(&desk, move |d| {
        d.save_env(id.as_deref(), group.as_deref(), &title, text)
    })
    .await?
}

#[tauri::command]
async fn copy_env(desk: Shared<'_>, id: String) -> Result<Note, String> {
    off_main(&desk, move |d| d.copy_env(&id)).await
}

#[tauri::command]
async fn attach(
    app: AppHandle,
    desk: Shared<'_>,
    id: String,
    name: String,
) -> Result<Reply, String> {
    use tauri_plugin_dialog::DialogExt;
    // Off the main thread, where a blocking picker is allowed; the lock is checked before asking.
    off_main(&desk, move |d| {
        if !d.session().is_open() {
            return Ok(Reply::notes(vec![]));
        }
        let picked = app.dialog().file().blocking_pick_file();
        match picked.and_then(|p| p.into_path().ok()) {
            Some(path) => d.attach(&id, &name, &path),
            None => Ok(Reply::notes(vec![])),
        }
    })
    .await?
}

#[tauri::command]
async fn remove_field(
    desk: Shared<'_>,
    id: String,
    name: String,
    file: bool,
) -> Result<Reply, String> {
    off_main(&desk, move |d| d.remove_field(&id, &name, file)).await?
}

#[tauri::command]
async fn extract(desk: Shared<'_>, id: String, name: String) -> Result<Note, String> {
    off_main(&desk, move |d| d.extract(&id, &name)).await?
}

#[tauri::command]
async fn agent_give(
    app: AppHandle,
    desk: Shared<'_>,
    id: String,
    name: String,
) -> Result<Note, String> {
    // It works with the ssh_agent setting off, as `g` does in the terminal app, so the first key of
    // an unlock is confirmed natively: a script in the page cannot answer a native dialog.
    off_main(&desk, move |d| {
        if !d.agent_confirmed() {
            use tauri_plugin_dialog::{DialogExt, MessageDialogButtons};
            let asked_under = d.unlock_count();
            let question = format!(
                "Give {} to ssh-agent? Until it expires or the vault locks, any program that can reach the agent can sign with it.",
                sennel_core::vault::printable(&name)
            );
            let yes = app
                .dialog()
                .message(question)
                .buttons(MessageDialogButtons::OkCancel)
                .blocking_show();
            if !yes {
                return Ok(desk::info("not given"));
            }
            if !d.confirm_agent(asked_under) {
                return Ok(desk::info("the vault locked meanwhile · not given"));
            }
        }
        d.agent_give(&id, &name)
    })
    .await?
}

// The window asked and the user chose to lose what could not be saved.
#[tauri::command]
fn quit(app: AppHandle, leaving: State<'_, Leaving>) {
    leaving.0.store(true, Ordering::SeqCst);
    app.exit(0);
}

// The default menu's Quit ends the app without `ExitRequested`, so ⌘Q skipped the question about
// unsaved changes. It is swapped for an item that exits the ordinary way, which asks first.
#[cfg(target_os = "macos")]
fn route_quit(app: &AppHandle) -> tauri::Result<()> {
    use tauri::menu::{Menu, MenuItem, MenuItemKind};
    let menu = Menu::default(app)?;
    if let Some(MenuItemKind::Submenu(first)) = menu.items()?.into_iter().next() {
        let last = first.items()?.len().saturating_sub(1);
        first.remove_at(last)?;
        let quit = MenuItem::with_id(app, "sennel-quit", "Quit Sennel", true, Some("CmdOrCtrl+Q"))?;
        first.append(&quit)?;
    }
    app.set_menu(menu)?;
    app.on_menu_event(|app, event| {
        if event.id() == "sennel-quit" {
            app.exit(0);
        }
    });
    Ok(())
}

// Only the bundled page, and the dev server in a debug build. The content security policy does not
// cover top-level navigation, so a script in the page could otherwise leave carrying what it read.
fn own_page(url: &tauri::Url) -> bool {
    match (url.scheme(), url.host_str()) {
        ("tauri", Some("localhost")) => true,
        ("http" | "https", Some("tauri.localhost")) => true,
        ("http", Some("localhost")) => cfg!(debug_assertions) && url.port() == Some(5173),
        ("about", None) => url.as_str() == "about:blank",
        _ => false,
    }
}

// Whether a close or quit has to stop and ask first.
fn must_ask(app: &AppHandle) -> bool {
    !app.state::<Leaving>().0.load(Ordering::SeqCst) && app.state::<Arc<Desk>>().unsaved_or_busy()
}

pub fn run(context: tauri::Context) {
    // A panic on the main thread ends the app without its normal exit. A command's panic is caught
    // on its own thread and the vault stays open, so that one must not empty the agent.
    let previous = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        previous(info);
        if std::thread::current().name() == Some("main") {
            sennel_core::clipboard::emergency_clear();
            sennel_core::agent::emergency_release();
        }
    }));
    // A GUI session always has HOME. Without it every path below would be relative to wherever the
    // app was started, so it does not start.
    if let Err(why) = sennel_core::config::home() {
        eprintln!("sennel-desktop: {why}");
        std::process::exit(1);
    }
    let settings = settings::Settings::load().unwrap_or_else(|why| {
        eprintln!("sennel-desktop: {why}");
        settings::Settings::fallback(why)
    });
    let board = sennel_core::clipboard::Board::new(settings.clipboard_timeout);
    let handle: Arc<OnceLock<AppHandle>> = Arc::default();
    let prompt_to = Arc::clone(&handle);
    let desk = Arc::new(Desk::new(settings, Some(board)).with_prompt(move |note| {
        if let Some(app) = prompt_to.get() {
            let _ = app.emit("prompt", note);
        }
    }));
    let app = tauri::Builder::default()
        .plugin(tauri_plugin_dialog::init())
        .plugin(
            tauri::plugin::Builder::<tauri::Wry>::new("stay")
                .on_navigation(|_, url| own_page(url))
                .build(),
        )
        .manage(Arc::clone(&desk))
        .manage(Leaving(AtomicBool::new(false)))
        .setup(move |app| {
            let _ = handle.set(app.handle().clone());
            #[cfg(target_os = "macos")]
            route_quit(app.handle())?;
            // A `kill` or a logout goes through the normal exit, which wipes the clipboard and
            // takes keys back from the agent. Nobody is there to ask about unsaved changes, so it
            // does not ask, and every signal is handled, not only the first.
            use signal_hook::consts::{SIGHUP, SIGINT, SIGTERM};
            if let Ok(mut signals) = signal_hook::iterator::Signals::new([SIGTERM, SIGINT, SIGHUP])
            {
                let app = app.handle().clone();
                std::thread::spawn(move || {
                    for _ in signals.forever() {
                        app.state::<Leaving>().0.store(true, Ordering::SeqCst);
                        app.exit(0);
                    }
                });
            }
            // On a Rust timer, so a hung or hidden webview cannot keep the vault open.
            let app = app.handle().clone();
            let desk = Arc::clone(&desk);
            std::thread::spawn(move || {
                loop {
                    std::thread::sleep(Duration::from_secs(1));
                    // One panic must not end idle locking for the rest of the run.
                    let idle = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                        desk.lock_if_idle(Instant::now())
                    }));
                    if let Ok(Some(notes)) = idle {
                        let _ = app.emit("locked", notes);
                    }
                }
            });
            Ok(())
        })
        .on_window_event(|window, event| {
            if let tauri::WindowEvent::CloseRequested { api, .. } = event
                && must_ask(window.app_handle())
            {
                api.prevent_close();
                let _ = window.emit("quit-asked", ());
            }
        })
        .invoke_handler(tauri::generate_handler![
            status,
            choose,
            check_path,
            touch,
            unlock,
            quick_unlock,
            lock,
            prefs,
            set_pref,
            tree,
            entries,
            entry,
            reveal,
            copy,
            copy_field,
            copy_text,
            clear_clipboard,
            cycle_sort,
            rekey,
            scan_clipboard,
            scan_file,
            generate,
            save_entry,
            delete_entry,
            move_entry,
            move_group,
            reparent,
            add_group,
            rename_group,
            delete_group,
            undo,
            save,
            merge,
            reload,
            audit,
            history,
            clear_history,
            fields,
            add_field,
            reveal_field,
            edit_field,
            env_preview,
            save_env,
            copy_env,
            attach,
            remove_field,
            extract,
            agent_give,
            quit,
        ])
        .build(context)
        .expect("the window could not be built");
    app.run(|app, event| match event {
        tauri::RunEvent::ExitRequested { api, .. } if must_ask(app) => {
            api.prevent_exit();
            let _ = app.emit("quit-asked", ());
        }
        tauri::RunEvent::Exit => app.state::<Arc<Desk>>().shutdown(),
        _ => {}
    });
}

#[cfg(test)]
mod tests;
