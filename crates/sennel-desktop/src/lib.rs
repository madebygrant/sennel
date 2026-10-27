// Sennel in a native window. The webview talks to this process over Tauri's in-process IPC: no
// HTTP server, no port. Every command runs on the blocking pool, never the main thread, since any
// of them can wait on the session while it derives a key or waits for a touch.

pub mod desk;
pub mod settings;

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, OnceLock};
use std::time::{Duration, Instant};

use desk::{AuditRow, Desk, EntryForm, EntryRow, EntryView, FieldRow, GroupRow, Note, Reply, Status, VersionRow};
use tauri::{AppHandle, Emitter, Manager, State};
use zeroize::Zeroizing;

type Shared<'a> = State<'a, Arc<Desk>>;

async fn off_main<T: Send + 'static>(desk: &Shared<'_>, work: impl FnOnce(&Desk) -> T + Send + 'static) -> Result<T, String> {
    let desk = Arc::clone(desk.inner());
    tauri::async_runtime::spawn_blocking(move || work(&desk)).await.map_err(|e| e.to_string())
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

// Keys and clicks only. Focus and blur never call this, so a window left in the background ages
// toward the lock like an idle one.
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
async fn tree(desk: Shared<'_>) -> Result<Vec<GroupRow>, String> {
    off_main(&desk, Desk::tree).await
}

#[tauri::command]
async fn entries(desk: Shared<'_>, group: Option<String>, needle: Option<String>) -> Result<Vec<EntryRow>, String> {
    off_main(&desk, move |d| d.entries(group.as_deref(), needle.as_deref())).await?
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
async fn generate(desk: Shared<'_>) -> Result<Zeroizing<String>, String> {
    off_main(&desk, Desk::generate).await?
}

#[tauri::command]
async fn save_entry(desk: Shared<'_>, id: Option<String>, group: Option<String>, form: EntryForm) -> Result<Reply, String> {
    off_main(&desk, move |d| d.save_entry(id.as_deref(), group.as_deref(), &form)).await?
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
async fn add_field(desk: Shared<'_>, id: String, name: String, value: String) -> Result<Reply, String> {
    off_main(&desk, move |d| d.add_field(&id, &name, &value)).await?
}

#[tauri::command]
async fn attach(desk: Shared<'_>, id: String, name: String, path: String) -> Result<Reply, String> {
    off_main(&desk, move |d| d.attach(&id, &name, &path)).await?
}

#[tauri::command]
async fn remove_field(desk: Shared<'_>, id: String, name: String, file: bool) -> Result<Reply, String> {
    off_main(&desk, move |d| d.remove_field(&id, &name, file)).await?
}

#[tauri::command]
async fn extract(desk: Shared<'_>, id: String, name: String) -> Result<Note, String> {
    off_main(&desk, move |d| d.extract(&id, &name)).await?
}

#[tauri::command]
async fn agent_give(desk: Shared<'_>, id: String, name: String) -> Result<Note, String> {
    off_main(&desk, move |d| d.agent_give(&id, &name)).await?
}

// The window asked and the user chose to lose what could not be saved.
#[tauri::command]
fn quit(app: AppHandle, leaving: State<'_, Leaving>) {
    leaving.0.store(true, Ordering::SeqCst);
    app.exit(0);
}

// Whether a close or quit has to stop and ask first.
fn must_ask(app: &AppHandle) -> bool {
    !app.state::<Leaving>().0.load(Ordering::SeqCst) && app.state::<Arc<Desk>>().unsaved()
}

pub fn run(context: tauri::Context) {
    let settings = match settings::Settings::load() {
        Ok(settings) => settings,
        // A broken config stops the terminal app at startup too.
        Err(why) => {
            eprintln!("sennel-desktop: {why}");
            std::process::exit(1);
        }
    };
    let board = sennel_core::clipboard::Board::new(settings.clipboard_timeout);
    let handle: Arc<OnceLock<AppHandle>> = Arc::default();
    let prompt_to = Arc::clone(&handle);
    let desk = Arc::new(Desk::new(settings, Some(board)).with_prompt(move |note| {
        if let Some(app) = prompt_to.get() {
            let _ = app.emit("prompt", note);
        }
    }));
    let app = tauri::Builder::default()
        .manage(Arc::clone(&desk))
        .manage(Leaving(AtomicBool::new(false)))
        .setup(move |app| {
            let _ = handle.set(app.handle().clone());
            // On a Rust timer, so a hung or hidden webview cannot keep the vault open.
            let app = app.handle().clone();
            let desk = Arc::clone(&desk);
            std::thread::spawn(move || {
                loop {
                    std::thread::sleep(Duration::from_secs(1));
                    if let Some(notes) = desk.lock_if_idle(Instant::now()) {
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
            touch,
            unlock,
            quick_unlock,
            lock,
            tree,
            entries,
            entry,
            reveal,
            copy,
            copy_field,
            copy_text,
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
