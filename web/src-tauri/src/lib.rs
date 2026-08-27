use std::collections::HashSet;
use std::sync::Mutex;

const MAX_CAMPAIGN_BYTES: u64 = 256 * 1024 * 1024;

use base64::Engine as _;
use serde::Serialize;
use tauri::menu::{MenuBuilder, MenuItemBuilder, PredefinedMenuItem, SubmenuBuilder};
use tauri::{AppHandle, Emitter, Manager, State};
use tauri_plugin_dialog::DialogExt;

const B64: base64::engine::general_purpose::GeneralPurpose =
    base64::engine::general_purpose::STANDARD;
const KEYRING_SERVICE: &str = "app.campaign.local";

#[derive(Default)]
struct PendingOpen(Mutex<Option<String>>);

#[derive(Default)]
struct OpenAllowlist(Mutex<HashSet<String>>);

#[derive(Serialize)]
struct PickedFile {
    name: String,
    path: String,
    data_b64: String,
}

#[derive(Serialize)]
struct PickedText {
    name: String,
    path: String,
    text: String,
}

#[tauri::command]
async fn pick_campaign_file(app: AppHandle) -> Result<Option<PickedFile>, String> {
    let picked = app
        .dialog()
        .file()
        .set_title("Open campaign")
        .add_filter("Campaign file", &["camp"])
        .blocking_pick_file();

    match picked {
        None => Ok(None),
        Some(fp) => {
            let path = fp.into_path().map_err(|e| e.to_string())?;
            let bytes = std::fs::read(&path).map_err(|e| e.to_string())?;

            Ok(Some(PickedFile {
                name: file_name(&path),
                path: path.to_string_lossy().into_owned(),
                data_b64: B64.encode(bytes),
            }))
        }
    }
}

#[tauri::command]
async fn read_campaign_path(
    path: String,
    allow: State<'_, OpenAllowlist>,
) -> Result<Option<PickedFile>, String> {
    if !allow.0.lock().unwrap().contains(&path) {
        return Err("path is not an authorized open target".into());
    }

    let p = std::path::PathBuf::from(&path);
    if !p.is_file() {
        return Ok(None);
    }

    if std::fs::metadata(&p).map(|m| m.len()).unwrap_or(0) > MAX_CAMPAIGN_BYTES {
        return Err("file too large to be a campaign".into());
    }
    let bytes = std::fs::read(&p).map_err(|e| e.to_string())?;

    Ok(Some(PickedFile {
        name: file_name(&p),
        path: p.to_string_lossy().into_owned(),
        data_b64: B64.encode(bytes),
    }))
}

#[tauri::command]
async fn save_campaign_file(
    app: AppHandle,
    default_name: String,
    data_b64: String,
) -> Result<Option<String>, String> {
    let bytes = B64.decode(data_b64.as_bytes()).map_err(|e| e.to_string())?;
    let picked = app
        .dialog()
        .file()
        .set_title("Export campaign file")
        .set_file_name(&default_name)
        .add_filter("Campaign file", &["camp"])
        .blocking_save_file();

    match picked {
        None => Ok(None),
        Some(fp) => {
            let path = fp.into_path().map_err(|e| e.to_string())?;
            std::fs::write(&path, &bytes).map_err(|e| e.to_string())?;

            Ok(Some(path.to_string_lossy().into_owned()))
        }
    }
}

#[tauri::command]
async fn pick_scan_files(app: AppHandle) -> Result<Vec<PickedText>, String> {
    let picked = app
        .dialog()
        .file()
        .set_title("Import scanner output")
        .add_filter("Scanner output", &["xml", "json", "nessus", "txt", "log", "zip"])
        .add_filter("All files", &["*"])
        .blocking_pick_files();

    let mut out = Vec::new();

    if let Some(files) = picked {
        for fp in files {
            let path = fp.into_path().map_err(|e| e.to_string())?;
            // Archives (SharpHound zips) are binary: they cross the IPC boundary
            // base64-encoded; the web layer unzips them.
            let bytes = std::fs::read(&path).map_err(|e| e.to_string())?;
            let text = if path.extension().is_some_and(|e| e == "zip") {
                B64.encode(&bytes)
            } else {
                String::from_utf8(bytes).map_err(|e| e.to_string())?
            };

            out.push(PickedText {
                name: file_name(&path),
                path: path.to_string_lossy().into_owned(),
                text,
            });
        }
    }

    Ok(out)
}

#[tauri::command]
async fn save_text_file(
    app: AppHandle,
    default_name: String,
    content: String,
) -> Result<Option<String>, String> {
    let ext = default_name.rsplit('.').next().unwrap_or("txt").to_string();
    let picked = app
        .dialog()
        .file()
        .set_title("Save")
        .set_file_name(&default_name)
        .add_filter("File", &[ext.as_str()])
        .blocking_save_file();

    match picked {
        None => Ok(None),
        Some(fp) => {
            let path = fp.into_path().map_err(|e| e.to_string())?;
            std::fs::write(&path, content.as_bytes()).map_err(|e| e.to_string())?;

            Ok(Some(path.to_string_lossy().into_owned()))
        }
    }
}

#[tauri::command]
async fn save_binary_file(
    app: AppHandle,
    default_name: String,
    data_b64: String,
) -> Result<Option<String>, String> {
    let bytes = B64.decode(data_b64.as_bytes()).map_err(|e| e.to_string())?;

    let ext = default_name.rsplit('.').next().unwrap_or("bin").to_string();
    let picked = app
        .dialog()
        .file()
        .set_title("Save")
        .set_file_name(&default_name)
        .add_filter("File", &[ext.as_str()])
        .blocking_save_file();

    match picked {
        None => Ok(None),
        Some(fp) => {
            let path = fp.into_path().map_err(|e| e.to_string())?;
            std::fs::write(&path, &bytes).map_err(|e| e.to_string())?;

            Ok(Some(path.to_string_lossy().into_owned()))
        }
    }
}

fn file_name(path: &std::path::Path) -> String {
    path.file_name()
        .map(|s| s.to_string_lossy().into_owned())
        .unwrap_or_default()
}

const ALLOWED_SECRET_KEYS: [&str; 1] = ["identity"];

fn check_secret_key(key: &str) -> Result<(), String> {
    if ALLOWED_SECRET_KEYS.contains(&key) {
        Ok(())
    } else {
        Err("unknown secret key".into())
    }
}

#[tauri::command]
async fn secret_get(key: String) -> Result<Option<String>, String> {
    check_secret_key(&key)?;
    let entry = keyring::Entry::new(KEYRING_SERVICE, &key).map_err(|e| e.to_string())?;

    match entry.get_password() {
        Ok(v) => Ok(Some(v)),
        Err(keyring::Error::NoEntry) => Ok(None),
        Err(e) => Err(e.to_string()),
    }
}

#[tauri::command]
async fn secret_set(key: String, value: String) -> Result<(), String> {
    check_secret_key(&key)?;

    let entry = keyring::Entry::new(KEYRING_SERVICE, &key).map_err(|e| e.to_string())?;
    entry.set_password(&value).map_err(|e| e.to_string())
}

#[tauri::command]
async fn secret_delete(key: String) -> Result<(), String> {
    check_secret_key(&key)?;

    let entry = keyring::Entry::new(KEYRING_SERVICE, &key).map_err(|e| e.to_string())?;
    match entry.delete_credential() {
        Ok(()) | Err(keyring::Error::NoEntry) => Ok(()),
        Err(e) => Err(e.to_string()),
    }
}

#[derive(Serialize)]
struct CampaignFileEntry {
    name: String,
    path: String,
    modified_ms: u64,
    size: u64,
}

#[tauri::command]
async fn pick_directory(app: AppHandle) -> Result<Option<String>, String> {
    let picked = app
        .dialog()
        .file()
        .set_title("Choose campaigns folder")
        .blocking_pick_folder();

    Ok(picked
        .and_then(|fp| fp.into_path().ok())
        .map(|p| p.to_string_lossy().into_owned()))
}

#[tauri::command]
async fn list_campaign_files(folder: String) -> Result<Vec<CampaignFileEntry>, String> {
    let entries = std::fs::read_dir(&folder).map_err(|e| e.to_string())?;
    
    let mut out = Vec::new();
    
    for entry in entries.flatten() {
        let path = entry.path();
        if path.extension().and_then(|e| e.to_str()) != Some("camp") {
            continue;
        }
    
        let Ok(meta) = entry.metadata() else { continue };
        if !meta.is_file() {
            continue;
        }
    
        let modified_ms = meta
            .modified()
            .ok()
            .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0);
    
        out.push(CampaignFileEntry {
            name: file_name(&path),
            path: path.to_string_lossy().into_owned(),
            modified_ms,
            size: meta.len(),
        });
    }
    out.sort_by(|a, b| b.modified_ms.cmp(&a.modified_ms));
    
    Ok(out)
}

#[tauri::command]
async fn read_campaign_file(folder: String, path: String) -> Result<Option<PickedFile>, String> {
    let base = std::fs::canonicalize(&folder).map_err(|e| e.to_string())?;

    let full = std::fs::canonicalize(&path).map_err(|e| e.to_string())?;
    if !full.starts_with(&base) {
        return Err("path is outside the chosen folder".into());
    }
    if !full.is_file() {
        return Ok(None);
    }

    if std::fs::metadata(&full).map(|m| m.len()).unwrap_or(0) > MAX_CAMPAIGN_BYTES {
        return Err("file too large to be a campaign".into());
    }
    let bytes = std::fs::read(&full).map_err(|e| e.to_string())?;

    Ok(Some(PickedFile {
        name: file_name(&full),
        path: full.to_string_lossy().into_owned(),
        data_b64: B64.encode(bytes),
    }))
}

#[tauri::command]
async fn write_campaign_file(
    folder: String,
    name: String,
    data_b64: String,
) -> Result<String, String> {
    let np = std::path::Path::new(&name);
    if np.components().count() != 1 || np.file_name().map(|n| n != name.as_str()).unwrap_or(true) {
        return Err("campaign file name must be a bare filename".into());
    }

    let base = std::fs::canonicalize(&folder).map_err(|e| e.to_string())?;

    let bytes = B64.decode(data_b64.as_bytes()).map_err(|e| e.to_string())?;
    if bytes.len() as u64 > MAX_CAMPAIGN_BYTES {
        return Err("campaign too large".into());
    }

    let dest = base.join(&name);
    std::fs::write(&dest, &bytes).map_err(|e| e.to_string())?;

    Ok(dest.to_string_lossy().into_owned())
}

#[tauri::command]
async fn delete_campaign_file(folder: String, name: String) -> Result<(), String> {
    let np = std::path::Path::new(&name);
    if np.components().count() != 1 || np.file_name().map(|n| n != name.as_str()).unwrap_or(true) {
        return Err("file name must be a bare filename".into());
    }
    
    let base = std::fs::canonicalize(&folder).map_err(|e| e.to_string())?;
    let dest = base.join(&name);
    
    match std::fs::remove_file(&dest) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e.to_string()),
    }
}

#[tauri::command]
fn take_pending_open(state: State<'_, PendingOpen>) -> Option<String> {
    state.0.lock().unwrap().take()
}

fn extract_open_target(args: &[String]) -> Option<String> {
    args.iter()
        .skip(1)
        .find(|a| a.ends_with(".camp"))
        .cloned()
}

pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_single_instance::init(|app, argv, _cwd| {
            if let Some(w) = app.get_webview_window("main") {
                let _ = w.set_focus();
            }

            if let Some(target) = extract_open_target(&argv) {
                app.state::<OpenAllowlist>()
                    .0
                    .lock()
                    .unwrap()
                    .insert(target.clone());
                let _ = app.emit("open-file", target);
            }
        }))
        .plugin(tauri_plugin_window_state::Builder::default().build())
        .plugin(tauri_plugin_dialog::init())
        .manage(PendingOpen::default())
        .manage(OpenAllowlist::default())
        .invoke_handler(tauri::generate_handler![
            pick_campaign_file,
            read_campaign_path,
            save_campaign_file,
            pick_scan_files,
            save_text_file,
            save_binary_file,
            secret_get,
            secret_set,
            secret_delete,
            pick_directory,
            list_campaign_files,
            read_campaign_file,
            write_campaign_file,
            delete_campaign_file,
            take_pending_open,
        ])
        .setup(|app| {
            build_native_menu(app)?;

            if let Some(target) = extract_open_target(&std::env::args().collect::<Vec<_>>()) {
                app.state::<OpenAllowlist>()
                    .0
                    .lock()
                    .unwrap()
                    .insert(target.clone());
                *app.state::<PendingOpen>().0.lock().unwrap() = Some(target);
            }
            Ok(())
        })
        .run(tauri::generate_context!())
        .expect("error while building the Campaign Knowledge desktop app");
}

fn build_native_menu(app: &tauri::App) -> tauri::Result<()> {
    let h = app.handle();
    let file = SubmenuBuilder::new(h, "File")
        .item(&MenuItemBuilder::with_id("new_campaign", "New Campaign").build(h)?)
        .item(
            &MenuItemBuilder::with_id("open_campaign", "Open Campaign File")
                .accelerator("CmdOrCtrl+O")
                .build(h)?,
        )
        .separator()
        .item(
            &MenuItemBuilder::with_id("export_campaign", "Export Campaign File")
                .accelerator("CmdOrCtrl+S")
                .build(h)?,
        )
        .item(&MenuItemBuilder::with_id("export_report", "Export Report").build(h)?)
        .item(&MenuItemBuilder::with_id("export_map", "Export Map Image").build(h)?)
        .separator()
        .item(&PredefinedMenuItem::close_window(h, Some("Close Window"))?)
        .item(&PredefinedMenuItem::quit(h, Some("Quit"))?)
        .build()?;

    let edit = SubmenuBuilder::new(h, "Edit")
        .undo()
        .redo()
        .separator()
        .cut()
        .copy()
        .paste()
        .select_all()
        .build()?;

    let view = SubmenuBuilder::new(h, "View")
        .item(
            &MenuItemBuilder::with_id("fit", "Fit Network to Screen")
                .accelerator("CmdOrCtrl+0")
                .build(h)?,
        )
        .item(
            &MenuItemBuilder::with_id("command_palette", "Command Palette")
                .accelerator("CmdOrCtrl+K")
                .build(h)?,
        )
        .item(&MenuItemBuilder::with_id("appearance", "Appearance").build(h)?)
        .separator()
        .item(
            &MenuItemBuilder::with_id("reload", "Reload")
                .accelerator("CmdOrCtrl+R")
                .build(h)?,
        )
        .build()?;

    let menu = MenuBuilder::new(h).items(&[&file, &edit, &view]).build()?;
    app.set_menu(menu)?;
    app.on_menu_event(move |app, event| {
        let _ = app.emit("menu", event.id().0.clone());
    });
    
    Ok(())
}
