#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

fn main() {
    eprintln!("[hello-tauri] starting");
    tauri::Builder::default()
        .setup(|app| {
            eprintln!("[hello-tauri] setup enter");
            use tauri::Manager;
            if let Some(w) = app.get_webview_window("main") {
                eprintln!("[hello-tauri] window label={}", w.label());
                match w.url() {
                    Ok(u) => eprintln!("[hello-tauri] window url={}", u),
                    Err(e) => eprintln!("[hello-tauri] url err={:?}", e),
                }
                #[cfg(debug_assertions)]
                w.open_devtools();
            } else {
                eprintln!("[hello-tauri] NO main window");
            }
            eprintln!("[hello-tauri] setup done");
            Ok(())
        })
        .run(tauri::generate_context!())
        .expect("error while running tauri");
}
