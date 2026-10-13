pub mod ca;
pub mod commands;
pub mod config;
pub mod divert;
pub mod proxy;
pub mod response;
pub mod rules;
pub mod state;
pub mod storage;

use crate::ca::CertAuthority;
use crate::config::AppConfig;
use crate::divert::{bootstrap as divert_bootstrap, Prober, RedirectorHandle};
use crate::proxy::ProxyHandle;
use crate::rules::RuleStore;
use crate::state::AppState;
use crate::storage::History;
use parking_lot::RwLock;
use std::sync::Arc;
use tauri::menu::{MenuBuilder, MenuItemBuilder};
use tauri::tray::TrayIconBuilder;
use tauri::Manager;

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "fake_response_proxy_lib=info,warn".into()),
        )
        .with_target(false)
        .init();

    let cfg_path = config::config_path();
    let cfg = AppConfig::load_or_default(&cfg_path);
    let _ = cfg.save(&cfg_path);

    let rules = RuleStore::load_or_default(config::rules_path()).expect("rules load");
    let history = History::open(&config::db_path()).expect("sqlite open");
    let ca =
        Arc::new(CertAuthority::load_or_create(&config::ca_dir()).expect("CA load/create"));

    let redirector =
        Arc::new(RedirectorHandle::new(divert_bootstrap::default_install_dir()));
    let prober = Arc::new(Prober::new());

    let state = AppState {
        config: Arc::new(RwLock::new(cfg)),
        rules,
        history,
        ca,
        proxy: Arc::new(ProxyHandle::new()),
        redirector,
        prober,
    };

    let auto_start_server = state.config.read().auto_start_server;

    tauri::Builder::default()
        .plugin(tauri_plugin_dialog::init())
        .plugin(tauri_plugin_shell::init())
        .plugin(tauri_plugin_autostart::init(
            tauri_plugin_autostart::MacosLauncher::LaunchAgent,
            None,
        ))
        .manage(state)
        .setup(move |app| {
            if let Some(win) = app.get_webview_window("main") {
                #[cfg(debug_assertions)]
                {
                    win.open_devtools();
                }
                // Tauri 2.11.2 sometimes leaves the window at about:blank when a
                // dev/asset URL is configured. Force navigate as a safety belt.
                #[cfg(debug_assertions)]
                let target = "http://localhost:1420/";
                #[cfg(not(debug_assertions))]
                let target = "tauri://localhost/";
                if win.url().map(|u| u.as_str() == "about:blank").unwrap_or(false) {
                    let win_nav = win.clone();
                    let target = target.to_string();
                    tauri::async_runtime::spawn(async move {
                        tokio::time::sleep(std::time::Duration::from_millis(200)).await;
                        if let Ok(url) = target.parse() {
                            let _ = win_nav.navigate(url);
                        }
                    });
                }

                // Hide-to-tray on close (release only; debug closes normally).
                #[cfg(not(debug_assertions))]
                {
                    let win_clone = win.clone();
                    win.on_window_event(move |e| {
                        if let tauri::WindowEvent::CloseRequested { api, .. } = e {
                            api.prevent_close();
                            let _ = win_clone.hide();
                        }
                    });
                }
            }

            // Tray.
            let show = MenuItemBuilder::with_id("show", "Show window").build(app)?;
            let start = MenuItemBuilder::with_id("start", "Start proxy").build(app)?;
            let stop = MenuItemBuilder::with_id("stop", "Stop proxy").build(app)?;
            let quit = MenuItemBuilder::with_id("quit", "Quit").build(app)?;
            let menu = MenuBuilder::new(app)
                .items(&[&show, &start, &stop, &quit])
                .build()?;
            let mut tray_builder = TrayIconBuilder::with_id("main-tray")
                .menu(&menu)
                .tooltip("Fake Response Proxy");
            if let Some(icon) = app.default_window_icon().cloned() {
                tray_builder = tray_builder.icon(icon);
            }
            let _tray = tray_builder
                .on_menu_event(move |app, event| match event.id().as_ref() {
                    "show" => {
                        if let Some(w) = app.get_webview_window("main") {
                            let _ = w.show();
                            let _ = w.set_focus();
                        }
                    }
                    "start" => {
                        let app = app.clone();
                        tauri::async_runtime::spawn(async move {
                            let s: tauri::State<'_, AppState> = app.state();
                            let _ = commands::start_server(s).await;
                        });
                    }
                    "stop" => {
                        let app = app.clone();
                        tauri::async_runtime::spawn(async move {
                            let s: tauri::State<'_, AppState> = app.state();
                            let _ = commands::stop_server(s).await;
                        });
                    }
                    "quit" => app.exit(0),
                    _ => {}
                })
                .build(app)?;

            if auto_start_server {
                let app = app.handle().clone();
                tauri::async_runtime::spawn(async move {
                    let s: tauri::State<'_, AppState> = app.state();
                    if let Err(e) = commands::start_server(s).await {
                        tracing::warn!("auto-start failed: {e}");
                    }
                });
            }

            // Auto-start enabled redirect rules. Only runs when elevated;
            // otherwise the UI surfaces a "Restart as Administrator" prompt.
            if ca::install::is_elevated() {
                let app = app.handle().clone();
                tauri::async_runtime::spawn(async move {
                    let s: tauri::State<'_, AppState> = app.state();
                    let enabled: Vec<_> = s
                        .config
                        .read()
                        .redirects
                        .iter()
                        .filter(|r| r.enabled)
                        .cloned()
                        .collect();
                    if enabled.is_empty() {
                        return;
                    }
                    let redirector = s.redirector.clone();
                    let res = tokio::task::spawn_blocking(move || {
                        for r in &enabled {
                            if let Err(e) = redirector.start_rule(r) {
                                tracing::warn!(rule_id = %r.id, "redirect auto-start failed: {e}");
                            }
                        }
                    })
                    .await;
                    if let Err(e) = res {
                        tracing::warn!("redirect auto-start join error: {e}");
                    }
                });
            } else {
                let s: tauri::State<'_, AppState> = app.state();
                if s.config.read().redirects.iter().any(|r| r.enabled) {
                    tracing::info!(
                        "enabled redirect rules present but app is not elevated — UI will prompt for UAC relaunch"
                    );
                }
            }
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            commands::get_status,
            commands::get_config,
            commands::save_config,
            commands::list_rules,
            commands::upsert_rule,
            commands::delete_rule,
            commands::list_history,
            commands::get_full_message,
            commands::clear_history,
            commands::start_server,
            commands::stop_server,
            commands::start_listener,
            commands::stop_listener,
            commands::install_ca,
            commands::uninstall_ca,
            commands::export_ca,
            commands::get_ca_install_state,
            commands::data_dir_path,
            commands::read_text_file,
            // Redirect (WinDivert)
            commands::get_redirect_status,
            commands::install_windivert,
            commands::list_redirect_rules,
            commands::upsert_redirect_rule,
            commands::delete_redirect_rule,
            commands::start_redirect_rule,
            commands::stop_redirect_rule,
            commands::request_admin_relaunch,
            // Process probe
            commands::probe_status,
            commands::start_probe,
            commands::stop_probe,
            commands::clear_probe_hits,
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
