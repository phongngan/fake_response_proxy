//! Tauri commands exposed to the frontend.

use crate::ca::install;
use crate::config::{self, AppConfig};
use crate::divert::bootstrap as divert_bootstrap;
use crate::divert::probe::{ProbeRequest, ProbeStatus};
use crate::divert::redirector::{RedirectRule, RedirectStatus};
use crate::proxy::{ListenerStatus, ProxyDeps};
use crate::rules::Rule;
use crate::state::AppState;
use crate::storage::{FullMessage, RequestRow};
use serde::Serialize;
use std::path::PathBuf;
use tauri::State;

fn err<E: std::fmt::Display>(e: E) -> String {
    format!("{e:#}")
}

#[derive(Serialize)]
pub struct StatusDto {
    pub listeners: Vec<ListenerStatus>,
    pub is_elevated: bool,
    pub ca_cert_path: String,
}

#[tauri::command]
pub async fn get_status(state: State<'_, AppState>) -> Result<StatusDto, String> {
    Ok(StatusDto {
        listeners: state.proxy.status(),
        is_elevated: install::is_elevated(),
        ca_cert_path: state.ca.ca_cert_path().to_string_lossy().to_string(),
    })
}

#[tauri::command]
pub async fn get_config(state: State<'_, AppState>) -> Result<AppConfig, String> {
    Ok(state.config.read().clone())
}

#[tauri::command]
pub async fn save_config(
    state: State<'_, AppState>,
    mut config: AppConfig,
) -> Result<AppConfig, String> {
    // Redirects are managed via the dedicated `upsert_redirect_rule` /
    // `delete_redirect_rule` commands. Preserve whatever is currently in
    // memory regardless of what the caller sent, so a Settings save that
    // forgets the `redirects` field never wipes the user's rules.
    config.redirects = state.config.read().redirects.clone();
    {
        let mut c = state.config.write();
        *c = config.clone();
    }
    config.save(&config::config_path()).map_err(err)?;
    Ok(config)
}

#[tauri::command]
pub async fn list_rules(state: State<'_, AppState>) -> Result<Vec<Rule>, String> {
    Ok(state.rules.list())
}

#[tauri::command]
pub async fn upsert_rule(state: State<'_, AppState>, rule: Rule) -> Result<Rule, String> {
    state.rules.upsert(rule).map_err(err)
}

#[tauri::command]
pub async fn delete_rule(state: State<'_, AppState>, id: i64) -> Result<(), String> {
    state.rules.delete(id).map_err(err)
}

#[tauri::command]
pub async fn list_history(
    state: State<'_, AppState>,
    limit: Option<i64>,
) -> Result<Vec<RequestRow>, String> {
    state.history.list_requests(limit.unwrap_or(200)).map_err(err)
}

#[tauri::command]
pub async fn get_full_message(
    state: State<'_, AppState>,
    request_id: i64,
) -> Result<Option<FullMessage>, String> {
    state.history.get_full(request_id).map_err(err)
}

#[tauri::command]
pub async fn clear_history(state: State<'_, AppState>) -> Result<(), String> {
    state.history.clear().map_err(err)
}

#[tauri::command]
pub async fn start_server(state: State<'_, AppState>) -> Result<StatusDto, String> {
    let cfg = state.config.read().clone();
    let deps = ProxyDeps {
        rules: state.rules.clone(),
        history: state.history.clone(),
        ca: state.ca.clone(),
    };
    state.proxy.stop_all();
    for lc in cfg.listeners.iter().filter(|l| l.enabled) {
        state.proxy.start_one(lc, deps.clone()).await;
    }
    get_status(state).await
}

#[tauri::command]
pub async fn stop_server(state: State<'_, AppState>) -> Result<StatusDto, String> {
    state.proxy.stop_all();
    get_status(state).await
}

#[tauri::command]
pub async fn start_listener(
    state: State<'_, AppState>,
    id: String,
) -> Result<StatusDto, String> {
    let cfg = state.config.read().clone();
    let deps = ProxyDeps {
        rules: state.rules.clone(),
        history: state.history.clone(),
        ca: state.ca.clone(),
    };
    if let Some(lc) = cfg.listeners.iter().find(|l| l.id == id) {
        state.proxy.start_one(lc, deps).await;
    } else {
        return Err(format!("listener id not found: {id}"));
    }
    get_status(state).await
}

#[tauri::command]
pub async fn stop_listener(state: State<'_, AppState>, id: String) -> Result<StatusDto, String> {
    state.proxy.stop_one(&id);
    get_status(state).await
}

#[tauri::command]
pub async fn install_ca(state: State<'_, AppState>, system_wide: bool) -> Result<String, String> {
    let path = state.ca.ca_cert_path();
    if system_wide {
        if !install::is_elevated() {
            return Err("This app must be run as Administrator to install into the system trust store. Use 'user' install or relaunch elevated.".into());
        }
        install::install_to_system_root(&path).map_err(err)?;
        Ok("Installed to LocalMachine\\Root".into())
    } else {
        install::install_to_user_root(&path).map_err(err)?;
        Ok("Installed to CurrentUser\\Root".into())
    }
}

#[tauri::command]
pub async fn uninstall_ca(state: State<'_, AppState>, system_wide: bool) -> Result<String, String> {
    let _ = state;
    let cn = "Fake Response Proxy Root CA";
    if system_wide {
        install::uninstall_system_root(cn).map_err(err)?;
        Ok("Removed from LocalMachine\\Root".into())
    } else {
        install::uninstall_user_root(cn).map_err(err)?;
        Ok("Removed from CurrentUser\\Root".into())
    }
}

#[tauri::command]
pub async fn export_ca(state: State<'_, AppState>) -> Result<String, String> {
    Ok(state.ca.ca_cert_pem().to_string())
}

#[derive(Serialize)]
pub struct CaInstallState {
    pub thumbprint: String,
    pub common_name: String,
    pub installed_user: bool,
    pub installed_system: bool,
}

#[tauri::command]
pub async fn get_ca_install_state(
    state: State<'_, AppState>,
) -> Result<CaInstallState, String> {
    let thumb = state.ca.sha1_thumbprint();
    let cn = crate::ca::CertAuthority::common_name().to_string();
    let thumb_clone = thumb.clone();
    let (user, system) = tokio::task::spawn_blocking(move || {
        let user = install::is_in_user_root(&thumb_clone);
        let system = install::is_in_system_root(&thumb_clone);
        (user, system)
    })
    .await
    .map_err(err)?;
    Ok(CaInstallState {
        thumbprint: thumb,
        common_name: cn,
        installed_user: user,
        installed_system: system,
    })
}

#[tauri::command]
pub async fn data_dir_path() -> Result<PathBuf, String> {
    Ok(config::data_dir())
}

#[tauri::command]
pub async fn read_text_file(path: String) -> Result<String, String> {
    tokio::fs::read_to_string(&path).await.map_err(err)
}

// --- Redirect (WinDivert) commands --------------------------------------

#[tauri::command]
pub async fn get_redirect_status(
    state: State<'_, AppState>,
) -> Result<RedirectStatus, String> {
    Ok(state.redirector.status())
}

/// Trigger WinDivert download/extract without enabling any rule.
/// Useful for an explicit "Install WinDivert" button.
#[tauri::command]
pub async fn install_windivert(
    state: State<'_, AppState>,
) -> Result<RedirectStatus, String> {
    if !install::is_elevated() {
        return Err("Administrator required to install the WinDivert driver.".into());
    }
    let redirector = state.redirector.clone();
    tokio::task::spawn_blocking(move || redirector.ensure_ready())
        .await
        .map_err(err)?
        .map_err(err)?;
    Ok(state.redirector.status())
}

#[tauri::command]
pub async fn list_redirect_rules(
    state: State<'_, AppState>,
) -> Result<Vec<RedirectRule>, String> {
    Ok(state.config.read().redirects.clone())
}

/// Insert or update a redirect rule (matched by id). Persists the config.
/// Does NOT start the rule — call `start_redirect_rule` for that.
#[tauri::command]
pub async fn upsert_redirect_rule(
    state: State<'_, AppState>,
    rule: RedirectRule,
) -> Result<RedirectRule, String> {
    let mut cfg = state.config.read().clone();
    if let Some(existing) = cfg.redirects.iter_mut().find(|r| r.id == rule.id) {
        *existing = rule.clone();
    } else {
        cfg.redirects.push(rule.clone());
    }
    {
        let mut w = state.config.write();
        *w = cfg.clone();
    }
    cfg.save(&config::config_path()).map_err(err)?;
    Ok(rule)
}

#[tauri::command]
pub async fn delete_redirect_rule(
    state: State<'_, AppState>,
    id: String,
) -> Result<(), String> {
    state.redirector.stop_rule(&id);
    let mut cfg = state.config.read().clone();
    cfg.redirects.retain(|r| r.id != id);
    {
        let mut w = state.config.write();
        *w = cfg.clone();
    }
    cfg.save(&config::config_path()).map_err(err)
}

#[tauri::command]
pub async fn start_redirect_rule(
    state: State<'_, AppState>,
    id: String,
) -> Result<RedirectStatus, String> {
    if !install::is_elevated() {
        return Err(
            "Administrator required for traffic redirection. Click 'Restart as Administrator'."
                .into(),
        );
    }
    let rule = state
        .config
        .read()
        .redirects
        .iter()
        .find(|r| r.id == id)
        .cloned()
        .ok_or_else(|| format!("redirect rule not found: {id}"))?;
    let redirector = state.redirector.clone();
    tokio::task::spawn_blocking(move || redirector.start_rule(&rule))
        .await
        .map_err(err)?
        .map_err(err)?;
    Ok(state.redirector.status())
}

#[tauri::command]
pub async fn stop_redirect_rule(
    state: State<'_, AppState>,
    id: String,
) -> Result<RedirectStatus, String> {
    let redirector = state.redirector.clone();
    let id_owned = id.clone();
    let _ = tokio::task::spawn_blocking(move || {
        redirector.stop_rule(&id_owned);
    })
    .await;
    Ok(state.redirector.status())
}

/// Relaunch the app under UAC. The current (unelevated) process exits on
/// success — the front-end won't get a reply because the window goes away.
#[tauri::command]
pub async fn request_admin_relaunch(
    app: tauri::AppHandle,
) -> Result<(), String> {
    divert_bootstrap::relaunch_elevated().map_err(err)?;
    // Give the new process a moment to start, then exit ourselves.
    tokio::time::sleep(std::time::Duration::from_millis(300)).await;
    app.exit(0);
    Ok(())
}

// --- Process probe commands ---------------------------------------------

#[tauri::command]
pub async fn probe_status(state: State<'_, AppState>) -> Result<ProbeStatus, String> {
    Ok(state.prober.status())
}

#[tauri::command]
pub async fn start_probe(
    state: State<'_, AppState>,
    request: ProbeRequest,
) -> Result<ProbeStatus, String> {
    if !install::is_elevated() {
        return Err(
            "Administrator required for FLOW-layer probing (WinDivert driver). \
             Click 'Restart as Administrator' on the Redirect tab."
                .into(),
        );
    }
    let prober = state.prober.clone();
    let redirector = state.redirector.clone();
    tokio::task::spawn_blocking(move || prober.start(request, &redirector))
        .await
        .map_err(err)?
        .map_err(err)?;
    Ok(state.prober.status())
}

#[tauri::command]
pub async fn stop_probe(state: State<'_, AppState>) -> Result<ProbeStatus, String> {
    let prober = state.prober.clone();
    let _ = tokio::task::spawn_blocking(move || prober.stop()).await;
    Ok(state.prober.status())
}

#[tauri::command]
pub async fn clear_probe_hits(state: State<'_, AppState>) -> Result<ProbeStatus, String> {
    state.prober.clear_hits();
    Ok(state.prober.status())
}
