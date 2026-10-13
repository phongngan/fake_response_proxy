use crate::divert::redirector::RedirectRule;
use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Scheme {
    Http,
    Https,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ListenerConfig {
    pub id: String,
    pub enabled: bool,
    pub scheme: Scheme,
    pub bind: String,
    pub port: u16,
}

impl ListenerConfig {
    pub fn addr(&self) -> String {
        format!("{}:{}", self.bind, self.port)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppConfig {
    pub listeners: Vec<ListenerConfig>,
    pub auto_start_server: bool,
    pub python_path: Option<String>,
    #[serde(default)]
    pub redirects: Vec<RedirectRule>,
}

impl Default for AppConfig {
    fn default() -> Self {
        Self {
            listeners: default_listeners(),
            auto_start_server: false,
            python_path: None,
            redirects: Vec::new(),
        }
    }
}

fn default_listeners() -> Vec<ListenerConfig> {
    vec![
        ListenerConfig {
            id: "http-8080".into(),
            enabled: true,
            scheme: Scheme::Http,
            bind: "127.0.0.1".into(),
            port: 8080,
        },
        ListenerConfig {
            id: "https-8443".into(),
            enabled: true,
            scheme: Scheme::Https,
            bind: "127.0.0.1".into(),
            port: 8443,
        },
    ]
}

impl AppConfig {
    pub fn load_or_default(path: &Path) -> Self {
        let mut cfg: AppConfig = fs::read_to_string(path)
            .ok()
            .and_then(|s| serde_json::from_str(&s).ok())
            .unwrap_or_default();
        if cfg.listeners.is_empty() {
            cfg.listeners = default_listeners();
        }
        cfg
    }

    pub fn save(&self, path: &Path) -> Result<()> {
        if let Some(p) = path.parent() {
            fs::create_dir_all(p).ok();
        }
        let s = serde_json::to_string_pretty(self)?;
        fs::write(path, s).context("write config")?;
        Ok(())
    }
}

pub fn data_dir() -> PathBuf {
    let base = dirs::data_dir().unwrap_or_else(|| PathBuf::from("."));
    base.join("FakeResponseProxy")
}
pub fn config_path() -> PathBuf {
    data_dir().join("config.json")
}
pub fn rules_path() -> PathBuf {
    data_dir().join("rules.json")
}
pub fn db_path() -> PathBuf {
    data_dir().join("history.sqlite")
}
pub fn ca_dir() -> PathBuf {
    data_dir().join("ca")
}
