//! Rule definitions, storage, and matching.

use anyhow::{Context, Result};
use parking_lot::RwLock;
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::PathBuf;
use std::sync::Arc;

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case", tag = "kind")]
pub enum ResponseSource {
    /// Raw HTTP response stored inline.
    #[default]
    None,
    RawText {
        raw: String,
    },
    File {
        path: String,
    },
    Script {
        /// Path to python interpreter, optional.
        python: Option<String>,
        /// Path to .py script file.
        script: String,
        /// Extra args passed before the temp request file path.
        args: Vec<String>,
    },
    /// Forward the incoming request to another host:port and return the
    /// upstream response back to the client. Useful for piping traffic into
    /// an interception proxy such as Burp Suite (configure Burp as an
    /// invisible proxy listening on the given target).
    Forward {
        /// Target as `host:port` (e.g. `127.0.0.1:8080`).
        target: String,
        /// If true, rewrite the request line into absolute form
        /// (`GET http://host/path HTTP/1.1`) so the target can act as an
        /// explicit HTTP proxy. Default false = invisible-proxy style.
        #[serde(default)]
        proxy_style: bool,
        /// Whether to use TLS when talking to the target. `Auto` (default)
        /// mirrors the inbound scheme — TLS for HTTPS, plain for HTTP — so
        /// Burp sees the request as HTTPS when it actually was HTTPS.
        #[serde(default)]
        tls: ForwardTlsMode,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum ForwardTlsMode {
    /// Mirror the inbound scheme: TLS if inbound was HTTPS, plain otherwise.
    #[default]
    Auto,
    /// Always connect to the target over plain HTTP.
    Off,
    /// Always establish a TLS connection to the target. SNI is set to the
    /// original Host (so Burp's invisible HTTPS proxy mints a matching leaf
    /// cert). Certificate verification is skipped on the client side.
    On,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Rule {
    pub id: i64,
    pub name: String,
    pub enabled: bool,
    /// Which listener this rule applies to. Empty string = all listeners
    /// (backwards-compatible with rules saved before this field existed).
    #[serde(default)]
    pub listener_id: String,
    /// Fallback rule: only considered when no non-default rule matches.
    /// host/method/path_regex are ignored for default rules.
    #[serde(default)]
    pub is_default: bool,
    /// Match by exact host (case-insensitive). Empty = any.
    pub host: String,
    /// Match by HTTP method, e.g. "GET". Empty = any.
    pub method: String,
    /// Regex to match against path+query. Empty = any.
    pub path_regex: String,
    pub response: ResponseSource,
}

impl Default for Rule {
    fn default() -> Self {
        Self {
            id: 0,
            name: "New rule".into(),
            enabled: true,
            listener_id: String::new(),
            is_default: false,
            host: String::new(),
            method: String::new(),
            path_regex: String::new(),
            response: ResponseSource::None,
        }
    }
}

#[derive(Clone)]
pub struct RuleStore {
    path: PathBuf,
    inner: Arc<RwLock<RuleSet>>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
struct RuleSet {
    next_id: i64,
    rules: Vec<Rule>,
}

impl RuleStore {
    pub fn load_or_default(path: PathBuf) -> Result<Self> {
        let set = if path.exists() {
            let txt = fs::read_to_string(&path).context("read rules.json")?;
            serde_json::from_str::<RuleSet>(&txt).unwrap_or_default()
        } else {
            RuleSet::default()
        };
        Ok(Self {
            path,
            inner: Arc::new(RwLock::new(set)),
        })
    }

    fn persist(&self) -> Result<()> {
        let s = self.inner.read();
        let json = serde_json::to_string_pretty(&*s)?;
        if let Some(p) = self.path.parent() {
            fs::create_dir_all(p).ok();
        }
        fs::write(&self.path, json).context("write rules.json")?;
        Ok(())
    }

    pub fn list(&self) -> Vec<Rule> {
        self.inner.read().rules.clone()
    }

    pub fn upsert(&self, mut rule: Rule) -> Result<Rule> {
        let mut s = self.inner.write();
        if rule.id == 0 {
            s.next_id += 1;
            rule.id = s.next_id;
            s.rules.push(rule.clone());
        } else if let Some(existing) = s.rules.iter_mut().find(|r| r.id == rule.id) {
            *existing = rule.clone();
        } else {
            s.rules.push(rule.clone());
        }
        drop(s);
        self.persist()?;
        Ok(rule)
    }

    pub fn delete(&self, id: i64) -> Result<()> {
        {
            let mut s = self.inner.write();
            s.rules.retain(|r| r.id != id);
        }
        self.persist()
    }

    /// Find the first enabled rule that matches.
    /// `listener_id` is the ID of the listener that received the request.
    /// Only rules scoped to that listener (or with empty `listener_id` = all)
    /// are considered.
    ///
    /// Two-pass matching:
    /// 1. First pass — find the first non-default enabled rule whose
    ///    host/method/path-regex all match.
    /// 2. Fallback — if nothing matched, return the first enabled default rule
    ///    in scope (host/method/path-regex are ignored on default rules).
    pub fn r#match(
        &self,
        listener_id: &str,
        host: &str,
        method: &str,
        path: &str,
    ) -> Option<Rule> {
        let s = self.inner.read();
        // Pass 1: regular (non-default) rules.
        for r in &s.rules {
            if !r.enabled || r.is_default {
                continue;
            }
            if !rule_in_scope(r, listener_id) {
                continue;
            }
            if !r.host.is_empty() && !r.host.eq_ignore_ascii_case(host) {
                continue;
            }
            if !r.method.is_empty() && !r.method.eq_ignore_ascii_case(method) {
                continue;
            }
            if !r.path_regex.is_empty() {
                let re = match Regex::new(&r.path_regex) {
                    Ok(re) => re,
                    Err(_) => continue,
                };
                if !re.is_match(path) {
                    continue;
                }
            }
            return Some(r.clone());
        }
        // Pass 2: default fallback. Prefer a listener-scoped default over a
        // global ("all listeners") default.
        let mut global_default: Option<Rule> = None;
        for r in &s.rules {
            if !r.enabled || !r.is_default {
                continue;
            }
            if r.listener_id == listener_id {
                return Some(r.clone());
            }
            if r.listener_id.is_empty() && global_default.is_none() {
                global_default = Some(r.clone());
            }
        }
        global_default
    }
}

fn rule_in_scope(r: &Rule, listener_id: &str) -> bool {
    r.listener_id.is_empty() || r.listener_id == listener_id
}
