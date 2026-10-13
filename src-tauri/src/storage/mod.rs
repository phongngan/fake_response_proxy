//! SQLite-backed history.
//! - `requests` ring buffer of up to 1000 metadata rows.
//! - `messages` ring buffer of up to 100 full raw req/res pairs.

use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use parking_lot::Mutex;
use rusqlite::{params, Connection};
use serde::Serialize;
use std::path::Path;
use std::sync::Arc;

pub const MAX_REQUESTS: i64 = 1000;
pub const MAX_FULL_MESSAGES: i64 = 100;

#[derive(Debug, Clone, Serialize)]
pub struct RequestRow {
    pub id: i64,
    pub ts: DateTime<Utc>,
    /// ID of the listener that received this request. Empty for old rows
    /// recorded before the column existed.
    #[serde(default)]
    pub listener_id: String,
    pub scheme: String,
    pub method: String,
    pub host: String,
    pub path: String,
    pub status: u16,
    pub rule_id: Option<i64>,
    pub source: String,
    pub duration_ms: i64,
    pub has_full: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct FullMessage {
    pub id: i64,
    pub request_id: i64,
    pub ts: DateTime<Utc>,
    pub request_raw: String,
    pub response_raw: String,
}

#[derive(Clone)]
pub struct History {
    conn: Arc<Mutex<Connection>>,
}

impl History {
    pub fn open(db_path: &Path) -> Result<Self> {
        if let Some(p) = db_path.parent() {
            std::fs::create_dir_all(p).ok();
        }
        let conn = Connection::open(db_path).context("open sqlite")?;
        conn.execute_batch(
            r#"
            PRAGMA journal_mode = WAL;
            PRAGMA synchronous = NORMAL;
            CREATE TABLE IF NOT EXISTS requests (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ts TEXT NOT NULL,
                scheme TEXT NOT NULL,
                method TEXT NOT NULL,
                host TEXT NOT NULL,
                path TEXT NOT NULL,
                status INTEGER NOT NULL,
                rule_id INTEGER,
                source TEXT NOT NULL,
                duration_ms INTEGER NOT NULL,
                has_full INTEGER NOT NULL DEFAULT 0
            );
            CREATE INDEX IF NOT EXISTS idx_req_ts ON requests(ts DESC);
            CREATE TABLE IF NOT EXISTS messages (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                request_id INTEGER NOT NULL,
                ts TEXT NOT NULL,
                request_raw TEXT NOT NULL,
                response_raw TEXT NOT NULL,
                FOREIGN KEY(request_id) REFERENCES requests(id) ON DELETE CASCADE
            );
            CREATE INDEX IF NOT EXISTS idx_msg_ts ON messages(ts DESC);
            "#,
        )
        .context("init schema")?;
        // Migration: add listener_id column to existing DBs. Ignore "duplicate
        // column" error if already present.
        let _ = conn.execute(
            "ALTER TABLE requests ADD COLUMN listener_id TEXT NOT NULL DEFAULT ''",
            [],
        );
        Ok(Self {
            conn: Arc::new(Mutex::new(conn)),
        })
    }

    /// Record a request. Returns the inserted id.
    pub fn record(
        &self,
        req: &RequestRow,
        full: Option<(&str, &str)>, // (request_raw, response_raw)
    ) -> Result<i64> {
        let mut conn = self.conn.lock();
        let tx = conn.transaction()?;
        tx.execute(
            "INSERT INTO requests (ts, listener_id, scheme, method, host, path, status, rule_id, source, duration_ms, has_full)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
            params![
                req.ts.to_rfc3339(),
                req.listener_id,
                req.scheme,
                req.method,
                req.host,
                req.path,
                req.status as i64,
                req.rule_id,
                req.source,
                req.duration_ms,
                full.is_some() as i64,
            ],
        )?;
        let id = tx.last_insert_rowid();

        if let Some((rreq, rres)) = full {
            tx.execute(
                "INSERT INTO messages (request_id, ts, request_raw, response_raw) VALUES (?1, ?2, ?3, ?4)",
                params![id, req.ts.to_rfc3339(), rreq, rres],
            )?;
        }

        // Trim ring buffers.
        tx.execute(
            "DELETE FROM messages WHERE id IN (
                SELECT id FROM messages ORDER BY id DESC LIMIT -1 OFFSET ?1
             )",
            params![MAX_FULL_MESSAGES],
        )?;
        tx.execute(
            "DELETE FROM requests WHERE id IN (
                SELECT id FROM requests ORDER BY id DESC LIMIT -1 OFFSET ?1
             )",
            params![MAX_REQUESTS],
        )?;

        tx.commit()?;
        Ok(id)
    }

    pub fn list_requests(&self, limit: i64) -> Result<Vec<RequestRow>> {
        let conn = self.conn.lock();
        let mut stmt = conn.prepare(
            "SELECT id, ts, listener_id, scheme, method, host, path, status, rule_id, source, duration_ms, has_full
             FROM requests ORDER BY id DESC LIMIT ?1",
        )?;
        let rows = stmt
            .query_map(params![limit], |r| {
                let ts: String = r.get(1)?;
                Ok(RequestRow {
                    id: r.get(0)?,
                    ts: DateTime::parse_from_rfc3339(&ts)
                        .map(|d| d.with_timezone(&Utc))
                        .unwrap_or_else(|_| Utc::now()),
                    listener_id: r.get(2)?,
                    scheme: r.get(3)?,
                    method: r.get(4)?,
                    host: r.get(5)?,
                    path: r.get(6)?,
                    status: r.get::<_, i64>(7)? as u16,
                    rule_id: r.get(8)?,
                    source: r.get(9)?,
                    duration_ms: r.get(10)?,
                    has_full: r.get::<_, i64>(11)? != 0,
                })
            })?
            .collect::<std::result::Result<Vec<_>, _>>()?;
        Ok(rows)
    }

    pub fn get_full(&self, request_id: i64) -> Result<Option<FullMessage>> {
        let conn = self.conn.lock();
        let mut stmt = conn.prepare(
            "SELECT id, request_id, ts, request_raw, response_raw FROM messages WHERE request_id = ?1",
        )?;
        let mut rows = stmt.query(params![request_id])?;
        if let Some(r) = rows.next()? {
            let ts: String = r.get(2)?;
            Ok(Some(FullMessage {
                id: r.get(0)?,
                request_id: r.get(1)?,
                ts: DateTime::parse_from_rfc3339(&ts)
                    .map(|d| d.with_timezone(&Utc))
                    .unwrap_or_else(|_| Utc::now()),
                request_raw: r.get(3)?,
                response_raw: r.get(4)?,
            }))
        } else {
            Ok(None)
        }
    }

    pub fn clear(&self) -> Result<()> {
        let conn = self.conn.lock();
        conn.execute_batch("DELETE FROM messages; DELETE FROM requests;")?;
        Ok(())
    }
}
