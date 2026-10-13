//! Response generation: parse raw HTTP response text into a usable
//! status/headers/body triple; dispatch by ResponseSource.

pub mod script;

use anyhow::{Context, Result};
use bytes::Bytes;
use http::{HeaderMap, HeaderName, HeaderValue, StatusCode};
use std::fs;

use crate::rules::ResponseSource;

#[derive(Debug, Clone)]
pub struct ParsedResponse {
    pub status: StatusCode,
    pub headers: HeaderMap,
    pub body: Bytes,
    /// The original raw text (for history). May be reconstructed.
    pub raw: String,
    /// Exact byte-for-byte response to write back to the client. When set,
    /// the proxy writes these bytes verbatim instead of rebuilding from
    /// status/headers/body — preserving upstream header case, ordering,
    /// `Connection: Upgrade`, transfer-encoding, etc. Required for clients
    /// (e.g. MT5) that validate responses strictly.
    pub raw_bytes: Option<Vec<u8>>,
}

impl ParsedResponse {
    pub fn default_404() -> Self {
        let body = Bytes::from_static(b"404 Not Found (no matching rule)");
        let raw = format!(
            "HTTP/1.1 404 Not Found\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Length: {}\r\n\r\n{}",
            body.len(),
            String::from_utf8_lossy(&body)
        );
        let mut headers = HeaderMap::new();
        headers.insert(
            http::header::CONTENT_TYPE,
            HeaderValue::from_static("text/plain; charset=utf-8"),
        );
        headers.insert(
            http::header::CONTENT_LENGTH,
            HeaderValue::from_str(&body.len().to_string()).unwrap(),
        );
        Self {
            status: StatusCode::NOT_FOUND,
            headers,
            body,
            raw_bytes: Some(raw.as_bytes().to_vec()),
            raw,
        }
    }

    pub fn error_500(msg: &str) -> Self {
        let body = Bytes::from(format!("500 Internal Proxy Error: {msg}"));
        let raw = format!(
            "HTTP/1.1 500 Internal Server Error\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Length: {}\r\n\r\n{}",
            body.len(),
            String::from_utf8_lossy(&body)
        );
        let mut headers = HeaderMap::new();
        headers.insert(
            http::header::CONTENT_TYPE,
            HeaderValue::from_static("text/plain; charset=utf-8"),
        );
        headers.insert(
            http::header::CONTENT_LENGTH,
            HeaderValue::from_str(&body.len().to_string()).unwrap(),
        );
        Self {
            status: StatusCode::INTERNAL_SERVER_ERROR,
            headers,
            body,
            raw_bytes: Some(raw.as_bytes().to_vec()),
            raw,
        }
    }
}

pub async fn resolve(source: &ResponseSource, request_raw: &str) -> Result<ParsedResponse> {
    match source {
        ResponseSource::None => Ok(ParsedResponse::default_404()),
        ResponseSource::RawText { raw } => parse_raw_response(raw),
        ResponseSource::File { path } => {
            let txt = fs::read_to_string(path)
                .with_context(|| format!("read response file: {path}"))?;
            parse_raw_response(&txt)
        }
        ResponseSource::Script {
            python,
            script,
            args,
        } => {
            let raw = script::run(
                python.as_deref(),
                script,
                args.iter().map(String::as_str),
                request_raw,
            )
            .await?;
            parse_raw_response(&raw)
        }
        // Forward is handled directly in proxy::server::handle_request, where
        // we still have the parsed request parts + body to relay upstream.
        ResponseSource::Forward { .. } => {
            anyhow::bail!("forward rules must be handled by the proxy server")
        }
    }
}

/// Parse a raw HTTP/1.1 response text into status/headers/body.
/// Accepts CRLF or LF line endings.
pub fn parse_raw_response(raw: &str) -> Result<ParsedResponse> {
    let normalized = raw.replace("\r\n", "\n");
    let (head, body) = match normalized.find("\n\n") {
        Some(i) => (&normalized[..i], &normalized[i + 2..]),
        None => (normalized.as_str(), ""),
    };
    let mut lines = head.split('\n');
    let status_line = lines
        .next()
        .ok_or_else(|| anyhow::anyhow!("empty response"))?;
    let mut parts = status_line.splitn(3, ' ');
    let _version = parts.next().context("missing HTTP version")?;
    let code: u16 = parts
        .next()
        .context("missing status code")?
        .parse()
        .context("invalid status code")?;
    let status = StatusCode::from_u16(code).context("invalid status code")?;

    let mut headers = HeaderMap::new();
    for line in lines {
        if line.trim().is_empty() {
            continue;
        }
        let (k, v) = line
            .split_once(':')
            .ok_or_else(|| anyhow::anyhow!("bad header line: {line}"))?;
        let name = HeaderName::from_bytes(k.trim().as_bytes())
            .with_context(|| format!("bad header name: {k}"))?;
        let val = HeaderValue::from_str(v.trim())
            .with_context(|| format!("bad header value: {v}"))?;
        headers.append(name, val);
    }

    let body_bytes = Bytes::from(body.as_bytes().to_vec());

    // Ensure Content-Length is consistent with the body we'll send.
    headers.remove(http::header::TRANSFER_ENCODING);
    headers.insert(
        http::header::CONTENT_LENGTH,
        HeaderValue::from_str(&body_bytes.len().to_string()).unwrap(),
    );

    // Rebuild the wire bytes with CRLF line endings + the headers we
    // normalized above (auto-fixed Content-Length, no Transfer-Encoding).
    // This is what the proxy will send to the client verbatim, so we
    // preserve the user's original header case and ordering — `headers`
    // is only kept around for metadata/history.
    let mut wire: Vec<u8> = Vec::with_capacity(raw.len() + 16);
    let mut lines = head.split('\n');
    if let Some(first) = lines.next() {
        wire.extend_from_slice(first.trim_end_matches('\r').as_bytes());
        wire.extend_from_slice(b"\r\n");
    }
    let mut seen_content_length = false;
    let mut seen_transfer_encoding = false;
    for line in lines {
        let line = line.trim_end_matches('\r');
        if line.is_empty() {
            continue;
        }
        let lname = line
            .split_once(':')
            .map(|(k, _)| k.trim().to_ascii_lowercase())
            .unwrap_or_default();
        if lname == "transfer-encoding" {
            seen_transfer_encoding = true;
            continue;
        }
        if lname == "content-length" {
            seen_content_length = true;
            wire.extend_from_slice(b"Content-Length: ");
            wire.extend_from_slice(body_bytes.len().to_string().as_bytes());
            wire.extend_from_slice(b"\r\n");
            continue;
        }
        wire.extend_from_slice(line.as_bytes());
        wire.extend_from_slice(b"\r\n");
    }
    if !seen_content_length {
        wire.extend_from_slice(b"Content-Length: ");
        wire.extend_from_slice(body_bytes.len().to_string().as_bytes());
        wire.extend_from_slice(b"\r\n");
    }
    let _ = seen_transfer_encoding;
    wire.extend_from_slice(b"\r\n");
    wire.extend_from_slice(&body_bytes);

    Ok(ParsedResponse {
        status,
        headers,
        body: body_bytes,
        raw: raw.to_string(),
        raw_bytes: Some(wire),
    })
}
