//! HTTP/HTTPS listeners. Each accepted connection is parsed at the byte
//! level (no hyper on the inbound side), matched against the active rule
//! set, and a canned response is returned verbatim. Going raw is necessary
//! because hyper rewrites headers (lowercases names, rebuilds the status
//! line, manages Connection/Upgrade itself) — strict clients like MT5
//! reject those altered responses. Burp Suite works for the same reason:
//! it writes the upstream bytes through unmodified.

use crate::proxy::tls::DynamicResolver;
use crate::proxy::ProxyDeps;
use crate::response::{self, ParsedResponse};
use crate::rules::{ForwardTlsMode, ResponseSource};
use crate::storage::RequestRow;
use anyhow::{Context, Result};
use bytes::Bytes;
use chrono::Utc;
use rustls::ServerConfig;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Instant;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::sync::oneshot;

const MAX_REQUEST_HEADER_BYTES: usize = 64 * 1024;
const MAX_REQUEST_BODY_BYTES: usize = 64 * 1024 * 1024;

pub async fn serve_http(
    listener_id: String,
    addr: SocketAddr,
    deps: ProxyDeps,
    stop: oneshot::Receiver<()>,
) -> Result<()> {
    let listener = TcpListener::bind(addr)
        .await
        .with_context(|| format!("bind HTTP {addr}"))?;
    tracing::info!("HTTP {listener_id} listening on {addr}");

    tokio::spawn(async move {
        let mut stop = stop;
        loop {
            tokio::select! {
                _ = &mut stop => {
                    tracing::info!("HTTP {listener_id} stopping");
                    break;
                }
                accept = listener.accept() => {
                    match accept {
                        Ok((stream, peer)) => {
                            let deps = deps.clone();
                            let lid = listener_id.clone();
                            tokio::spawn(async move {
                                if let Err(e) = serve_one_plain(stream, peer, deps, lid).await {
                                    tracing::debug!("conn err {peer}: {e:#}");
                                }
                            });
                        }
                        Err(e) => {
                            tracing::warn!("accept err: {e}");
                        }
                    }
                }
            }
        }
    });
    Ok(())
}

pub async fn serve_https(
    listener_id: String,
    addr: SocketAddr,
    deps: ProxyDeps,
    stop: oneshot::Receiver<()>,
) -> Result<()> {
    let _ = rustls::crypto::ring::default_provider().install_default();

    let resolver = Arc::new(DynamicResolver::new(deps.ca.clone()));
    // Force TLS 1.2 only. Strict clients (MT5) reject TLS 1.3 connections
    // from this proxy with error 1003 even when HTTP headers are byte-
    // identical to Burp. Burp negotiates TLS 1.2 by default, so we mirror
    // that. The schannel "remote party requests renegotiation" curl logs
    // we kept seeing on both sides were the TLS 1.3 NewSessionTicket
    // post-handshake message being mislabelled — pinning to 1.2 eliminates
    // that whole code path.
    let mut tls_config = ServerConfig::builder_with_protocol_versions(&[&rustls::version::TLS12])
        .with_no_client_auth()
        .with_cert_resolver(resolver);
    // Disable session resumption — keeps each handshake fully fresh and
    // avoids any session-ticket back-and-forth that might confuse the
    // client.
    tls_config.session_storage = Arc::new(rustls::server::NoServerSessionStorage {});
    let tls_config = Arc::new(tls_config);
    let acceptor = tokio_rustls::TlsAcceptor::from(tls_config);

    let listener = TcpListener::bind(addr)
        .await
        .with_context(|| format!("bind HTTPS {addr}"))?;
    tracing::info!("HTTPS {listener_id} listening on {addr}");

    tokio::spawn(async move {
        let mut stop = stop;
        loop {
            tokio::select! {
                _ = &mut stop => {
                    tracing::info!("HTTPS {listener_id} stopping");
                    break;
                }
                accept = listener.accept() => {
                    match accept {
                        Ok((tcp, peer)) => {
                            let acceptor = acceptor.clone();
                            let deps = deps.clone();
                            let lid = listener_id.clone();
                            tokio::spawn(async move {
                                match acceptor.accept(tcp).await {
                                    Ok(tls) => {
                                        if let Err(e) = serve_one_tls(tls, peer, deps, lid).await {
                                            tracing::debug!("tls conn err {peer}: {e:#}");
                                        }
                                    }
                                    Err(e) => {
                                        tracing::debug!("tls handshake err {peer}: {e}");
                                    }
                                }
                            });
                        }
                        Err(e) => tracing::warn!("accept err: {e}"),
                    }
                }
            }
        }
    });
    Ok(())
}

async fn serve_one_plain(
    mut stream: tokio::net::TcpStream,
    peer: SocketAddr,
    deps: ProxyDeps,
    listener_id: String,
) -> Result<()> {
    let resp_bytes = read_and_handle(&mut stream, peer, &deps, &listener_id, "http").await?;
    stream
        .write_all(&resp_bytes)
        .await
        .context("write plain response")?;
    let _ = stream.flush().await;
    // Half-close write side so the client gets an unambiguous EOF.
    let _ = stream.shutdown().await;
    Ok(())
}

async fn serve_one_tls(
    mut stream: tokio_rustls::server::TlsStream<tokio::net::TcpStream>,
    peer: SocketAddr,
    deps: ProxyDeps,
    listener_id: String,
) -> Result<()> {
    let resp_bytes = read_and_handle(&mut stream, peer, &deps, &listener_id, "https").await?;
    stream
        .write_all(&resp_bytes)
        .await
        .context("write tls response")?;
    let _ = stream.flush().await;
    let _ = stream.shutdown().await;
    Ok(())
}

/// Read one HTTP/1.1 request from `stream`, resolve a response, record
/// history, and return the raw response bytes to write back. Pure I/O
/// helper — caller is responsible for the actual write + shutdown.
async fn read_and_handle<S>(
    stream: &mut S,
    _peer: SocketAddr,
    deps: &ProxyDeps,
    listener_id: &str,
    scheme: &str,
) -> Result<Vec<u8>>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let started = Instant::now();

    let req = match read_http_request(stream).await {
        Ok(r) => r,
        Err(e) => {
            tracing::debug!("read request err: {e:#}");
            let pr = ParsedResponse::error_500(&format!("bad request: {e:#}"));
            return Ok(pr.raw_bytes.unwrap_or_else(|| pr.raw.into_bytes()));
        }
    };

    // Match rule (scoped to this listener).
    let matched = deps
        .rules
        .r#match(listener_id, &req.host, &req.method, &req.target);

    let parsed: ParsedResponse = match &matched {
        Some(rule) => match &rule.response {
            ResponseSource::Forward {
                target,
                proxy_style,
                tls,
            } => match forward_request(
                target,
                *proxy_style,
                tls,
                scheme,
                &req,
            )
            .await
            {
                Ok(p) => p,
                Err(e) => {
                    tracing::warn!("rule {} forward error: {e:#}", rule.id);
                    ParsedResponse::error_500(&format!("forward to {target}: {e:#}"))
                }
            },
            other => match response::resolve(other, &req.raw_text()).await {
                Ok(p) => p,
                Err(e) => {
                    tracing::warn!("rule {} response error: {e:#}", rule.id);
                    ParsedResponse::error_500(&format!("{e:#}"))
                }
            },
        },
        None => ParsedResponse::default_404(),
    };

    let duration_ms = started.elapsed().as_millis() as i64;

    // History.
    let row = RequestRow {
        id: 0,
        ts: Utc::now(),
        listener_id: listener_id.to_string(),
        scheme: scheme.into(),
        method: req.method.clone(),
        host: req.host.clone(),
        path: req.target.clone(),
        status: parsed.status.as_u16(),
        rule_id: matched.as_ref().map(|r| r.id),
        source: matched
            .as_ref()
            .map(|r| source_label(&r.response))
            .unwrap_or_else(|| "no_match".into()),
        duration_ms,
        has_full: true,
    };
    let _ = deps
        .history
        .record(&row, Some((&req.raw_text(), &parsed.raw)));

    // Write raw bytes verbatim — preserves Title-Case, header ordering,
    // upstream Connection/Upgrade headers, transfer-encoding, etc.
    let out = parsed
        .raw_bytes
        .unwrap_or_else(|| parsed.raw.into_bytes());
    Ok(out)
}

/// Parsed inbound HTTP request — bytes verbatim plus a handful of fields
/// extracted for rule matching and upstream forwarding.
pub(crate) struct InboundRequest {
    pub method: String,
    pub target: String,
    pub host: String,
    /// Verbatim request bytes including the trailing CRLF CRLF and body.
    pub raw: Vec<u8>,
    /// Offset where the body starts inside `raw`.
    pub body_start: usize,
}

impl InboundRequest {
    fn body(&self) -> &[u8] {
        &self.raw[self.body_start..]
    }
    fn raw_text(&self) -> String {
        String::from_utf8_lossy(&self.raw).into_owned()
    }
}

/// Read a full HTTP/1.1 request from `stream`. Handles Content-Length and
/// chunked transfer-encoding. The body is appended to `raw` so the entire
/// on-wire request can be relayed upstream without reassembly.
async fn read_http_request<R>(stream: &mut R) -> Result<InboundRequest>
where
    R: AsyncRead + Unpin,
{
    let mut buf: Vec<u8> = Vec::with_capacity(2048);
    let mut tmp = [0u8; 4096];
    let header_end: usize;
    loop {
        let n = stream.read(&mut tmp).await.context("read request bytes")?;
        if n == 0 {
            anyhow::bail!("connection closed before request headers complete");
        }
        buf.extend_from_slice(&tmp[..n]);
        if let Some(pos) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
            header_end = pos;
            break;
        }
        if buf.len() > MAX_REQUEST_HEADER_BYTES {
            anyhow::bail!("request headers exceed {MAX_REQUEST_HEADER_BYTES} bytes");
        }
    }

    let head_str =
        std::str::from_utf8(&buf[..header_end]).context("request headers not UTF-8")?;
    let mut lines = head_str.split("\r\n");
    let request_line = lines.next().context("empty request")?;
    let mut sp = request_line.splitn(3, ' ');
    let method = sp.next().context("missing method")?.to_string();
    let target = sp.next().context("missing request target")?.to_string();
    let _version = sp.next().context("missing HTTP version")?;

    let mut host = String::new();
    let mut content_length: Option<usize> = None;
    let mut chunked = false;
    for line in lines {
        if line.is_empty() {
            continue;
        }
        let (k, v) = match line.split_once(':') {
            Some(kv) => kv,
            None => continue,
        };
        let kl = k.trim().to_ascii_lowercase();
        let vt = v.trim();
        if kl == "host" {
            host = vt.to_string();
        } else if kl == "content-length" {
            content_length = vt.parse().ok();
        } else if kl == "transfer-encoding"
            && vt
                .split(',')
                .any(|t| t.trim().eq_ignore_ascii_case("chunked"))
        {
            chunked = true;
        }
    }

    let body_start = header_end + 4;

    if chunked {
        // Read until we've decoded a zero-sized chunk. We keep the raw
        // chunked encoding in `buf` (we don't decode here) so it can be
        // relayed upstream byte-identical.
        let mut cursor = body_start;
        loop {
            // Need at least size-line + CRLF.
            let crlf = loop {
                if let Some(rel) = buf[cursor..].windows(2).position(|w| w == b"\r\n") {
                    break cursor + rel;
                }
                let n = stream
                    .read(&mut tmp)
                    .await
                    .context("read chunked size line")?;
                if n == 0 {
                    anyhow::bail!("EOF while reading chunked size line");
                }
                buf.extend_from_slice(&tmp[..n]);
                if buf.len() > MAX_REQUEST_BODY_BYTES {
                    anyhow::bail!("chunked body exceeds {MAX_REQUEST_BODY_BYTES} bytes");
                }
            };
            let size_line = std::str::from_utf8(&buf[cursor..crlf])
                .context("chunk size line not UTF-8")?;
            let size_str = size_line.split(';').next().unwrap_or("").trim();
            let size = usize::from_str_radix(size_str, 16)
                .with_context(|| format!("invalid chunk size '{size_str}'"))?;
            cursor = crlf + 2;
            // Read `size` bytes + trailing CRLF.
            let need_end = cursor + size + 2;
            while buf.len() < need_end {
                let n = stream
                    .read(&mut tmp)
                    .await
                    .context("read chunk data")?;
                if n == 0 {
                    anyhow::bail!("EOF mid-chunk");
                }
                buf.extend_from_slice(&tmp[..n]);
                if buf.len() > MAX_REQUEST_BODY_BYTES {
                    anyhow::bail!("chunked body exceeds {MAX_REQUEST_BODY_BYTES} bytes");
                }
            }
            cursor = need_end;
            if size == 0 {
                // Optional trailers + final CRLF. For simplicity we don't
                // parse trailers — just stop here. Most clients don't send
                // them.
                break;
            }
        }
    } else if let Some(len) = content_length {
        if len > MAX_REQUEST_BODY_BYTES {
            anyhow::bail!("Content-Length {len} exceeds limit");
        }
        let need = body_start + len;
        while buf.len() < need {
            let n = stream.read(&mut tmp).await.context("read request body")?;
            if n == 0 {
                anyhow::bail!("EOF before Content-Length bytes received");
            }
            buf.extend_from_slice(&tmp[..n]);
        }
        buf.truncate(need);
    } else {
        // No CL, no chunked — body is empty per RFC 7230 §3.3.3 unless the
        // method semantically allows a body (we assume not). Anything past
        // the header terminator is left alone.
    }

    Ok(InboundRequest {
        method,
        target,
        host,
        raw: buf,
        body_start,
    })
}

fn source_label(s: &crate::rules::ResponseSource) -> String {
    match s {
        crate::rules::ResponseSource::None => "none",
        crate::rules::ResponseSource::RawText { .. } => "raw_text",
        crate::rules::ResponseSource::File { .. } => "file",
        crate::rules::ResponseSource::Script { .. } => "script",
        crate::rules::ResponseSource::Forward { .. } => "forward",
    }
    .into()
}

/// Open a connection to `target` (host:port) and relay the inbound request,
/// returning the upstream response verbatim. The response bytes go into
/// `ParsedResponse.raw_bytes` so the caller writes them to the client
/// unchanged, preserving header case/ordering exactly like Burp would.
async fn forward_request(
    target: &str,
    proxy_style: bool,
    tls_mode: &ForwardTlsMode,
    in_scheme: &str,
    req: &InboundRequest,
) -> Result<ParsedResponse> {
    let target = target.trim();
    if target.is_empty() {
        anyhow::bail!("forward target is empty");
    }
    let use_tls = match tls_mode {
        ForwardTlsMode::Auto => in_scheme.eq_ignore_ascii_case("https"),
        ForwardTlsMode::Off => false,
        ForwardTlsMode::On => true,
    };

    // Rebuild the request: rewrite request-line target if proxy_style, strip
    // hop-by-hop headers, and force `Connection: close` so we can read the
    // upstream response until EOF.
    let req_line_target = if proxy_style && !req.host.is_empty() {
        format!("{in_scheme}://{}{}", req.host, req.target)
    } else {
        req.target.clone()
    };

    let head_str = std::str::from_utf8(&req.raw[..req.body_start.saturating_sub(4)])
        .context("inbound request headers not UTF-8")?;
    let mut lines = head_str.split("\r\n");
    let _ = lines.next(); // original request line

    let mut buf: Vec<u8> = Vec::with_capacity(req.raw.len() + 32);
    buf.extend_from_slice(req.method.as_bytes());
    buf.push(b' ');
    buf.extend_from_slice(req_line_target.as_bytes());
    buf.extend_from_slice(b" HTTP/1.1\r\n");

    let mut have_host = false;
    for line in lines {
        if line.is_empty() {
            continue;
        }
        let lname = line
            .split_once(':')
            .map(|(k, _)| k.trim().to_ascii_lowercase())
            .unwrap_or_default();
        if matches!(
            lname.as_str(),
            "connection"
                | "keep-alive"
                | "proxy-authenticate"
                | "proxy-authorization"
                | "te"
                | "trailer"
                | "transfer-encoding"
                | "upgrade"
                | "content-length"
        ) {
            continue;
        }
        if lname == "host" {
            have_host = true;
        }
        buf.extend_from_slice(line.as_bytes());
        buf.extend_from_slice(b"\r\n");
    }
    if !have_host && !req.host.is_empty() {
        buf.extend_from_slice(b"Host: ");
        buf.extend_from_slice(req.host.as_bytes());
        buf.extend_from_slice(b"\r\n");
    }
    let body = req.body();
    buf.extend_from_slice(format!("Content-Length: {}\r\n", body.len()).as_bytes());
    buf.extend_from_slice(b"Connection: close\r\n");
    buf.extend_from_slice(b"\r\n");
    buf.extend_from_slice(body);

    let tcp = tokio::net::TcpStream::connect(target)
        .await
        .with_context(|| format!("connect forward target {target}"))?;

    let resp_buf = if use_tls {
        let server_name = host_without_port(&req.host);
        if server_name.is_empty() {
            anyhow::bail!("cannot derive SNI: inbound Host header is empty");
        }
        let sni = rustls::pki_types::ServerName::try_from(server_name.to_string())
            .context("invalid SNI hostname")?;
        let connector = tokio_rustls::TlsConnector::from(tls_client_config().clone());
        let mut tls = connector
            .connect(sni, tcp)
            .await
            .context("forward TLS handshake")?;
        tls.write_all(&buf)
            .await
            .context("write forward request (tls)")?;
        tls.flush().await.ok();
        let mut resp_buf: Vec<u8> = Vec::with_capacity(8192);
        tls.read_to_end(&mut resp_buf)
            .await
            .context("read forward response (tls)")?;
        resp_buf
    } else {
        let mut stream = tcp;
        stream
            .write_all(&buf)
            .await
            .context("write forward request")?;
        stream.flush().await.ok();
        let mut resp_buf: Vec<u8> = Vec::with_capacity(8192);
        stream
            .read_to_end(&mut resp_buf)
            .await
            .context("read forward response")?;
        resp_buf
    };

    parse_response_bytes(resp_buf)
}

fn host_without_port(host: &str) -> String {
    let host = host.trim();
    if let Some(stripped) = host.strip_prefix('[') {
        if let Some(end) = stripped.find(']') {
            return stripped[..end].to_string();
        }
    }
    if let Some(idx) = host.rfind(':') {
        if host[idx + 1..].chars().all(|c| c.is_ascii_digit()) {
            return host[..idx].to_string();
        }
    }
    host.to_string()
}

fn tls_client_config() -> &'static Arc<rustls::ClientConfig> {
    static CONFIG: once_cell::sync::Lazy<Arc<rustls::ClientConfig>> =
        once_cell::sync::Lazy::new(|| {
            let _ = rustls::crypto::ring::default_provider().install_default();
            let config = rustls::ClientConfig::builder()
                .dangerous()
                .with_custom_certificate_verifier(Arc::new(NoCertVerify))
                .with_no_client_auth();
            Arc::new(config)
        });
    &CONFIG
}

#[derive(Debug)]
struct NoCertVerify;

impl rustls::client::danger::ServerCertVerifier for NoCertVerify {
    fn verify_server_cert(
        &self,
        _end_entity: &rustls::pki_types::CertificateDer<'_>,
        _intermediates: &[rustls::pki_types::CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> std::result::Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }
    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> std::result::Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }
    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> std::result::Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }
    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        use rustls::SignatureScheme::*;
        vec![
            RSA_PKCS1_SHA1,
            ECDSA_SHA1_Legacy,
            RSA_PKCS1_SHA256,
            ECDSA_NISTP256_SHA256,
            RSA_PKCS1_SHA384,
            ECDSA_NISTP384_SHA384,
            RSA_PKCS1_SHA512,
            ECDSA_NISTP521_SHA512,
            RSA_PSS_SHA256,
            RSA_PSS_SHA384,
            RSA_PSS_SHA512,
            ED25519,
            ED448,
        ]
    }
}

/// Parse the upstream response into a `ParsedResponse` while ALSO keeping
/// the exact upstream bytes in `raw_bytes`. The byte copy is what gets
/// shipped to the client — `status`/`headers`/`body` are only used for
/// metadata (history, rule introspection).
fn parse_response_bytes(buf: Vec<u8>) -> Result<ParsedResponse> {
    use http::{HeaderMap, HeaderName, HeaderValue, StatusCode};

    let header_end = buf
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .ok_or_else(|| anyhow::anyhow!("incomplete response: no header terminator"))?;
    let head = std::str::from_utf8(&buf[..header_end])
        .context("response headers are not valid UTF-8")?;
    let body_section = &buf[header_end + 4..];

    let mut lines = head.split("\r\n");
    let status_line = lines
        .next()
        .ok_or_else(|| anyhow::anyhow!("empty response"))?;
    let mut sp = status_line.splitn(3, ' ');
    let _version = sp.next().context("missing HTTP version")?;
    let code: u16 = sp
        .next()
        .context("missing status code")?
        .parse()
        .context("invalid status code")?;
    let status = StatusCode::from_u16(code).context("invalid status code")?;

    let mut headers = HeaderMap::new();
    let mut chunked = false;
    let mut content_length: Option<usize> = None;
    for line in lines {
        if line.is_empty() {
            continue;
        }
        let (k, v) = line
            .split_once(':')
            .ok_or_else(|| anyhow::anyhow!("bad header line: {line}"))?;
        let name = HeaderName::from_bytes(k.trim().as_bytes())
            .with_context(|| format!("bad header name: {k}"))?;
        let value = HeaderValue::from_str(v.trim())
            .with_context(|| format!("bad header value: {v}"))?;
        let ln = name.as_str().to_ascii_lowercase();
        if ln == "transfer-encoding"
            && v.split(',')
                .any(|t| t.trim().eq_ignore_ascii_case("chunked"))
        {
            chunked = true;
        }
        if ln == "content-length" {
            if let Ok(n) = v.trim().parse::<usize>() {
                content_length = Some(n);
            }
        }
        headers.append(name, value);
    }

    let body_bytes: Bytes = if chunked {
        decode_chunked(body_section).context("decode chunked response")?
    } else if let Some(n) = content_length {
        let take = n.min(body_section.len());
        Bytes::copy_from_slice(&body_section[..take])
    } else {
        Bytes::copy_from_slice(body_section)
    };

    let mut raw = String::with_capacity(header_end + 4 + body_bytes.len());
    raw.push_str(&String::from_utf8_lossy(&buf[..header_end + 4]));
    match std::str::from_utf8(&body_bytes) {
        Ok(txt) => raw.push_str(txt),
        Err(_) => raw.push_str(&format!("<binary body, {} bytes>", body_bytes.len())),
    }

    Ok(ParsedResponse {
        status,
        headers,
        body: body_bytes,
        raw,
        // Ship upstream bytes verbatim. This preserves Title-Case headers,
        // original Connection/Upgrade/Keep-Alive values, and any chunked
        // framing — exactly what strict clients expect.
        raw_bytes: Some(buf),
    })
}

fn decode_chunked(data: &[u8]) -> Result<Bytes> {
    let mut out: Vec<u8> = Vec::with_capacity(data.len());
    let mut i = 0usize;
    loop {
        let rel = data
            .get(i..)
            .and_then(|s| s.windows(2).position(|w| w == b"\r\n"))
            .ok_or_else(|| anyhow::anyhow!("chunked: missing CRLF after size"))?;
        let size_line = std::str::from_utf8(&data[i..i + rel])
            .context("chunked: size line not UTF-8")?;
        let size_str = size_line.split(';').next().unwrap_or("").trim();
        let size = usize::from_str_radix(size_str, 16)
            .with_context(|| format!("chunked: bad chunk size '{size_str}'"))?;
        i += rel + 2;
        if size == 0 {
            break;
        }
        if i + size > data.len() {
            anyhow::bail!(
                "chunked: short data ({} bytes left, {} needed)",
                data.len() - i,
                size
            );
        }
        out.extend_from_slice(&data[i..i + size]);
        i += size;
        if data.get(i..i + 2) != Some(b"\r\n") {
            anyhow::bail!("chunked: missing CRLF after chunk data");
        }
        i += 2;
    }
    Ok(Bytes::from(out))
}
