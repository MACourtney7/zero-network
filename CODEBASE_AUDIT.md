# zero_network Codebase Dump

## FILE: .gitignore
```
.DS_Store
/target
target/
**/*.rs.bk
```

## FILE: Cargo.toml
```toml
[package]
name = "zero_network"
version = "0.1.0"
edition = "2021"

[lib]
crate-type = ["cdylib", "rlib"]

[dependencies]
base64 = "0.22"
hex = "0.4"
serde = { version = "1.0", features = ["derive"] }
serde_json = "1.0"
url = "2.5"
worker = "0.7"
zero_protocol = { path = "../zero_protocol/crates/zero_protocol" }
```

## FILE: src/auth.rs
```rust
//! Authentication and authorization routines for ZeroNetwork.
//! Supports header authentication (`X-Host-Secret`, `Authorization: Bearer <hex>`)
//! and URL query parameter authentication (`?secret=<hex>`).
//! Uses constant-time comparison to protect against timing side-channel attacks.

use crate::durable_object::{HibernatingSocket, HostAttachment};
use crate::handlers::{extract_bearer_token, parse_host_secret, HttpResponse, NetworkError};

/// Extracts the raw secret candidate from headers or query parameters.
/// Preference order:
/// 1. `X-Host-Secret` header
/// 2. `Authorization: Bearer <token>` header
/// 3. `?secret=<token>` or `?host_secret=<token>` query parameter
pub fn extract_secret_from_params(
    x_host_secret: Option<&str>,
    authorization: Option<&str>,
    query_secret: Option<&str>,
) -> Option<String> {
    if let Some(s) = x_host_secret {
        let trimmed = s.trim();
        if !trimmed.is_empty() {
            return Some(trimmed.to_string());
        }
    }
    if let Some(auth) = authorization {
        if let Some(token) = extract_bearer_token(Some(auth)) {
            return Some(token.to_string());
        }
    }
    if let Some(q) = query_secret {
        let trimmed = q.trim();
        if !trimmed.is_empty() {
            return Some(trimmed.to_string());
        }
    }
    None
}

/// Constant-time comparison of two byte slices to prevent timing side-channel attacks.
pub fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

/// Parses and validates a 32-byte secret candidate string (64-char hex or Base64),
/// returning `Ok([u8; 32])` or `Err(NetworkError::Unauthorized)`.
pub fn parse_secret_candidate(raw: &str) -> Result<[u8; 32], NetworkError> {
    parse_host_secret(raw).map_err(|_| NetworkError::Unauthorized)
}

/// Authenticates a host request against an optional expected 32-byte room secret.
///
/// If `secret_candidate` is None, returns `Err(NetworkError::Unauthorized)`.
/// If `secret_candidate` is not valid 32-byte secret (e.g. malformed or invalid hex), returns `Err(NetworkError::Unauthorized)`.
/// If `expected_room_secret` is `Some(expected)`, validates the decoded secret against `expected`
/// using constant-time comparison; on mismatch, returns `Err(NetworkError::Unauthorized)`.
/// On success, returns `Ok([u8; 32])`.
pub fn authenticate_host(
    secret_candidate: Option<&str>,
    expected_room_secret: Option<&[u8; 32]>,
) -> Result<[u8; 32], NetworkError> {
    let raw = secret_candidate.ok_or(NetworkError::Unauthorized)?;
    let parsed = parse_secret_candidate(raw)?;

    if let Some(expected) = expected_room_secret {
        if !constant_time_eq(&parsed, expected) {
            return Err(NetworkError::Unauthorized);
        }
    }

    Ok(parsed)
}

/// Extracts `?secret=<hex>` or `?host_secret=<hex>` from a URL path or query string.
pub fn parse_query_secret(url_or_query: &str) -> Option<String> {
    let query_part = if let Some(idx) = url_or_query.find('?') {
        &url_or_query[idx + 1..]
    } else {
        url_or_query
    };

    for pair in query_part.split('&') {
        let mut parts = pair.splitn(2, '=');
        let key = parts.next()?.trim();
        if key == "secret" || key == "host_secret" {
            let val = parts.next()?.trim();
            if !val.is_empty() {
                return Some(val.to_string());
            }
        }
    }
    None
}

/// Target-independent helper to authenticate host upgrade from URL query parameter.
pub fn process_host_query_upgrade<S: HibernatingSocket>(
    upgrade_header: Option<&str>,
    url_or_query: &str,
    expected_secret: Option<&[u8; 32]>,
    socket: &mut S,
) -> Result<HttpResponse, NetworkError> {
    let secret = parse_query_secret(url_or_query);
    let host_secret = authenticate_host(secret.as_deref(), expected_secret)?;

    match upgrade_header {
        Some(val) if val.trim().eq_ignore_ascii_case("websocket") => {}
        _ => return Err(NetworkError::MissingUpgradeHeader),
    }

    socket
        .attach_host_secret(&HostAttachment::new(host_secret))
        .map_err(NetworkError::SocketError)?;

    Ok(HttpResponse {
        status: 101,
        body: String::new(),
        headers: Vec::new(),
    })
}

/// Comprehensive target-independent host upgrade authentication:
/// Checks X-Host-Secret, Authorization header, and ?secret query param.
pub fn process_host_upgrade_authenticated<S: HibernatingSocket>(
    upgrade_header: Option<&str>,
    x_host_secret: Option<&str>,
    authorization: Option<&str>,
    query_secret: Option<&str>,
    expected_room_secret: Option<&[u8; 32]>,
    socket: &mut S,
) -> Result<HttpResponse, NetworkError> {
    let secret_opt = extract_secret_from_params(x_host_secret, authorization, query_secret);
    let host_secret = authenticate_host(secret_opt.as_deref(), expected_room_secret)?;

    match upgrade_header {
        Some(val) if val.trim().eq_ignore_ascii_case("websocket") => {}
        _ => return Err(NetworkError::MissingUpgradeHeader),
    }

    socket
        .attach_host_secret(&HostAttachment::new(host_secret))
        .map_err(NetworkError::SocketError)?;

    Ok(HttpResponse {
        status: 101,
        body: String::new(),
        headers: Vec::new(),
    })
}

/// Extracts secret candidate from a `worker::Request` by inspecting:
/// 1. `X-Host-Secret` header
/// 2. `Authorization` header (`Bearer <token>` or raw token)
/// 3. Query parameter `?secret=<token>` or `?host_secret=<token>`
pub fn extract_secret_from_request(req: &worker::Request) -> Option<String> {
    if let Ok(Some(s)) = req.headers().get("X-Host-Secret") {
        let trimmed = s.trim();
        if !trimmed.is_empty() {
            return Some(trimmed.to_string());
        }
    }
    if let Ok(Some(auth)) = req.headers().get("Authorization") {
        if let Some(token) = extract_bearer_token(Some(&auth)) {
            return Some(token.to_string());
        }
    }
    if let Ok(url) = req.url() {
        for (k, v) in url.query_pairs() {
            if k == "secret" || k == "host_secret" {
                let trimmed = v.trim();
                if !trimmed.is_empty() {
                    return Some(trimmed.to_string());
                }
            }
        }
    }
    None
}
```

## FILE: src/durable_object.rs
```rust
//! Cloudflare Durable Object with WebSocket Hibernation and ephemeral in-memory invite burn state.

use std::cell::RefCell;
use std::collections::HashSet;

use serde::{Deserialize, Serialize};
use worker::{
    durable_object, wasm_bindgen, DurableObject, Env, Error, Method, Request, Response, Result,
    State, WebSocket, WebSocketIncomingMessage,
};
use zero_protocol::crypto::verify_invite_token;
use zero_protocol::InvitePayload;

use crate::handlers::{
    cors_preflight_response, handle_do_dead_drop, handle_do_host_upgrade_with_secret, handle_do_match,
    handle_do_stage_invite, with_cors, StageInviteRequest,
};

/// Cloudflare Worker environment binding name for the signaling Durable Object namespace.
pub const DEAD_DROP_BINDING: &str = "DEAD_DROP_ROOM";

/// Hibernation tag attached to host WebSockets inside the Durable Object.
pub const HOST_WEBSOCKET_TAG: &str = "host";

/// Maximum number of burned invite UUIDs tracked in memory per room to prevent memory exhaustion DoS.
pub const MAX_BURNED_UUIDS: usize = 4096;

/// Serializable attachment saved to the hibernating host WebSocket via `serialize_attachment()`.
/// Allows the Durable Object to sleep with 0 duration billing and recover the 32-byte `host_secret`
/// in ~3ms when a joiner POSTs to `/drop/:do_id/:invite_uuid`, or serve staged invites for dead-drop matchmaking.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HostAttachment {
    pub host_secret: [u8; 32],
    #[serde(default)]
    pub staged_invite: Option<InvitePayload>,
}

impl HostAttachment {
    pub fn new(host_secret: [u8; 32]) -> Self {
        Self {
            host_secret,
            staged_invite: None,
        }
    }

    pub fn with_staged_invite(host_secret: [u8; 32], staged_invite: InvitePayload) -> Self {
        Self {
            host_secret,
            staged_invite: Some(staged_invite),
        }
    }
}

/// Target-independent abstraction over a hibernating WebSocket supporting attachment serialization
/// and text payload forwarding. Implemented for `worker::WebSocket` and `MockHostSocket`.
pub trait HibernatingSocket {
    /// Serializes and attaches the `HostAttachment` to the underlying socket before hibernation.
    fn attach_host_secret(
        &mut self,
        attachment: &HostAttachment,
    ) -> std::result::Result<(), String>;

    /// Recovers the `HostAttachment` from the hibernating socket upon wakeup.
    fn recover_host_secret(&self) -> std::result::Result<Option<HostAttachment>, String>;

    /// Pipes a serialized JSON payload down the host WebSocket.
    fn send_text(&mut self, payload: &str) -> std::result::Result<(), String>;
}

impl HibernatingSocket for WebSocket {
    fn attach_host_secret(
        &mut self,
        attachment: &HostAttachment,
    ) -> std::result::Result<(), String> {
        self.serialize_attachment(attachment)
            .map_err(|e| e.to_string())
    }

    fn recover_host_secret(&self) -> std::result::Result<Option<HostAttachment>, String> {
        self.deserialize_attachment::<HostAttachment>()
            .map_err(|e| e.to_string())
    }

    fn send_text(&mut self, payload: &str) -> std::result::Result<(), String> {
        self.send_with_str(payload).map_err(|e| e.to_string())
    }
}

/// Test/mock implementation of a hibernating host WebSocket for deterministic native verification.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct MockHostSocket {
    pub attachment: Option<HostAttachment>,
    pub sent_messages: Vec<String>,
    pub hibernating: bool,
}

impl MockHostSocket {
    pub fn new() -> Self {
        Self::default()
    }
}

impl HibernatingSocket for MockHostSocket {
    fn attach_host_secret(
        &mut self,
        attachment: &HostAttachment,
    ) -> std::result::Result<(), String> {
        self.attachment = Some(attachment.clone());
        self.hibernating = true;
        Ok(())
    }

    fn recover_host_secret(&self) -> std::result::Result<Option<HostAttachment>, String> {
        Ok(self.attachment.clone())
    }

    fn send_text(&mut self, payload: &str) -> std::result::Result<(), String> {
        self.sent_messages.push(payload.to_string());
        Ok(())
    }
}

/// Ephemeral in-memory tracker of burned single-use invite UUIDs and room secret.
/// Purged automatically when the Durable Object unloads from memory; never written to persistent storage.
#[derive(Debug, Default, Clone)]
pub struct EphemeralRoomState {
    burned_uuids: HashSet<String>,
    room_secret: Option<[u8; 32]>,
}

impl EphemeralRoomState {
    pub fn new() -> Self {
        Self {
            burned_uuids: HashSet::new(),
            room_secret: None,
        }
    }

    pub fn with_room_secret(room_secret: [u8; 32]) -> Self {
        Self {
            burned_uuids: HashSet::new(),
            room_secret: Some(room_secret),
        }
    }

    pub fn room_secret(&self) -> Option<&[u8; 32]> {
        self.room_secret.as_ref()
    }

    pub fn set_room_secret(&mut self, secret: [u8; 32]) {
        self.room_secret = Some(secret);
    }

    /// Returns `true` if `invite_uuid` has already been consumed.
    pub fn is_burned(&self, invite_uuid: &str) -> bool {
        self.burned_uuids.contains(invite_uuid)
    }

    /// Marks `invite_uuid` as burned. Returns `false` if already burned or if `MAX_BURNED_UUIDS` is reached.
    pub fn burn_uuid(&mut self, invite_uuid: String) -> bool {
        if self.burned_uuids.contains(&invite_uuid) {
            return false;
        }
        if self.burned_uuids.len() >= MAX_BURNED_UUIDS {
            return false;
        }
        self.burned_uuids.insert(invite_uuid)
    }

    /// Returns the number of burned invite UUIDs currently held in volatile memory.
    pub fn burned_count(&self) -> usize {
        self.burned_uuids.len()
    }
}

/// Stateless/ephemeral Cloudflare Durable Object coordinating WebSocket hibernation and dead-drop delivery.
/// Zero persistent storage calls (`state.storage()`) are ever made.
#[durable_object]
pub struct DeadDropRoom {
    state: State,
    #[allow(dead_code)]
    env: Env,
    ephemeral: RefCell<EphemeralRoomState>,
}

impl DurableObject for DeadDropRoom {
    fn new(state: State, env: Env) -> Self {
        Self {
            state,
            env,
            ephemeral: RefCell::new(EphemeralRoomState::new()),
        }
    }

    async fn fetch(&self, mut req: Request) -> Result<Response> {
        if req.method() == Method::Options {
            return cors_preflight_response();
        }

        let url = req.url()?;
        let segments: Vec<&str> = url
            .path_segments()
            .map(|s| s.filter(|seg| !seg.is_empty()).collect())
            .unwrap_or_default();

        match (req.method(), segments.as_slice()) {
            (Method::Get, ["host", _do_id]) => {
                let expected = self.ephemeral.borrow().room_secret().copied();
                let resp = handle_do_host_upgrade_with_secret(&req, &self.state, expected.as_ref())?;
                if resp.status_code() == 101 && expected.is_none() {
                    if let Some(sec_str) = crate::auth::extract_secret_from_request(&req) {
                        if let Ok(parsed) = crate::auth::authenticate_host(Some(&sec_str), None) {
                            self.ephemeral.borrow_mut().set_room_secret(parsed);
                        }
                    }
                }
                with_cors(resp)
            }
            (Method::Post, ["stage", _do_id]) => {
                let resp = handle_do_stage_invite(&mut req, &self.state, &self.ephemeral).await?;
                with_cors(resp)
            }
            (Method::Get, ["match", _do_id]) => {
                let resp = handle_do_match(&self.state, &self.ephemeral).await?;
                with_cors(resp)
            }
            (Method::Post, ["drop", _do_id, invite_uuid]) => {
                let resp = handle_do_dead_drop(&mut req, &self.state, &self.ephemeral, invite_uuid)
                    .await?;
                with_cors(resp)
            }
            _ => with_cors(Response::error("Not Found", 404)?),
        }
    }

    async fn websocket_message(
        &self,
        ws: WebSocket,
        message: WebSocketIncomingMessage,
    ) -> Result<()> {
        let text_opt = match message {
            WebSocketIncomingMessage::String(text) => Some(text),
            WebSocketIncomingMessage::Binary(bytes) => String::from_utf8(bytes).ok(),
        };

        if let Some(text) = text_opt {
            let invite_opt = serde_json::from_str::<StageInviteRequest>(&text)
                .map(|r| r.invite)
                .or_else(|_| serde_json::from_str::<InvitePayload>(&text))
                .ok();

            if let Some(invite) = invite_opt {
                if let Ok(Some(mut attachment)) = ws.deserialize_attachment::<HostAttachment>() {
                    let room_state = self.ephemeral.borrow();
                    if verify_invite_token(
                        &attachment.host_secret,
                        &invite.invite_uuid,
                        &invite.token,
                    )
                    .is_ok()
                        && !room_state.is_burned(&invite.invite_uuid)
                    {
                        attachment.staged_invite = Some(invite);
                        let _ = ws.serialize_attachment(&attachment);
                    }
                }
            }
        }

        Ok(())
    }

    async fn websocket_close(
        &self,
        ws: WebSocket,
        code: usize,
        reason: String,
        _was_clean: bool,
    ) -> Result<()> {
        let _ = ws.close(Some(code as u16), Some(reason.as_str()));
        Ok(())
    }

    async fn websocket_error(&self, ws: WebSocket, _error: Error) -> Result<()> {
        let _ = ws.close(Some(1011), Some("WebSocket error"));
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ephemeral_room_state_burn_and_duplicate() {
        let mut state = EphemeralRoomState::new();
        assert_eq!(state.burned_count(), 0);
        assert!(!state.is_burned("uuid-1"));

        assert!(state.burn_uuid("uuid-1".to_string()));
        assert_eq!(state.burned_count(), 1);
        assert!(state.is_burned("uuid-1"));

        // Duplicate burn returns false
        assert!(!state.burn_uuid("uuid-1".to_string()));
        assert_eq!(state.burned_count(), 1);
    }

    #[test]
    fn test_ephemeral_room_state_capacity_bound() {
        let mut state = EphemeralRoomState::new();
        for i in 0..MAX_BURNED_UUIDS {
            assert!(state.burn_uuid(format!("uuid-{i}")));
        }
        assert_eq!(state.burned_count(), MAX_BURNED_UUIDS);
        assert!(!state.burn_uuid("uuid-overflow".to_string()));
        assert_eq!(state.burned_count(), MAX_BURNED_UUIDS);
    }

    #[test]
    fn test_mock_host_socket_attachment_and_send() {
        let mut socket = MockHostSocket::new();
        assert!(!socket.hibernating);
        assert_eq!(socket.recover_host_secret().unwrap(), None);

        let attachment = HostAttachment::new([0x55u8; 32]);
        socket.attach_host_secret(&attachment).unwrap();
        assert!(socket.hibernating);
        assert_eq!(
            socket.recover_host_secret().unwrap(),
            Some(attachment.clone())
        );

        socket.send_text("{\"invite_uuid\":\"abc\"}").unwrap();
        assert_eq!(socket.sent_messages, vec!["{\"invite_uuid\":\"abc\"}"]);

        let json = serde_json::to_string(&attachment).unwrap();
        let recovered: HostAttachment = serde_json::from_str(&json).unwrap();
        assert_eq!(recovered, attachment);
        assert_eq!(recovered.staged_invite, None);

        // Verify backward compatibility: legacy serialized HostAttachment without staged_invite field
        let legacy_json = r#"{"host_secret":[85,85,85,85,85,85,85,85,85,85,85,85,85,85,85,85,85,85,85,85,85,85,85,85,85,85,85,85,85,85,85,85]}"#;
        let legacy_recovered: HostAttachment = serde_json::from_str(legacy_json).unwrap();
        assert_eq!(legacy_recovered.host_secret, [0x55u8; 32]);
        assert_eq!(legacy_recovered.staged_invite, None);
    }
}
```

## FILE: src/handlers.rs
```rust
//! HTTP/WebSocket route handlers, HMAC-SHA256 verification, and single-use invite burning
//! for the stateless Cloudflare Worker & Hibernating Durable Object signaling bootstrap.

use std::cell::RefCell;
use std::fmt;

use base64::engine::general_purpose::{STANDARD, STANDARD_NO_PAD, URL_SAFE, URL_SAFE_NO_PAD};
use base64::Engine;
use serde::{Deserialize, Serialize};
use worker::{Headers, Request, RequestInit, Response, Result, State, WebSocketPair};
use zero_protocol::crypto::verify_invite_token;
use zero_protocol::{from_json_bytes, to_json_string, DropPayload, InvitePayload};

use crate::durable_object::{
    EphemeralRoomState, HibernatingSocket, HostAttachment, HOST_WEBSOCKET_TAG,
};

/// Maximum permitted HTTP body size (64 KiB) for `POST /drop/:do_id/:invite_uuid`.
pub const MAX_DROP_BODY_BYTES: usize = 65_536;

/// Payload accepted by `POST /stage/:do_id` or sent over active host WebSocket.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StageInviteRequest {
    pub invite: InvitePayload,
}

/// Response returned by `GET /match/:do_id`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum MatchResponse {
    Matched { invite: InvitePayload },
    Empty,
}

pub const CORS_ALLOW_ORIGIN: &str = "*";
pub const CORS_ALLOW_METHODS: &str = "GET, POST, OPTIONS";
pub const CORS_ALLOW_HEADERS: &str = "Content-Type, Authorization, X-Host-Secret";
pub const CORS_MAX_AGE: &str = "86400";

/// Returns standard CORS headers as key-value pairs.
pub fn cors_headers_vec() -> Vec<(String, String)> {
    vec![
        ("Access-Control-Allow-Origin".to_string(), CORS_ALLOW_ORIGIN.to_string()),
        ("Access-Control-Allow-Methods".to_string(), CORS_ALLOW_METHODS.to_string()),
        ("Access-Control-Allow-Headers".to_string(), CORS_ALLOW_HEADERS.to_string()),
        ("Access-Control-Max-Age".to_string(), CORS_MAX_AGE.to_string()),
    ]
}

/// Target-independent HTTP response representation returned by protocol handlers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HttpResponse {
    pub status: u16,
    pub body: String,
    pub headers: Vec<(String, String)>,
}

impl HttpResponse {
    pub fn new(status: u16, body: impl Into<String>) -> Self {
        Self {
            status,
            body: body.into(),
            headers: Vec::new(),
        }
    }

    pub fn with_cors(mut self) -> Self {
        self.headers = cors_headers_vec();
        self
    }

    pub fn cors_preflight() -> Self {
        Self {
            status: 204,
            body: String::new(),
            headers: cors_headers_vec(),
        }
    }

    pub fn get_header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }
}

/// Signaling protocol errors mapped deterministically to HTTP status codes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NetworkError {
    MissingUpgradeHeader,
    InvalidHostSecret,
    Unauthorized,
    HostSocketUnavailable,
    InvalidDropPayload(String),
    InviteUuidMismatch,
    ForbiddenHmac,
    InviteAlreadyBurned,
    BurnCapacityExceeded,
    PayloadTooLarge,
    SocketError(String),
}

impl NetworkError {
    /// Returns the canonical HTTP status code for this error.
    pub fn status_code(&self) -> u16 {
        match self {
            Self::MissingUpgradeHeader => 426,
            Self::InvalidHostSecret => 400,
            Self::Unauthorized => 401,
            Self::HostSocketUnavailable => 404,
            Self::InvalidDropPayload(_) => 400,
            Self::InviteUuidMismatch => 400,
            Self::ForbiddenHmac => 403,
            Self::InviteAlreadyBurned => 410,
            Self::BurnCapacityExceeded => 429,
            Self::PayloadTooLarge => 413,
            Self::SocketError(_) => 500,
        }
    }
}

impl fmt::Display for NetworkError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MissingUpgradeHeader => write!(f, "Expected Upgrade: websocket header"),
            Self::InvalidHostSecret => {
                write!(
                    f,
                    "Invalid or missing 32-byte host_secret (expected hex or base64)"
                )
            }
            Self::Unauthorized => write!(f, "401 Unauthorized: Invalid or missing host secret"),
            Self::HostSocketUnavailable => {
                write!(f, "No active hibernating host WebSocket for room")
            }
            Self::InvalidDropPayload(msg) => write!(f, "Invalid DropPayload: {msg}"),
            Self::InviteUuidMismatch => {
                write!(f, "Path invite_uuid does not match DropPayload.invite_uuid")
            }
            Self::ForbiddenHmac => write!(f, "403 Forbidden: Invalid HMAC invite token"),
            Self::InviteAlreadyBurned => {
                write!(f, "410 Gone: Invite UUID has already been burned")
            }
            Self::BurnCapacityExceeded => {
                write!(
                    f,
                    "429 Too Many Requests: Room invite burn capacity exceeded"
                )
            }
            Self::PayloadTooLarge => write!(f, "413 Payload Too Large"),
            Self::SocketError(msg) => write!(f, "WebSocket error: {msg}"),
        }
    }
}

impl std::error::Error for NetworkError {}

/// Extracts a bearer token (or raw token) from an optional `Authorization` header value.
pub fn extract_bearer_token(auth_header: Option<&str>) -> Option<&str> {
    let trimmed = auth_header?.trim();
    if trimmed.is_empty() || trimmed.eq_ignore_ascii_case("bearer") {
        return None;
    }

    if let Some(prefix) = trimmed.get(..7) {
        if prefix.eq_ignore_ascii_case("bearer ") {
            let remainder = trimmed[7..].trim();
            return if remainder.is_empty() {
                None
            } else {
                Some(remainder)
            };
        }
    }

    Some(trimmed)
}

/// Parses a 32-byte `host_secret` from either a 64-character hex string or a Base64/Base64URL string.
/// Strips an optional `"Bearer "` prefix if present.
pub fn parse_host_secret(raw: &str) -> std::result::Result<[u8; 32], NetworkError> {
    let cleaned = extract_bearer_token(Some(raw)).ok_or(NetworkError::InvalidHostSecret)?;

    if cleaned.len() == 64 {
        if let Ok(bytes) = hex::decode(cleaned) {
            if bytes.len() == 32 {
                let mut secret = [0u8; 32];
                secret.copy_from_slice(&bytes);
                return Ok(secret);
            }
        }
    }

    let engines = [URL_SAFE_NO_PAD, URL_SAFE, STANDARD_NO_PAD, STANDARD];
    for engine in engines {
        if let Ok(bytes) = engine.decode(cleaned) {
            if bytes.len() == 32 {
                let mut secret = [0u8; 32];
                secret.copy_from_slice(&bytes);
                return Ok(secret);
            }
        }
    }

    Err(NetworkError::InvalidHostSecret)
}

/// Validates a host WebSocket upgrade request (`/host/:do_id`), parses the 32-byte `host_secret`,
/// and attaches `HostAttachment { host_secret }` to the hibernating socket.
pub fn process_host_upgrade<S: HibernatingSocket>(
    upgrade_header: Option<&str>,
    secret_str: Option<&str>,
    socket: &mut S,
) -> std::result::Result<HttpResponse, NetworkError> {
    match upgrade_header {
        Some(val) if val.trim().eq_ignore_ascii_case("websocket") => {}
        _ => return Err(NetworkError::MissingUpgradeHeader),
    }

    let raw_secret = secret_str.ok_or(NetworkError::InvalidHostSecret)?;
    let host_secret = parse_host_secret(raw_secret)?;

    socket
        .attach_host_secret(&HostAttachment::new(host_secret))
        .map_err(NetworkError::SocketError)?;

    Ok(HttpResponse {
        status: 101,
        body: String::new(),
        headers: Vec::new(),
    })
}

/// Validates caller host secret and stages an unburned `InvitePayload` on the matching host socket.
pub fn process_stage_invite<S: HibernatingSocket>(
    secret_str: Option<&str>,
    body_bytes: &[u8],
    room_state: &EphemeralRoomState,
    host_sockets: &mut [S],
) -> std::result::Result<HttpResponse, NetworkError> {
    let raw_secret = secret_str.ok_or(NetworkError::InvalidHostSecret)?;
    let host_secret = parse_host_secret(raw_secret)?;

    let mut matched_idx: Option<usize> = None;
    for (idx, sock) in host_sockets.iter().enumerate() {
        if let Ok(Some(att)) = sock.recover_host_secret() {
            if att.host_secret == host_secret {
                matched_idx = Some(idx);
                break;
            }
        }
    }

    let target_idx = matched_idx.ok_or(NetworkError::HostSocketUnavailable)?;

    let invite: InvitePayload = if let Ok(req) = from_json_bytes::<StageInviteRequest>(body_bytes) {
        req.invite
    } else {
        from_json_bytes::<InvitePayload>(body_bytes)
            .map_err(|e| NetworkError::InvalidDropPayload(e.to_string()))?
    };

    verify_invite_token(&host_secret, &invite.invite_uuid, &invite.token)
        .map_err(|_| NetworkError::ForbiddenHmac)?;

    if room_state.is_burned(&invite.invite_uuid) {
        return Err(NetworkError::InviteAlreadyBurned);
    }

    let attachment = HostAttachment {
        host_secret,
        staged_invite: Some(invite),
    };
    host_sockets[target_idx]
        .attach_host_secret(&attachment)
        .map_err(NetworkError::SocketError)?;

    Ok(HttpResponse {
        status: 200,
        body: r#"{"status":"ok"}"#.to_string(),
        headers: cors_headers_vec(),
    })
}

/// Inspects active host sockets, selects one with an unburned staged invite via `selector_seed`,
/// atomically consumes (clears) the staged invite on that socket, and returns `MatchResponse`.
pub fn process_match_request<S: HibernatingSocket>(
    room_state: &EphemeralRoomState,
    host_sockets: &mut [S],
    selector_seed: usize,
) -> std::result::Result<HttpResponse, NetworkError> {
    let mut available: Vec<(usize, HostAttachment, InvitePayload)> = Vec::new();
    for (idx, sock) in host_sockets.iter().enumerate() {
        if let Ok(Some(att)) = sock.recover_host_secret() {
            if let Some(ref inv) = att.staged_invite {
                if !room_state.is_burned(&inv.invite_uuid) {
                    available.push((idx, att.clone(), inv.clone()));
                }
            }
        }
    }

    if available.is_empty() {
        let resp = MatchResponse::Empty;
        let body = to_json_string(&resp).map_err(|e| NetworkError::SocketError(e.to_string()))?;
        return Ok(HttpResponse {
            status: 200,
            body,
            headers: cors_headers_vec(),
        });
    }

    let selected_idx = selector_seed % available.len();
    let (sock_idx, mut attachment, invite) = available.remove(selected_idx);

    // Atomically clear staged_invite on that socket's attachment
    attachment.staged_invite = None;
    host_sockets[sock_idx]
        .attach_host_secret(&attachment)
        .map_err(NetworkError::SocketError)?;

    let resp = MatchResponse::Matched { invite };
    let body = to_json_string(&resp).map_err(|e| NetworkError::SocketError(e.to_string()))?;
    Ok(HttpResponse {
        status: 200,
        body,
        headers: cors_headers_vec(),
    })
}

/// Processes a joiner's dead-drop `POST /drop/:do_id/:invite_uuid`:
/// 1. Validates payload size, JSON structure, and `invite_uuid` consistency.
/// 2. Iterates host sockets to locate the specific socket whose `host_secret` matches the invite HMAC.
/// 3. Verifies HMAC-SHA256 in constant time (returning `403 Forbidden` if no socket matches).
/// 4. Checks and burns `invite_uuid` in `EphemeralRoomState` (returning `410 Gone` on replay).
/// 5. Pipes the serialized `DropPayload` strictly to the matching host WebSocket.
pub fn process_dead_drop<S: HibernatingSocket>(
    path_invite_uuid: &str,
    auth_header: Option<&str>,
    body_bytes: &[u8],
    room_state: &mut EphemeralRoomState,
    host_sockets: &mut [S],
) -> std::result::Result<HttpResponse, NetworkError> {
    if body_bytes.len() > MAX_DROP_BODY_BYTES {
        return Err(NetworkError::PayloadTooLarge);
    }

    if path_invite_uuid.trim().is_empty() {
        return Err(NetworkError::InvalidDropPayload(
            "Empty invite UUID".to_string(),
        ));
    }

    let payload: DropPayload =
        from_json_bytes(body_bytes).map_err(|e| NetworkError::InvalidDropPayload(e.to_string()))?;

    if payload.invite_uuid != path_invite_uuid {
        return Err(NetworkError::InviteUuidMismatch);
    }

    let token = match extract_bearer_token(auth_header) {
        Some(header_token) => {
            if !payload.token.is_empty() && payload.token != header_token {
                return Err(NetworkError::ForbiddenHmac);
            }
            header_token
        }
        None => {
            let trimmed = payload.token.trim();
            if trimmed.is_empty() {
                return Err(NetworkError::ForbiddenHmac);
            }
            trimmed
        }
    };

    if host_sockets.is_empty() {
        return Err(NetworkError::HostSocketUnavailable);
    }

    let mut found_any_attachment = false;
    let mut matching_idx: Option<usize> = None;

    for (idx, sock) in host_sockets.iter().enumerate() {
        if let Some(att) = sock
            .recover_host_secret()
            .map_err(NetworkError::SocketError)?
        {
            found_any_attachment = true;
            if verify_invite_token(&att.host_secret, path_invite_uuid, token).is_ok() {
                matching_idx = Some(idx);
                break;
            }
        }
    }

    if !found_any_attachment {
        return Err(NetworkError::HostSocketUnavailable);
    }

    let target_idx = matching_idx.ok_or(NetworkError::ForbiddenHmac)?;

    // REQ-003.4: Replay detection & single-use invite burning in volatile memory.
    if room_state.is_burned(path_invite_uuid) {
        return Err(NetworkError::InviteAlreadyBurned);
    }
    if !room_state.burn_uuid(path_invite_uuid.to_string()) {
        return Err(NetworkError::BurnCapacityExceeded);
    }

    // Pipe serialized DropPayload strictly to that matching host socket.
    let serialized =
        to_json_string(&payload).map_err(|e| NetworkError::InvalidDropPayload(e.to_string()))?;

    host_sockets[target_idx]
        .send_text(&serialized)
        .map_err(NetworkError::SocketError)?;

    Ok(HttpResponse {
        status: 200,
        body: r#"{"status":"ok"}"#.to_string(),
        headers: cors_headers_vec(),
    })
}

/// Attaches permissive CORS headers to a Cloudflare Worker `Response`.
pub fn with_cors(mut resp: Response) -> Result<Response> {
    let status = resp.status_code();
    if status == 101 {
        return Ok(resp);
    }

    let headers = resp.headers_mut();
    headers.set("Access-Control-Allow-Origin", "*")?;
    headers.set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")?;
    headers.set(
        "Access-Control-Allow-Headers",
        "Content-Type, Authorization, X-Host-Secret",
    )?;
    headers.set("Access-Control-Max-Age", "86400")?;

    if (status == 200 || status == 201) && headers.get("Content-Type")?.is_none() {
        headers.set("Content-Type", "application/json")?;
    }

    Ok(resp)
}

/// Constructs an HTTP 204 No Content response for CORS preflight `OPTIONS` requests.
pub fn cors_preflight_response() -> Result<Response> {
    let resp = Response::empty()?.with_status(204);
    with_cors(resp)
}

/// Retrieves a binding string from `worker::Env`, checking secrets first, then environment variables.
pub fn get_env_var(env: &worker::Env, key: &str) -> Option<String> {
    if let Ok(sec) = env.secret(key) {
        let val = sec.to_string();
        if !val.trim().is_empty() {
            return Some(val);
        }
    }
    if let Ok(var) = env.var(key) {
        let val = var.to_string();
        if !val.trim().is_empty() {
            return Some(val);
        }
    }
    None
}

/// Parses custom TURN/ICE servers JSON string (array, object with `iceServers`, or object with `urls`) into `{ "iceServers": ... }`.
pub fn parse_custom_ice_servers(raw_json: &str) -> Option<serde_json::Value> {
    let parsed: serde_json::Value = serde_json::from_str(raw_json).ok()?;
    match parsed {
        serde_json::Value::Array(arr) => Some(serde_json::json!({
            "iceServers": arr
        })),
        serde_json::Value::Object(map) => {
            if let Some(servers) = map.get("iceServers") {
                Some(serde_json::json!({ "iceServers": servers }))
            } else if map.contains_key("urls") {
                Some(serde_json::json!({ "iceServers": [map] }))
            } else {
                None
            }
        }
        _ => None,
    }
}

/// Returns default STUN configuration structure for WebRTC NAT traversal.
pub fn default_ice_servers_json() -> serde_json::Value {
    serde_json::json!({
        "iceServers": [
            { "urls": "stun:stun.cloudflare.com:3478" },
            { "urls": "stun:stun.l.google.com:19302" }
        ]
    })
}

/// Target-independent handler resolving custom JSON or falling back to default STUN configuration.
pub fn process_ice_servers(custom_json: Option<&str>) -> HttpResponse {
    if let Some(json_str) = custom_json {
        if let Some(val) = parse_custom_ice_servers(json_str) {
            return HttpResponse {
                status: 200,
                body: serde_json::to_string(&val).unwrap_or_default(),
                headers: cors_headers_vec(),
            };
        }
    }
    HttpResponse {
        status: 200,
        body: serde_json::to_string(&default_ice_servers_json()).unwrap_or_default(),
        headers: cors_headers_vec(),
    }
}

/// Constructs a 200 OK Response with default STUN configuration and CORS headers.
pub fn build_default_stun_response() -> Result<Response> {
    with_cors(Response::from_json(&default_ice_servers_json())?)
}

/// Provisions short-lived ephemeral Cloudflare TURN credentials or returns a reliable default STUN configuration.
pub async fn handle_ice_config(env: &worker::Env) -> Result<Response> {
    // Mode 1: Cloudflare Realtime TURN API
    let key_id = get_env_var(env, "CF_TURN_KEY_ID");
    let api_token = get_env_var(env, "CF_TURN_API_TOKEN");

    if let (Some(key_id), Some(api_token)) = (key_id, api_token) {
        let url = format!(
            "https://rtc.live.cloudflare.com/v1/turn/keys/{key_id}/credentials/generate-ice-servers"
        );
        let headers = Headers::new();
        let _ = headers.set("Authorization", &format!("Bearer {api_token}"));
        let _ = headers.set("Content-Type", "application/json");

        let mut init = RequestInit::new();
        init.with_method(worker::Method::Post);
        init.with_headers(headers);
        init.with_body(Some(worker::wasm_bindgen::JsValue::from_str(
            "{\"ttl\": 86400}",
        )));

        match Request::new_with_init(&url, &init) {
            Ok(req) => match worker::Fetch::Request(req).send().await {
                Ok(mut cf_res) => {
                    let status = cf_res.status_code();
                    if (200..=299).contains(&status) {
                        if let Ok(body_str) = cf_res.text().await {
                            let json_val = parse_custom_ice_servers(&body_str).or_else(|| {
                                serde_json::from_str::<serde_json::Value>(&body_str).ok()
                            });
                            if let Some(json_val) = json_val {
                                return with_cors(Response::from_json(&json_val)?);
                            }
                        }
                    }
                    #[cfg(target_arch = "wasm32")]
                    worker::console_warn!(
                        "Cloudflare TURN API returned status {} or invalid body",
                        status
                    );
                    #[cfg(not(target_arch = "wasm32"))]
                    eprintln!(
                        "Cloudflare TURN API returned status {} or invalid body",
                        status
                    );
                }
                Err(e) => {
                    #[cfg(target_arch = "wasm32")]
                    worker::console_warn!("Failed to fetch Cloudflare TURN credentials: {:?}", e);
                    #[cfg(not(target_arch = "wasm32"))]
                    eprintln!("Failed to fetch Cloudflare TURN credentials: {:?}", e);
                }
            },
            Err(e) => {
                #[cfg(target_arch = "wasm32")]
                worker::console_warn!("Failed to build Cloudflare TURN request: {:?}", e);
                #[cfg(not(target_arch = "wasm32"))]
                eprintln!("Failed to build Cloudflare TURN request: {:?}", e);
            }
        }
    }

    // Mode 2 & Mode 3: Custom JSON Override or Default STUN Fallback
    let custom_json = get_env_var(env, "TURN_SERVERS_JSON");
    let resolved = process_ice_servers(custom_json.as_deref());
    let val: serde_json::Value =
        serde_json::from_str(&resolved.body).unwrap_or_else(|_| default_ice_servers_json());
    with_cors(Response::from_json(&val)?)
}

/// Cloudflare Durable Object adapter for `GET /host/:do_id` WebSocket upgrade and hibernation registration.
pub fn handle_do_host_upgrade(req: &Request, state: &State) -> Result<Response> {
    handle_do_host_upgrade_with_secret(req, state, None)
}

/// Cloudflare Durable Object adapter for `GET /host/:do_id` with optional expected room secret validation.
pub fn handle_do_host_upgrade_with_secret(
    req: &Request,
    state: &State,
    expected_secret: Option<&[u8; 32]>,
) -> Result<Response> {
    // 1. Resolve expected room secret: either passed explicitly or recovered from existing host sockets.
    let mut expected: Option<[u8; 32]> = expected_secret.copied();
    if expected.is_none() {
        for sock in state.get_websockets_with_tag(HOST_WEBSOCKET_TAG).iter() {
            if let Ok(Some(att)) = sock.recover_host_secret() {
                expected = Some(att.host_secret);
                break;
            }
        }
    }

    // 2. Extract and authenticate secret (from headers or ?secret=<hex> query param)
    let secret = crate::auth::extract_secret_from_request(req);
    let host_secret = match crate::auth::authenticate_host(secret.as_deref(), expected.as_ref()) {
        Ok(s) => s,
        Err(err) => {
            return with_cors(Response::error(err.to_string(), err.status_code())?);
        }
    };

    // 3. Validate Upgrade: websocket header
    let upgrade = req.headers().get("Upgrade")?;
    match upgrade.as_deref() {
        Some(val) if val.trim().eq_ignore_ascii_case("websocket") => {}
        _ => {
            let err = NetworkError::MissingUpgradeHeader;
            return with_cors(Response::error(err.to_string(), err.status_code())?);
        }
    }

    let pair = WebSocketPair::new()?;
    let mut server = pair.server;
    let client = pair.client;

    if let Err(err) = server.attach_host_secret(&HostAttachment::new(host_secret)) {
        return with_cors(Response::error(err, 500)?);
    }

    state.accept_websocket_with_tags(&server, &[HOST_WEBSOCKET_TAG]);
    Response::from_websocket(client)
}

/// Cloudflare Durable Object adapter for `POST /drop/:do_id/:invite_uuid`.
pub async fn handle_do_dead_drop(
    req: &mut Request,
    state: &State,
    ephemeral: &RefCell<EphemeralRoomState>,
    invite_uuid: &str,
) -> Result<Response> {
    let auth_header = req.headers().get("Authorization")?;
    let body_bytes = req.bytes().await?;

    let mut sockets = state.get_websockets_with_tag(HOST_WEBSOCKET_TAG);
    if sockets.is_empty() {
        sockets = state.get_websockets();
    }

    let result = {
        let mut room_state = ephemeral.borrow_mut();
        process_dead_drop(
            invite_uuid,
            auth_header.as_deref(),
            &body_bytes,
            &mut room_state,
            &mut sockets,
        )
    };

    match result {
        Ok(_) => with_cors(Response::from_json(&serde_json::json!({ "status": "ok" }))?),
        Err(err) => with_cors(Response::error(err.to_string(), err.status_code())?),
    }
}

/// Cloudflare Durable Object adapter for `POST /stage/:do_id`.
pub async fn handle_do_stage_invite(
    req: &mut Request,
    state: &State,
    ephemeral: &RefCell<EphemeralRoomState>,
) -> Result<Response> {
    let secret = crate::auth::extract_secret_from_request(req);
    let body_bytes = req.bytes().await?;
    let mut sockets = state.get_websockets_with_tag(HOST_WEBSOCKET_TAG);
    if sockets.is_empty() {
        sockets = state.get_websockets();
    }

    let result = {
        let room_state = ephemeral.borrow();
        process_stage_invite(secret.as_deref(), &body_bytes, &room_state, &mut sockets)
    };

    match result {
        Ok(_) => with_cors(Response::from_json(&serde_json::json!({ "status": "ok" }))?),
        Err(err) => with_cors(Response::error(err.to_string(), err.status_code())?),
    }
}

/// Cloudflare Durable Object adapter for `GET /match/:do_id`.
pub async fn handle_do_match(
    state: &State,
    ephemeral: &RefCell<EphemeralRoomState>,
) -> Result<Response> {
    let mut sockets = state.get_websockets_with_tag(HOST_WEBSOCKET_TAG);
    if sockets.is_empty() {
        sockets = state.get_websockets();
    }

    let seed = generate_selector_seed();
    let result = {
        let room_state = ephemeral.borrow();
        process_match_request(&room_state, &mut sockets, seed)
    };

    match result {
        Ok(http_res) => {
            let mut resp = Response::ok(&http_res.body)?;
            resp.headers_mut().set("Content-Type", "application/json")?;
            with_cors(resp)
        }
        Err(err) => with_cors(Response::error(err.to_string(), err.status_code())?),
    }
}

/// Generates a pseudo-random selector seed for round-robin / randomized host selection.
pub fn generate_selector_seed() -> usize {
    #[cfg(target_arch = "wasm32")]
    {
        (worker::js_sys::Math::random() * 1_000_000.0) as usize
    }
    #[cfg(not(target_arch = "wasm32"))]
    {
        use std::time::{SystemTime, UNIX_EPOCH};
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| (d.as_nanos() & 0xFFFF_FFFF) as usize)
            .unwrap_or(0)
    }
}
```

## FILE: src/lib.rs
```rust
//! Stateless Cloudflare Worker & Hibernating Durable Object signaling bootstrap crate.

pub use zero_protocol;

pub mod auth;
pub mod durable_object;
pub mod handlers;

pub use auth::*;
pub use durable_object::{
    DeadDropRoom, EphemeralRoomState, HibernatingSocket, HostAttachment, MockHostSocket,
    DEAD_DROP_BINDING, HOST_WEBSOCKET_TAG, MAX_BURNED_UUIDS,
};
pub use handlers::{
    build_default_stun_response, cors_preflight_response, default_ice_servers_json,
    extract_bearer_token, get_env_var, handle_do_match, handle_do_stage_invite, handle_ice_config,
    parse_custom_ice_servers, parse_host_secret, process_dead_drop, process_host_upgrade,
    process_ice_servers, process_match_request, process_stage_invite, with_cors, HttpResponse,
    MatchResponse, NetworkError, StageInviteRequest, MAX_DROP_BODY_BYTES,
};

use worker::{event, Context, Env, Method, Request, Response, Result, Router};

/// Cloudflare Worker fetch entrypoint routing `/host/:do_id` and `/drop/:do_id/:invite_uuid`
/// to the named `DeadDropRoom` Durable Object instance, and `/ice` for TURN/STUN negotiation.
#[event(fetch)]
pub async fn fetch(req: Request, env: Env, _ctx: Context) -> Result<Response> {
    if req.method() == Method::Options {
        return cors_preflight_response();
    }

    let router = Router::new();

    router
        .options("/host/:do_id", |_, _| cors_preflight_response())
        .options("/stage/:do_id", |_, _| cors_preflight_response())
        .options("/match/:do_id", |_, _| cors_preflight_response())
        .options("/drop/:do_id/:invite_uuid", |_, _| {
            cors_preflight_response()
        })
        .options("/ice", |_, _| cors_preflight_response())
        .get_async("/host/:do_id", |req, ctx| async move {
            let do_id = match ctx.param("do_id") {
                Some(id) if !id.trim().is_empty() => id,
                _ => return with_cors(Response::error("Missing Durable Object ID", 400)?),
            };
            let namespace = ctx.durable_object(DEAD_DROP_BINDING)?;
            let stub = namespace.id_from_name(do_id)?.get_stub()?;
            let resp = match stub.fetch_with_request(req).await {
                Ok(r) => r,
                Err(e) => {
                    let err_resp = Response::error(format!("Durable Object error: {e}"), 500)?;
                    return with_cors(err_resp);
                }
            };
            if resp.status_code() == 101 {
                return Ok(resp);
            }
            with_cors(resp)
        })
        .post_async("/stage/:do_id", |req, ctx| async move {
            let do_id = match ctx.param("do_id") {
                Some(id) if !id.trim().is_empty() => id,
                _ => return with_cors(Response::error("Missing Durable Object ID", 400)?),
            };
            let namespace = ctx.durable_object(DEAD_DROP_BINDING)?;
            let stub = namespace.id_from_name(do_id)?.get_stub()?;
            let mut resp = match stub.fetch_with_request(req).await {
                Ok(r) => r,
                Err(e) => {
                    let err_resp = Response::error(format!("Durable Object error: {e}"), 500)?;
                    return with_cors(err_resp);
                }
            };

            let status = resp.status_code();
            let body_text = resp.text().await.unwrap_or_default();
            let fresh_resp = if (200..300).contains(&status) {
                let mut r = Response::ok(body_text)?;
                if status != 200 {
                    r = r.with_status(status);
                }
                r
            } else {
                Response::error(body_text, status)?
            };

            with_cors(fresh_resp)
        })
        .get_async("/match/:do_id", |req, ctx| async move {
            let do_id = match ctx.param("do_id") {
                Some(id) if !id.trim().is_empty() => id,
                _ => return with_cors(Response::error("Missing Durable Object ID", 400)?),
            };
            let namespace = ctx.durable_object(DEAD_DROP_BINDING)?;
            let stub = namespace.id_from_name(do_id)?.get_stub()?;
            let mut resp = match stub.fetch_with_request(req).await {
                Ok(r) => r,
                Err(e) => {
                    let err_resp = Response::error(format!("Durable Object error: {e}"), 500)?;
                    return with_cors(err_resp);
                }
            };

            let status = resp.status_code();
            let body_text = resp.text().await.unwrap_or_default();
            let fresh_resp = if (200..300).contains(&status) {
                let mut r = Response::ok(body_text)?;
                if status != 200 {
                    r = r.with_status(status);
                }
                r
            } else {
                Response::error(body_text, status)?
            };

            with_cors(fresh_resp)
        })
        .post_async("/drop/:do_id/:invite_uuid", |req, ctx| async move {
            let do_id = match ctx.param("do_id") {
                Some(id) if !id.trim().is_empty() => id,
                _ => return with_cors(Response::error("Missing Durable Object ID", 400)?),
            };
            let namespace = ctx.durable_object(DEAD_DROP_BINDING)?;
            let stub = namespace.id_from_name(do_id)?.get_stub()?;
            let mut resp = match stub.fetch_with_request(req).await {
                Ok(r) => r,
                Err(e) => {
                    let err_resp = Response::error(format!("Durable Object error: {e}"), 500)?;
                    return with_cors(err_resp);
                }
            };

            // Never mutate headers on WebSocket 101 Switching Protocols
            if resp.status_code() == 101 {
                return Ok(resp);
            }

            let status = resp.status_code();
            let body_text = resp.text().await.unwrap_or_default();
            let fresh_resp = if (200..300).contains(&status) {
                let mut r = Response::ok(body_text)?;
                if status != 200 {
                    r = r.with_status(status);
                }
                r
            } else {
                Response::error(body_text, status)?
            };

            with_cors(fresh_resp)
        })
        .get_async("/ice", |_req, ctx| async move {
            handle_ice_config(&ctx.env).await
        })
        .post_async("/ice", |_req, ctx| async move {
            handle_ice_config(&ctx.env).await
        })
        .get("/health", |_, _| with_cors(Response::ok("ok")?))
        .run(req, env)
        .await
}
```

## FILE: tests/network_tests.rs
```rust
//! Comprehensive integration tests for `zero_network` signaling, WebSocket hibernation attachment,
//! constant-time HMAC-SHA256 verification, single-use invite burning, and dead-drop piping.

use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use base64::Engine;
use zero_network::{
    authenticate_host, constant_time_eq, default_ice_servers_json, extract_bearer_token,
    extract_secret_from_params, parse_custom_ice_servers, parse_host_secret, parse_query_secret,
    process_dead_drop, process_host_query_upgrade, process_host_upgrade,
    process_host_upgrade_authenticated, process_ice_servers, process_match_request,
    process_stage_invite, EphemeralRoomState, HibernatingSocket, HostAttachment, HttpResponse,
    MatchResponse, MockHostSocket, NetworkError, StageInviteRequest, MAX_BURNED_UUIDS,
    MAX_DROP_BODY_BYTES,
};
#[cfg(target_arch = "wasm32")]
use zero_network::{build_default_stun_response, cors_preflight_response, with_cors};
use zero_protocol::crypto::{compute_invite_token, X25519Keypair};
use zero_protocol::{
    from_json_str, to_json_bytes, to_json_string, DropPayload, InvitePayload, SdpAnswer, SdpOffer,
};

fn sample_invite_payload(
    do_id: &str,
    invite_uuid: &str,
    token: &str,
    host_pubkey: [u8; 32],
) -> InvitePayload {
    InvitePayload {
        do_id: do_id.to_string(),
        invite_uuid: invite_uuid.to_string(),
        token: token.to_string(),
        sdp_offer: SdpOffer {
            sdp: "v=0\r\no=- 123 2 IN IP4 127.0.0.1\r\na=setup:actpass\r\n".to_string(),
        },
        host_public_key: host_pubkey,
        guest_private_key: None,
        host_peer_id: Some("host-peer-1".to_string()),
        assigned_peer_id: Some("guest-peer-1".to_string()),
        host_signing_key: None,
    }
}

fn sample_drop_payload(invite_uuid: &str, token: &str) -> DropPayload {
    let joiner_kp = X25519Keypair::from_private_key([0x42; 32]);
    DropPayload {
        invite_uuid: invite_uuid.to_string(),
        token: token.to_string(),
        sdp_answer: SdpAnswer {
            sdp: "v=0\r\no=- 999 2 IN IP4 127.0.0.1\r\na=setup:active\r\n".to_string(),
        },
        joiner_public_key: *joiner_kp.public_key_bytes(),
        joiner_peer_id: None,
        joiner_signing_key: None,
        sealed_sdp_answer: None,
        signature: None,
    }
}

#[test]
fn test_host_upgrade_accepts_hex_and_base64_secrets() {
    let raw_secret = [0xABu8; 32];
    let hex_secret = hex::encode(raw_secret);
    let b64_std_secret = STANDARD.encode(raw_secret);
    let b64_url_secret = URL_SAFE_NO_PAD.encode(raw_secret);

    // 1. 64-char hex secret
    let mut socket_hex = MockHostSocket::new();
    let res_hex = process_host_upgrade(Some("websocket"), Some(&hex_secret), &mut socket_hex)
        .expect("hex secret upgrade should succeed");
    assert_eq!(res_hex.status, 101);
    assert!(socket_hex.hibernating);
    assert_eq!(
        socket_hex.recover_host_secret().unwrap(),
        Some(HostAttachment::new(raw_secret))
    );

    // 2. Standard Base64 (44 chars) with Bearer prefix
    let mut socket_b64 = MockHostSocket::new();
    let bearer_b64 = format!("Bearer {b64_std_secret}");
    let res_b64 = process_host_upgrade(Some("WebSocket"), Some(&bearer_b64), &mut socket_b64)
        .expect("base64 secret upgrade should succeed");
    assert_eq!(res_b64.status, 101);
    assert!(socket_b64.hibernating);
    assert_eq!(
        socket_b64.recover_host_secret().unwrap(),
        Some(HostAttachment::new(raw_secret))
    );

    // 3. Base64URL no-pad (43 chars)
    let mut socket_url = MockHostSocket::new();
    let res_url = process_host_upgrade(Some("websocket"), Some(&b64_url_secret), &mut socket_url)
        .expect("base64url secret upgrade should succeed");
    assert_eq!(res_url.status, 101);
    assert_eq!(
        socket_url.recover_host_secret().unwrap(),
        Some(HostAttachment::new(raw_secret))
    );

    // 4. Missing or invalid Upgrade header -> 426 Upgrade Required
    let mut socket_no_upg = MockHostSocket::new();
    let err_no_upg = process_host_upgrade(None, Some(&hex_secret), &mut socket_no_upg)
        .expect_err("missing upgrade header must fail");
    assert_eq!(err_no_upg, NetworkError::MissingUpgradeHeader);
    assert_eq!(err_no_upg.status_code(), 426);
    assert!(!socket_no_upg.hibernating);

    // 5. Malformed or wrong-length secret -> 400 Bad Request
    let mut socket_bad_sec = MockHostSocket::new();
    let err_short = process_host_upgrade(Some("websocket"), Some("deadbeef"), &mut socket_bad_sec)
        .expect_err("short secret must fail");
    assert_eq!(err_short, NetworkError::InvalidHostSecret);
    assert_eq!(err_short.status_code(), 400);

    let err_missing = process_host_upgrade(Some("websocket"), None, &mut socket_bad_sec)
        .expect_err("missing secret must fail");
    assert_eq!(err_missing, NetworkError::InvalidHostSecret);
    assert_eq!(err_missing.status_code(), 400);

    // Verify extract_bearer_token helper directly
    assert_eq!(
        extract_bearer_token(Some("  Bearer abc123  ")),
        Some("abc123")
    );
    assert_eq!(extract_bearer_token(Some("bearer   xyz")), Some("xyz"));
    assert_eq!(extract_bearer_token(Some("Bearer   ")), None);
    assert_eq!(extract_bearer_token(Some("   ")), None);
    assert_eq!(extract_bearer_token(None), None);
    assert_eq!(parse_host_secret(&hex_secret).unwrap(), raw_secret);
}

#[test]
fn test_dead_drop_rejects_invalid_or_tampered_hmac_with_403() {
    let host_secret = [0x55u8; 32];
    let invite_uuid = "invite-uuid-001";

    let mut host_socket = MockHostSocket::new();
    process_host_upgrade(
        Some("websocket"),
        Some(&hex::encode(host_secret)),
        &mut host_socket,
    )
    .expect("host upgrade");

    let mut sockets = vec![host_socket];
    let mut room_state = EphemeralRoomState::new();

    // Compute valid token and tamper with the last character
    let valid_token = compute_invite_token(&host_secret, invite_uuid)
        .expect("compute token")
        .hmac_hex;
    let mut tampered_token = valid_token.clone();
    let last_char = tampered_token.pop().unwrap();
    tampered_token.push(if last_char == 'a' { 'b' } else { 'a' });

    let bad_payload = sample_drop_payload(invite_uuid, &tampered_token);
    let bad_bytes = to_json_bytes(&bad_payload).expect("serialize payload");

    let err = process_dead_drop(invite_uuid, None, &bad_bytes, &mut room_state, &mut sockets)
        .expect_err("tampered HMAC must be rejected");
    assert_eq!(err, NetworkError::ForbiddenHmac);
    assert_eq!(err.status_code(), 403);

    // Verify invite UUID was NOT burned and no message was sent to the host WebSocket
    assert!(!room_state.is_burned(invite_uuid));
    assert_eq!(room_state.burned_count(), 0);
    assert!(sockets[0].sent_messages.is_empty());

    // Also test token signed with wrong host_secret
    let wrong_secret = [0x99u8; 32];
    let wrong_key_token = compute_invite_token(&wrong_secret, invite_uuid)
        .expect("compute wrong key token")
        .hmac_hex;
    let wrong_payload = sample_drop_payload(invite_uuid, &wrong_key_token);
    let wrong_bytes = to_json_bytes(&wrong_payload).expect("serialize wrong payload");

    let err_wrong_key = process_dead_drop(
        invite_uuid,
        Some(&format!("Bearer {wrong_key_token}")),
        &wrong_bytes,
        &mut room_state,
        &mut sockets,
    )
    .expect_err("wrong key HMAC must be rejected");
    assert_eq!(err_wrong_key, NetworkError::ForbiddenHmac);
    assert_eq!(err_wrong_key.status_code(), 403);
    assert!(!room_state.is_burned(invite_uuid));
    assert!(sockets[0].sent_messages.is_empty());

    // Also test empty token
    let empty_token_payload = sample_drop_payload(invite_uuid, "   ");
    let empty_token_bytes = to_json_bytes(&empty_token_payload).expect("serialize");
    let err_empty = process_dead_drop(
        invite_uuid,
        None,
        &empty_token_bytes,
        &mut room_state,
        &mut sockets,
    )
    .expect_err("empty token must be rejected");
    assert_eq!(err_empty, NetworkError::ForbiddenHmac);
    assert_eq!(err_empty.status_code(), 403);
}

#[test]
fn test_dead_drop_burns_uuid_and_rejects_replay_with_410() {
    let host_secret = [0x77u8; 32];
    let invite_uuid = "invite-single-use-42";

    let mut host_socket = MockHostSocket::new();
    process_host_upgrade(
        Some("websocket"),
        Some(&hex::encode(host_secret)),
        &mut host_socket,
    )
    .expect("host upgrade");

    let mut sockets = vec![host_socket];
    let mut room_state = EphemeralRoomState::new();

    let token = compute_invite_token(&host_secret, invite_uuid)
        .expect("compute token")
        .hmac_hex;
    let payload = sample_drop_payload(invite_uuid, &token);
    let body_bytes = to_json_bytes(&payload).expect("serialize payload");

    // First submission succeeds with HTTP 200 and burns the invite_uuid
    let first_res = process_dead_drop(
        invite_uuid,
        Some(&format!("Bearer {token}")),
        &body_bytes,
        &mut room_state,
        &mut sockets,
    )
    .expect("first dead drop should succeed");
    assert_eq!(first_res.status, 200);
    assert!(room_state.is_burned(invite_uuid));
    assert_eq!(room_state.burned_count(), 1);
    assert_eq!(sockets[0].sent_messages.len(), 1);

    // Second submission (replay) with identical valid token is rejected with HTTP 410 Gone
    let replay_err = process_dead_drop(
        invite_uuid,
        Some(&format!("Bearer {token}")),
        &body_bytes,
        &mut room_state,
        &mut sockets,
    )
    .expect_err("replayed invite_uuid must fail with 410 Gone");
    assert_eq!(replay_err, NetworkError::InviteAlreadyBurned);
    assert_eq!(replay_err.status_code(), 410);

    // Ensure no second message was piped to the host WebSocket
    assert_eq!(sockets[0].sent_messages.len(), 1);
}

#[test]
fn test_valid_dead_drop_pipes_answer_to_hibernating_websocket() {
    let host_secret = [0x33u8; 32];
    let invite_uuid = "invite-e2e-handshake-001";

    // Step 1: Host upgrades WebSocket and hibernates with attached secret
    let mut host_socket = MockHostSocket::new();
    let upgrade_res = process_host_upgrade(
        Some("websocket"),
        Some(&URL_SAFE_NO_PAD.encode(host_secret)),
        &mut host_socket,
    )
    .expect("host upgrade should succeed");
    assert_eq!(upgrade_res.status, 101);
    assert!(host_socket.hibernating);

    // Step 2: Host generates HMAC-SHA256 invite token
    let invite_token = compute_invite_token(&host_secret, invite_uuid).expect("compute token");

    // Step 3: Joiner posts DropPayload containing SDP answer and X25519 public key
    let expected_payload = sample_drop_payload(invite_uuid, &invite_token.hmac_hex);
    let body_bytes = to_json_bytes(&expected_payload).expect("serialize DropPayload");

    let mut sockets = vec![host_socket];
    let mut room_state = EphemeralRoomState::new();

    let drop_res = process_dead_drop(
        invite_uuid,
        None,
        &body_bytes,
        &mut room_state,
        &mut sockets,
    )
    .expect("valid dead drop should succeed");
    assert_eq!(drop_res.status, 200);
    assert_eq!(drop_res.body, r#"{"status":"ok"}"#);

    // Step 4: Host receives the exact DropPayload over the awakened WebSocket
    assert_eq!(sockets[0].sent_messages.len(), 1);
    let forwarded_json = &sockets[0].sent_messages[0];
    let received_payload: DropPayload =
        from_json_str(forwarded_json).expect("deserialize forwarded DropPayload");
    assert_eq!(received_payload, expected_payload);
}

#[test]
fn test_dead_drop_preserves_joiner_peer_id_to_host_websocket() {
    let host_secret = [0x44u8; 32];
    let invite_uuid = "invite-joiner-peer-id-001";

    let mut host_socket = MockHostSocket::new();
    process_host_upgrade(
        Some("websocket"),
        Some(&hex::encode(host_secret)),
        &mut host_socket,
    )
    .expect("host upgrade should succeed");

    let invite_token = compute_invite_token(&host_secret, invite_uuid).expect("compute token");

    let joiner_kp = X25519Keypair::from_private_key([0x55; 32]);
    let payload = DropPayload {
        invite_uuid: invite_uuid.to_string(),
        token: invite_token.hmac_hex.clone(),
        sdp_answer: SdpAnswer {
            sdp: "v=0\r\no=- 100 2 IN IP4 127.0.0.1\r\na=setup:active\r\n".to_string(),
        },
        joiner_public_key: *joiner_kp.public_key_bytes(),
        joiner_peer_id: Some("peer-bob-assigned-123".to_string()),
        joiner_signing_key: None,
        sealed_sdp_answer: None,
        signature: None,
    };
    let body_bytes = to_json_bytes(&payload).expect("serialize DropPayload");

    let mut sockets = vec![host_socket];
    let mut room_state = EphemeralRoomState::new();

    let drop_res = process_dead_drop(
        invite_uuid,
        None,
        &body_bytes,
        &mut room_state,
        &mut sockets,
    )
    .expect("dead drop with joiner_peer_id should succeed");
    assert_eq!(drop_res.status, 200);

    // Host receives the exact DropPayload containing joiner_peer_id
    assert_eq!(sockets[0].sent_messages.len(), 1);
    let forwarded_json = &sockets[0].sent_messages[0];
    assert!(forwarded_json.contains("\"joiner_peer_id\":\"peer-bob-assigned-123\""));

    let received_payload: DropPayload =
        from_json_str(forwarded_json).expect("deserialize forwarded DropPayload");
    assert_eq!(received_payload, payload);
    assert_eq!(
        received_payload.joiner_peer_id.as_deref(),
        Some("peer-bob-assigned-123")
    );
}

#[test]
fn test_dead_drop_edge_cases_and_dos_guards() {
    let host_secret = [0xAAu8; 32];
    let invite_uuid = "invite-edge-case";

    let mut host_socket = MockHostSocket::new();
    process_host_upgrade(
        Some("websocket"),
        Some(&hex::encode(host_secret)),
        &mut host_socket,
    )
    .expect("host upgrade");
    let mut sockets = vec![host_socket];
    let mut room_state = EphemeralRoomState::new();

    let valid_token = compute_invite_token(&host_secret, invite_uuid)
        .expect("token")
        .hmac_hex;
    let valid_payload = sample_drop_payload(invite_uuid, &valid_token);
    let valid_bytes = to_json_bytes(&valid_payload).expect("bytes");

    // 1. Mismatched path_invite_uuid vs payload.invite_uuid -> 400 Bad Request
    let err_mismatch = process_dead_drop(
        "different-invite-uuid",
        None,
        &valid_bytes,
        &mut room_state,
        &mut sockets,
    )
    .expect_err("mismatched invite_uuid must fail");
    assert_eq!(err_mismatch, NetworkError::InviteUuidMismatch);
    assert_eq!(err_mismatch.status_code(), 400);

    // 2. Oversized payload (> MAX_DROP_BODY_BYTES) -> 413 Payload Too Large
    let oversized = vec![b'a'; MAX_DROP_BODY_BYTES + 1];
    let err_large = process_dead_drop(invite_uuid, None, &oversized, &mut room_state, &mut sockets)
        .expect_err("oversized body must fail");
    assert_eq!(err_large, NetworkError::PayloadTooLarge);
    assert_eq!(err_large.status_code(), 413);

    // 3. Mismatched Authorization: Bearer header vs payload.token -> 403 Forbidden
    let err_header_mismatch = process_dead_drop(
        invite_uuid,
        Some("Bearer conflicting-token"),
        &valid_bytes,
        &mut room_state,
        &mut sockets,
    )
    .expect_err("conflicting header token must fail");
    assert_eq!(err_header_mismatch, NetworkError::ForbiddenHmac);
    assert_eq!(err_header_mismatch.status_code(), 403);

    // 4. Missing host socket -> 404 Not Found
    let mut empty_sockets: Vec<MockHostSocket> = Vec::new();
    let err_no_host = process_dead_drop(
        invite_uuid,
        None,
        &valid_bytes,
        &mut room_state,
        &mut empty_sockets,
    )
    .expect_err("missing host socket must return 404");
    assert_eq!(err_no_host, NetworkError::HostSocketUnavailable);
    assert_eq!(err_no_host.status_code(), 404);

    // 5. Burn capacity exhaustion -> 429 Too Many Requests
    let mut full_state = EphemeralRoomState::new();
    for i in 0..MAX_BURNED_UUIDS {
        assert!(full_state.burn_uuid(format!("burned-{i}")));
    }
    let err_capacity = process_dead_drop(
        invite_uuid,
        None,
        &valid_bytes,
        &mut full_state,
        &mut sockets,
    )
    .expect_err("full burn table must return 429");
    assert_eq!(err_capacity, NetworkError::BurnCapacityExceeded);
    assert_eq!(err_capacity.status_code(), 429);
}

#[test]
fn test_ice_endpoint_returns_default_stun_fallback() {
    let resp = process_ice_servers(None);
    assert_eq!(resp.status, 200);

    let json: serde_json::Value = serde_json::from_str(&resp.body).expect("parse JSON body");

    assert!(json.get("iceServers").is_some());
    let ice_servers = json["iceServers"]
        .as_array()
        .expect("iceServers should be an array");
    assert_eq!(ice_servers.len(), 2);

    let urls: Vec<&str> = ice_servers
        .iter()
        .map(|s| s["urls"].as_str().expect("urls string"))
        .collect();
    assert_eq!(
        urls,
        vec![
            "stun:stun.cloudflare.com:3478",
            "stun:stun.l.google.com:19302"
        ]
    );

    // Verify default_ice_servers_json helper consistency
    assert_eq!(json, default_ice_servers_json());
}

#[test]
fn test_parse_custom_ice_servers_modes() {
    // Mode 2a: Valid array wrapped into { "iceServers": ... }
    let raw_arr = r#"[{"urls":"turn:turn.example.com:3478","username":"user","credential":"pwd"}]"#;
    let parsed_arr = parse_custom_ice_servers(raw_arr).expect("parse custom array");
    let arr = parsed_arr["iceServers"]
        .as_array()
        .expect("iceServers array");
    assert_eq!(arr.len(), 1);
    assert_eq!(arr[0]["urls"], "turn:turn.example.com:3478");

    // Mode 2b: Valid object already containing iceServers
    let raw_obj = r#"{"iceServers":[{"urls":"turn:turn.override.com:3478"}]}"#;
    let parsed_obj = parse_custom_ice_servers(raw_obj).expect("parse custom object");
    let arr2 = parsed_obj["iceServers"]
        .as_array()
        .expect("iceServers array");
    assert_eq!(arr2.len(), 1);
    assert_eq!(arr2[0]["urls"], "turn:turn.override.com:3478");

    // Mode 2c: Flat credential object containing urls
    let raw_flat = r#"{"urls":"turn:turn.cloudflare.com:3478","username":"u","credential":"p"}"#;
    let parsed_flat = parse_custom_ice_servers(raw_flat).expect("parse flat credential object");
    let arr3 = parsed_flat["iceServers"]
        .as_array()
        .expect("iceServers array");
    assert_eq!(arr3.len(), 1);
    assert_eq!(arr3[0]["urls"], "turn:turn.cloudflare.com:3478");
    assert_eq!(arr3[0]["username"], "u");
    assert_eq!(arr3[0]["credential"], "p");

    // Malformed JSON -> None
    assert!(parse_custom_ice_servers("not valid json").is_none());

    // Object without iceServers -> None
    assert!(parse_custom_ice_servers(r#"{"other":"key"}"#).is_none());

    // Primitive number -> None
    assert!(parse_custom_ice_servers("123").is_none());
}

#[test]
fn test_stage_invite_and_match_atomic_consumption() {
    let host_secret = [0x11u8; 32];
    let host_hex = hex::encode(host_secret);
    let mut host_socket = MockHostSocket::new();
    process_host_upgrade(Some("websocket"), Some(&host_hex), &mut host_socket)
        .expect("host upgrade");

    let mut sockets = vec![host_socket];
    let room_state = EphemeralRoomState::new();

    // 1. Initial match with no staged invites -> 200 OK with MatchResponse::Empty
    let match_res_empty =
        process_match_request(&room_state, &mut sockets, 0).expect("match request should succeed");
    assert_eq!(match_res_empty.status, 200);
    let decoded_empty: MatchResponse =
        from_json_str(&match_res_empty.body).expect("deserialize MatchResponse::Empty");
    assert_eq!(decoded_empty, MatchResponse::Empty);
    assert_eq!(match_res_empty.body, r#"{"status":"empty"}"#);

    // 2. Host stages a valid invite via process_stage_invite
    let invite_uuid = "staged-invite-001";
    let token = compute_invite_token(&host_secret, invite_uuid)
        .expect("compute token")
        .hmac_hex;
    let invite = sample_invite_payload("room-alpha", invite_uuid, &token, [0x22u8; 32]);
    let stage_req = StageInviteRequest {
        invite: invite.clone(),
    };
    let stage_bytes = to_json_bytes(&stage_req).expect("serialize StageInviteRequest");

    let stage_res = process_stage_invite(
        Some(&format!("Bearer {host_hex}")),
        &stage_bytes,
        &room_state,
        &mut sockets,
    )
    .expect("stage invite should succeed");
    assert_eq!(stage_res.status, 200);

    // Verify attachment now contains staged_invite
    let att = sockets[0].recover_host_secret().unwrap().unwrap();
    assert_eq!(att.staged_invite, Some(invite.clone()));

    // 3. Match request selects the staged invite and atomically clears it
    let match_res = process_match_request(&room_state, &mut sockets, 0)
        .expect("match request with staged invite");
    assert_eq!(match_res.status, 200);
    let decoded_match: MatchResponse =
        from_json_str(&match_res.body).expect("deserialize MatchResponse::Matched");
    assert_eq!(decoded_match, MatchResponse::Matched { invite });

    // 4. Verify socket attachment had staged_invite atomically cleared (now None)
    let att_after = sockets[0].recover_host_secret().unwrap().unwrap();
    assert_eq!(att_after.staged_invite, None);

    // 5. Subsequent match request is Empty
    let match_res_empty2 =
        process_match_request(&room_state, &mut sockets, 0).expect("second match should be empty");
    let decoded_empty2: MatchResponse =
        from_json_str(&match_res_empty2.body).expect("deserialize MatchResponse::Empty");
    assert_eq!(decoded_empty2, MatchResponse::Empty);
}

#[test]
fn test_stage_invite_authorization_and_hmac_validation() {
    let host_secret = [0x33u8; 32];
    let host_hex = hex::encode(host_secret);
    let mut host_socket = MockHostSocket::new();
    process_host_upgrade(Some("websocket"), Some(&host_hex), &mut host_socket)
        .expect("host upgrade");

    let mut sockets = vec![host_socket];
    let mut room_state = EphemeralRoomState::new();

    let invite_uuid = "secure-invite-002";
    let valid_token = compute_invite_token(&host_secret, invite_uuid)
        .expect("compute token")
        .hmac_hex;
    let valid_invite = sample_invite_payload("room-beta", invite_uuid, &valid_token, [0x44u8; 32]);
    let valid_bytes = to_json_bytes(&valid_invite).expect("serialize invite");

    // 1. Missing or invalid secret -> 400 Bad Request
    let err_no_sec = process_stage_invite(None, &valid_bytes, &room_state, &mut sockets)
        .expect_err("missing secret must fail");
    assert_eq!(err_no_sec, NetworkError::InvalidHostSecret);
    assert_eq!(err_no_sec.status_code(), 400);

    // 2. Secret does not match any connected host socket -> 404 HostSocketUnavailable
    let wrong_host_secret = [0x99u8; 32];
    let wrong_hex = hex::encode(wrong_host_secret);
    let err_wrong_sock =
        process_stage_invite(Some(&wrong_hex), &valid_bytes, &room_state, &mut sockets)
            .expect_err("unknown host secret socket must fail");
    assert_eq!(err_wrong_sock, NetworkError::HostSocketUnavailable);
    assert_eq!(err_wrong_sock.status_code(), 404);

    // 3. Tampered token in InvitePayload -> 403 Forbidden
    let tampered_invite =
        sample_invite_payload("room-beta", invite_uuid, "deadbeef-bad-hmac", [0x44u8; 32]);
    let tampered_bytes = to_json_bytes(&tampered_invite).expect("serialize tampered");
    let err_tampered =
        process_stage_invite(Some(&host_hex), &tampered_bytes, &room_state, &mut sockets)
            .expect_err("tampered HMAC must fail");
    assert_eq!(err_tampered, NetworkError::ForbiddenHmac);
    assert_eq!(err_tampered.status_code(), 403);

    // 4. Burned invite UUID -> 410 Gone
    assert!(room_state.burn_uuid(invite_uuid.to_string()));
    let err_burned = process_stage_invite(Some(&host_hex), &valid_bytes, &room_state, &mut sockets)
        .expect_err("burned invite must fail");
    assert_eq!(err_burned, NetworkError::InviteAlreadyBurned);
    assert_eq!(err_burned.status_code(), 410);

    // Ensure socket staged_invite was never populated
    let att = sockets[0].recover_host_secret().unwrap().unwrap();
    assert_eq!(att.staged_invite, None);
}

#[test]
fn test_match_skips_burned_staged_invites() {
    let host_secret = [0x55u8; 32];
    let host_hex = hex::encode(host_secret);
    let mut host_socket = MockHostSocket::new();
    process_host_upgrade(Some("websocket"), Some(&host_hex), &mut host_socket)
        .expect("host upgrade");

    let invite_uuid = "pre-burned-invite-003";
    let token = compute_invite_token(&host_secret, invite_uuid)
        .expect("token")
        .hmac_hex;
    let invite = sample_invite_payload("room-gamma", invite_uuid, &token, [0x66u8; 32]);

    // Attach staged invite directly
    host_socket
        .attach_host_secret(&HostAttachment::with_staged_invite(host_secret, invite))
        .unwrap();

    let mut sockets = vec![host_socket];
    let mut room_state = EphemeralRoomState::new();

    // Burn the UUID in room state
    assert!(room_state.burn_uuid(invite_uuid.to_string()));

    // Match request must skip the burned staged invite and return Empty
    let match_res =
        process_match_request(&room_state, &mut sockets, 0).expect("match request should succeed");
    let decoded: MatchResponse = from_json_str(&match_res.body).expect("deserialize");
    assert_eq!(decoded, MatchResponse::Empty);

    // Staged invite was NOT cleared because it was skipped
    let att = sockets[0].recover_host_secret().unwrap().unwrap();
    assert!(att.staged_invite.is_some());
}

#[test]
fn test_match_pseudo_random_distribution_multiple_hosts() {
    let secret_1 = [0x11u8; 32];
    let secret_2 = [0x22u8; 32];

    let mut sock_1 = MockHostSocket::new();
    process_host_upgrade(Some("websocket"), Some(&hex::encode(secret_1)), &mut sock_1)
        .expect("host 1");
    let mut sock_2 = MockHostSocket::new();
    process_host_upgrade(Some("websocket"), Some(&hex::encode(secret_2)), &mut sock_2)
        .expect("host 2");

    let invite_1 = sample_invite_payload(
        "room-multi",
        "inv-1",
        &compute_invite_token(&secret_1, "inv-1").unwrap().hmac_hex,
        [0xAA; 32],
    );
    let invite_2 = sample_invite_payload(
        "room-multi",
        "inv-2",
        &compute_invite_token(&secret_2, "inv-2").unwrap().hmac_hex,
        [0xBB; 32],
    );

    let mut sockets = vec![sock_1, sock_2];
    let room_state = EphemeralRoomState::new();

    // Stage invites on both hosts
    process_stage_invite(
        Some(&hex::encode(secret_1)),
        &to_json_bytes(&invite_1).unwrap(),
        &room_state,
        &mut sockets,
    )
    .unwrap();
    process_stage_invite(
        Some(&hex::encode(secret_2)),
        &to_json_bytes(&invite_2).unwrap(),
        &room_state,
        &mut sockets,
    )
    .unwrap();

    // With selector_seed = 1: 1 % 2 == index 1 (sock_2) selected
    let res_1 = process_match_request(&room_state, &mut sockets, 1).unwrap();
    let decoded_1: MatchResponse = from_json_str(&res_1.body).unwrap();
    assert_eq!(decoded_1, MatchResponse::Matched { invite: invite_2 });

    // Now only sock_1 has a staged invite: next call must return invite_1
    let res_2 = process_match_request(&room_state, &mut sockets, 5).unwrap();
    let decoded_2: MatchResponse = from_json_str(&res_2.body).unwrap();
    assert_eq!(decoded_2, MatchResponse::Matched { invite: invite_1 });

    // Both consumed -> Empty
    let res_3 = process_match_request(&room_state, &mut sockets, 0).unwrap();
    let decoded_3: MatchResponse = from_json_str(&res_3.body).unwrap();
    assert_eq!(decoded_3, MatchResponse::Empty);
}

#[test]
fn test_multi_host_targeted_dead_drop_routing() {
    let secret_a = [0xAAu8; 32];
    let secret_b = [0xBBu8; 32];
    let secret_c = [0xCCu8; 32];

    let mut sock_a = MockHostSocket::new();
    process_host_upgrade(Some("websocket"), Some(&hex::encode(secret_a)), &mut sock_a).unwrap();
    let mut sock_b = MockHostSocket::new();
    process_host_upgrade(Some("websocket"), Some(&hex::encode(secret_b)), &mut sock_b).unwrap();
    let mut sock_c = MockHostSocket::new();
    process_host_upgrade(Some("websocket"), Some(&hex::encode(secret_c)), &mut sock_c).unwrap();

    let mut sockets = vec![sock_a, sock_b, sock_c];
    let mut room_state = EphemeralRoomState::new();

    // 1. Joiner sends dead drop targeted at Host B's invite UUID
    let uuid_b = "uuid-for-host-b";
    let token_b = compute_invite_token(&secret_b, uuid_b).unwrap().hmac_hex;
    let payload_b = sample_drop_payload(uuid_b, &token_b);
    let bytes_b = to_json_bytes(&payload_b).unwrap();

    let res_b = process_dead_drop(uuid_b, None, &bytes_b, &mut room_state, &mut sockets).unwrap();
    assert_eq!(res_b.status, 200);

    // Verify: STRICTLY socket B received the message; sockets A and C received NOTHING!
    assert!(
        sockets[0].sent_messages.is_empty(),
        "Host A must receive 0 messages"
    );
    assert_eq!(
        sockets[1].sent_messages.len(),
        1,
        "Host B must receive exactly 1 message"
    );
    assert!(
        sockets[2].sent_messages.is_empty(),
        "Host C must receive 0 messages"
    );

    let received_b: DropPayload = from_json_str(&sockets[1].sent_messages[0]).unwrap();
    assert_eq!(received_b, payload_b);

    // 2. Next joiner sends dead drop targeted at Host C's invite UUID
    let uuid_c = "uuid-for-host-c";
    let token_c = compute_invite_token(&secret_c, uuid_c).unwrap().hmac_hex;
    let payload_c = sample_drop_payload(uuid_c, &token_c);
    let bytes_c = to_json_bytes(&payload_c).unwrap();

    let res_c = process_dead_drop(uuid_c, None, &bytes_c, &mut room_state, &mut sockets).unwrap();
    assert_eq!(res_c.status, 200);

    assert!(
        sockets[0].sent_messages.is_empty(),
        "Host A still has 0 messages"
    );
    assert_eq!(
        sockets[1].sent_messages.len(),
        1,
        "Host B still has 1 message"
    );
    assert_eq!(
        sockets[2].sent_messages.len(),
        1,
        "Host C received its message"
    );

    let received_c: DropPayload = from_json_str(&sockets[2].sent_messages[0]).unwrap();
    assert_eq!(received_c, payload_c);

    // 3. Foreign token not matching ANY host -> 403 Forbidden; none of the sockets receive messages
    let foreign_secret = [0xEEu8; 32];
    let uuid_x = "uuid-foreign";
    let token_x = compute_invite_token(&foreign_secret, uuid_x)
        .unwrap()
        .hmac_hex;
    let payload_x = sample_drop_payload(uuid_x, &token_x);
    let bytes_x = to_json_bytes(&payload_x).unwrap();

    let err_foreign = process_dead_drop(uuid_x, None, &bytes_x, &mut room_state, &mut sockets)
        .expect_err("foreign token must fail");
    assert_eq!(err_foreign, NetworkError::ForbiddenHmac);
    assert_eq!(err_foreign.status_code(), 403);

    assert_eq!(sockets[0].sent_messages.len(), 0);
    assert_eq!(sockets[1].sent_messages.len(), 1);
    assert_eq!(sockets[2].sent_messages.len(), 1);
}

#[test]
fn test_stage_and_match_wire_json_serialization() {
    let invite = sample_invite_payload("room-test", "uuid-test", "tok-123", [0x77; 32]);

    // StageInviteRequest
    let req = StageInviteRequest {
        invite: invite.clone(),
    };
    let req_json = to_json_string(&req).unwrap();
    let req_decoded: StageInviteRequest = from_json_str(&req_json).unwrap();
    assert_eq!(req, req_decoded);

    // MatchResponse::Matched
    let res_matched = MatchResponse::Matched {
        invite: invite.clone(),
    };
    let matched_json = to_json_string(&res_matched).unwrap();
    assert!(matched_json.contains(r#""status":"matched""#));
    let matched_decoded: MatchResponse = from_json_str(&matched_json).unwrap();
    assert_eq!(res_matched, matched_decoded);

    // MatchResponse::Empty
    let res_empty = MatchResponse::Empty;
    let empty_json = to_json_string(&res_empty).unwrap();
    assert_eq!(empty_json, r#"{"status":"empty"}"#);
    let empty_decoded: MatchResponse = from_json_str(&empty_json).unwrap();
    assert_eq!(res_empty, empty_decoded);
}

#[test]
fn test_host_query_secret_authentication() {
    let valid_secret = [0x42u8; 32];
    let valid_hex = hex::encode(valid_secret);

    // Direct verification of parse_query_secret
    assert_eq!(parse_query_secret("/host/room1?secret=aabbcc"), Some("aabbcc".to_string()));
    assert_eq!(parse_query_secret("/host/room1?host_secret=ddeeff"), Some("ddeeff".to_string()));
    assert_eq!(parse_query_secret("/host/room1?other=123"), None);

    // Direct verification of authenticate_host
    assert_eq!(authenticate_host(Some(&valid_hex), None).unwrap(), valid_secret);
    assert_eq!(
        authenticate_host(Some("not_a_valid_hex"), None).unwrap_err(),
        NetworkError::Unauthorized
    );

    // 1. GET /host/:do_id?secret=<valid_hex> successfully authenticates
    let mut socket_ok = MockHostSocket::new();
    let url_valid = format!("/host/room-abc?secret={valid_hex}");
    let res = process_host_query_upgrade(Some("websocket"), &url_valid, None, &mut socket_ok)
        .expect("valid query secret upgrade should succeed");
    assert_eq!(res.status, 101);
    assert!(socket_ok.hibernating);
    assert_eq!(
        socket_ok.recover_host_secret().unwrap(),
        Some(HostAttachment::new(valid_secret))
    );

    // Also verify with ?host_secret= alias
    let mut socket_alias = MockHostSocket::new();
    let url_alias = format!("/host/room-abc?host_secret={valid_hex}");
    let res_alias = process_host_query_upgrade(Some("websocket"), &url_alias, None, &mut socket_alias)
        .expect("valid host_secret alias upgrade should succeed");
    assert_eq!(res_alias.status, 101);
    assert!(socket_alias.hibernating);

    // 2. GET /host/:do_id?secret=<invalid_hex> returns 401 Unauthorized
    let mut socket_bad_hex = MockHostSocket::new();
    let err_bad_hex = process_host_query_upgrade(
        Some("websocket"),
        "/host/room-abc?secret=not_a_valid_hex_string_12345",
        None,
        &mut socket_bad_hex,
    )
    .expect_err("invalid hex secret must fail");
    assert_eq!(err_bad_hex, NetworkError::Unauthorized);
    assert_eq!(err_bad_hex.status_code(), 401);
    assert!(!socket_bad_hex.hibernating);

    // Short hex secret (e.g. 8 chars instead of 64 chars) -> 401 Unauthorized
    let mut socket_short_hex = MockHostSocket::new();
    let err_short_hex = process_host_query_upgrade(
        Some("websocket"),
        "/host/room-abc?secret=deadbeef",
        None,
        &mut socket_short_hex,
    )
    .expect_err("short hex secret must fail");
    assert_eq!(err_short_hex, NetworkError::Unauthorized);
    assert_eq!(err_short_hex.status_code(), 401);

    // Missing secret parameter completely -> 401 Unauthorized
    let mut socket_missing = MockHostSocket::new();
    let err_missing = process_host_query_upgrade(
        Some("websocket"),
        "/host/room-abc",
        None,
        &mut socket_missing,
    )
    .expect_err("missing query secret must fail");
    assert_eq!(err_missing, NetworkError::Unauthorized);
    assert_eq!(err_missing.status_code(), 401);

    // 3. Constant-time comparison against expected room secret
    let room_secret = [0x55u8; 32];
    let other_secret = [0x99u8; 32];
    let room_hex = hex::encode(room_secret);
    let other_hex = hex::encode(other_secret);

    // Matching room secret succeeds
    let mut socket_room_match = MockHostSocket::new();
    let res_room = process_host_query_upgrade(
        Some("websocket"),
        &format!("/host/room-abc?secret={room_hex}"),
        Some(&room_secret),
        &mut socket_room_match,
    )
    .expect("matching room secret should succeed");
    assert_eq!(res_room.status, 101);

    // Mismatched room secret returns 401 Unauthorized
    let mut socket_mismatch = MockHostSocket::new();
    let err_mismatch = process_host_query_upgrade(
        Some("websocket"),
        &format!("/host/room-abc?secret={other_hex}"),
        Some(&room_secret),
        &mut socket_mismatch,
    )
    .expect_err("mismatched room secret must return 401");
    assert_eq!(err_mismatch, NetworkError::Unauthorized);
    assert_eq!(err_mismatch.status_code(), 401);

    // Verify constant_time_eq helper directly
    assert!(constant_time_eq(&room_secret, &room_secret));
    assert!(!constant_time_eq(&room_secret, &other_secret));
    assert!(!constant_time_eq(&[1, 2, 3], &[1, 2]));

    // 4. Header precedence over query parameter
    let header_secret = [0x11u8; 32];
    let header_hex = hex::encode(header_secret);
    let query_hex = hex::encode(other_secret);

    // X-Host-Secret takes precedence over ?secret
    let extracted = extract_secret_from_params(Some(&header_hex), None, Some(&query_hex)).unwrap();
    assert_eq!(extracted, header_hex);

    // Authorization: Bearer takes precedence over ?secret
    let auth_header = format!("Bearer {header_hex}");
    let extracted_auth = extract_secret_from_params(None, Some(&auth_header), Some(&query_hex)).unwrap();
    assert_eq!(extracted_auth, header_hex);

    // Fallback to ?secret when headers absent
    let extracted_query = extract_secret_from_params(None, None, Some(&query_hex)).unwrap();
    assert_eq!(extracted_query, query_hex);

    // process_host_upgrade_authenticated with query secret
    let mut socket_auth = MockHostSocket::new();
    let res_auth = process_host_upgrade_authenticated(
        Some("websocket"),
        None,
        None,
        Some(&valid_hex),
        None,
        &mut socket_auth,
    )
    .expect("authenticated upgrade with query secret should succeed");
    assert_eq!(res_auth.status, 101);
}

#[test]
fn test_universal_cors_headers_and_options_preflight() {
    // 1. Target-independent preflight OPTIONS response returns 204 with universal CORS headers
    let preflight = HttpResponse::cors_preflight();
    assert_eq!(preflight.status, 204);
    assert_eq!(
        preflight.get_header("Access-Control-Allow-Origin"),
        Some("*")
    );
    assert_eq!(
        preflight.get_header("Access-Control-Allow-Methods"),
        Some("GET, POST, OPTIONS")
    );
    assert_eq!(
        preflight.get_header("Access-Control-Allow-Headers"),
        Some("Content-Type, Authorization, X-Host-Secret")
    );
    assert_eq!(
        preflight.get_header("Access-Control-Max-Age"),
        Some("86400")
    );

    // 2. /ice endpoint responses have CORS headers attached
    let ice_resp = process_ice_servers(None);
    assert_eq!(ice_resp.status, 200);
    assert_eq!(
        ice_resp.get_header("Access-Control-Allow-Origin"),
        Some("*")
    );
    assert_eq!(
        ice_resp.get_header("Access-Control-Allow-Methods"),
        Some("GET, POST, OPTIONS")
    );
    assert_eq!(
        ice_resp.get_header("Access-Control-Allow-Headers"),
        Some("Content-Type, Authorization, X-Host-Secret")
    );

    // 3. /match/:do_id standard response has CORS headers attached
    let room_state = EphemeralRoomState::new();
    let mut empty_sockets: Vec<MockHostSocket> = Vec::new();
    let match_resp = process_match_request(&room_state, &mut empty_sockets, 0)
        .expect("empty match request");
    assert_eq!(match_resp.status, 200);
    assert_eq!(
        match_resp.get_header("Access-Control-Allow-Origin"),
        Some("*")
    );
    assert_eq!(
        match_resp.get_header("Access-Control-Allow-Methods"),
        Some("GET, POST, OPTIONS")
    );
    assert_eq!(
        match_resp.get_header("Access-Control-Allow-Headers"),
        Some("Content-Type, Authorization, X-Host-Secret")
    );

    // 4. /stage/:do_id standard response has CORS headers attached
    let host_secret = [0x77u8; 32];
    let mut host_socket = MockHostSocket::new();
    process_host_upgrade(
        Some("websocket"),
        Some(&hex::encode(host_secret)),
        &mut host_socket,
    )
    .expect("host upgrade");
    let mut host_sockets = vec![host_socket];
    let invite_token = zero_protocol::crypto::compute_invite_token(&host_secret, "uuid-cors-stage")
        .unwrap()
        .hmac_hex;
    let invite = sample_invite_payload("room-cors", "uuid-cors-stage", &invite_token, [0x88; 32]);
    let stage_bytes = to_json_bytes(&StageInviteRequest { invite }).unwrap();
    let stage_resp = process_stage_invite(
        Some(&hex::encode(host_secret)),
        &stage_bytes,
        &room_state,
        &mut host_sockets,
    )
    .expect("stage invite");
    assert_eq!(stage_resp.status, 200);
    assert_eq!(
        stage_resp.get_header("Access-Control-Allow-Origin"),
        Some("*")
    );
    assert_eq!(
        stage_resp.get_header("Access-Control-Allow-Methods"),
        Some("GET, POST, OPTIONS")
    );
    assert_eq!(
        stage_resp.get_header("Access-Control-Allow-Headers"),
        Some("Content-Type, Authorization, X-Host-Secret")
    );

    // 5. In Wasm runtime contexts, verify worker::Response wrappers directly
    #[cfg(target_arch = "wasm32")]
    {
        let wasm_preflight = cors_preflight_response().expect("create cors preflight response");
        assert_eq!(wasm_preflight.status_code(), 204);
        let headers = wasm_preflight.headers();
        assert_eq!(headers.get("Access-Control-Allow-Origin").unwrap(), Some("*".to_string()));
    }
}
```

## FILE: wrangler.toml
```toml
name = "network"
main = "build/worker/shim.mjs"
compatibility_date = "2025-01-01"

[build]
command = "cargo install -q worker-build@^0.7 && worker-build --release"

[[durable_objects.bindings]]
name = "DEAD_DROP_ROOM"
class_name = "DeadDropRoom"

[[migrations]]
tag = "v1"
new_sqlite_classes = ["DeadDropRoom"]

[vars]
# Optional: Ephemeral Cloudflare Realtime TURN credentials for 4G/5G CGNAT traversal
# Set via: wrangler secret put CF_TURN_KEY_ID
# Set via: wrangler secret put CF_TURN_API_TOKEN
# Optional fallback override: TURN_SERVERS_JSON

[env.production]
name = "network"

[[env.production.durable_objects.bindings]]
name = "DEAD_DROP_ROOM"
class_name = "DeadDropRoom"

[env.production.vars]
# Optional: Ephemeral Cloudflare Realtime TURN credentials for 4G/5G CGNAT traversal
# Set via: wrangler secret put CF_TURN_KEY_ID
# Set via: wrangler secret put CF_TURN_API_TOKEN
# Optional fallback override: TURN_SERVERS_JSON
```

