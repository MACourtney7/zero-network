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

/// Durable Object storage key holding the authoritative 32-byte room secret (hex-encoded).
pub const ROOM_SECRET_STORAGE_KEY: &str = "room_secret";

/// Durable Object storage key holding the current host peer id.
pub const HOST_PEER_ID_STORAGE_KEY: &str = "host_peer_id";

/// Durable Object storage key holding the host claim timestamp (ms since UNIX epoch).
pub const HOST_CLAIMED_AT_STORAGE_KEY: &str = "host_claimed_at";

/// Host election TTL in milliseconds. A dead host releases the room after this window.
pub const HOST_TTL_MS: f64 = 8_000.0;

/// Payload accepted by `POST /stage/:do_id` or sent over active host WebSocket.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StageInviteRequest {
    pub invite: InvitePayload,
}

/// A staged invite together with the peer id of the host that staged it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StagedInvite {
    pub invite: InvitePayload,
    pub host_peer_id: String,
}

/// Response returned by `GET /match/:do_id`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum MatchResponse {
    /// Caller is the elected host for this room.
    Host,
    /// Caller is a joiner and has been assigned a staged invite.
    Joiner {
        invite: InvitePayload,
        assigned_peer_id: String,
    },
    /// Caller is waiting for a host to stage an invite.
    Waiting,
    /// Legacy variant retained for backward compatibility with existing tests.
    Matched { invite: InvitePayload },
    /// Legacy variant retained for backward compatibility with existing tests.
    Empty,
}

pub const CORS_ALLOW_ORIGIN: &str = "*";
pub const CORS_ALLOW_METHODS: &str = "GET, POST, OPTIONS";
pub const CORS_ALLOW_HEADERS: &str = "Content-Type, Authorization, X-Host-Secret, X-Peer-Id";
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

    // Preserve the socket's existing host_peer_id when re-attaching the staged invite.
    let existing_peer_id = host_sockets[target_idx]
        .recover_host_secret()
        .ok()
        .flatten()
        .and_then(|att| att.host_peer_id);
    let attachment = HostAttachment {
        host_secret,
        staged_invite: Some(invite),
        host_peer_id: existing_peer_id,
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
    let mut staged_match_idx: Option<usize> = None;
    let mut hmac_match_idx: Option<usize> = None;

    // Pass 1: prefer a socket that staged this exact invite AND whose HMAC verifies.
    // A matching staged UUID alone is not sufficient authorization.
    for (idx, sock) in host_sockets.iter().enumerate() {
        if let Some(att) = sock
            .recover_host_secret()
            .map_err(NetworkError::SocketError)?
        {
            found_any_attachment = true;
            let staged_matches = att
                .staged_invite
                .as_ref()
                .map(|i| i.invite_uuid.as_str())
                == Some(path_invite_uuid);
            if staged_matches
                && verify_invite_token(&att.host_secret, path_invite_uuid, token).is_ok()
            {
                staged_match_idx = Some(idx);
                break;
            }
        }
    }

    // Pass 2: fall back to any socket whose HMAC verifies AND that has no staged
    // invite. This preserves backward compatibility with sockets that have no
    // staged invite (e.g. direct host connections and unit tests) while strictly
    // guaranteeing that a socket staged for a different invite is never selected
    // as a fallback for this invite.
    if staged_match_idx.is_none() {
        for (idx, sock) in host_sockets.iter().enumerate() {
            if let Some(att) = sock
                .recover_host_secret()
                .map_err(NetworkError::SocketError)?
            {
                if att.staged_invite.is_none()
                    && verify_invite_token(&att.host_secret, path_invite_uuid, token).is_ok()
                {
                    hmac_match_idx = Some(idx);
                    break;
                }
            }
        }
    }

    if !found_any_attachment {
        return Err(NetworkError::HostSocketUnavailable);
    }

    let was_staged = staged_match_idx.is_some();
    let target_idx = staged_match_idx
        .or(hmac_match_idx)
        .ok_or(NetworkError::ForbiddenHmac)?;

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

    // Clear staged invite only after successful send so failed delivery does not drop the reservation
    if was_staged {
        if let Ok(Some(mut att)) = host_sockets[target_idx].recover_host_secret() {
            att.staged_invite = None;
            let _ = host_sockets[target_idx].attach_host_secret(&att);
        }
    }

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
        "Content-Type, Authorization, X-Host-Secret, X-Peer-Id",
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

    // Record the owning host peer id (if provided) so staged invites can be
    // filtered to the active host during `/match`. Prefer the `X-Peer-Id`
    // header; fall back to the `?peer_id=...` query parameter for browser
    // WebSocket clients that cannot set custom headers.
    let mut attachment = HostAttachment::new(host_secret);
    let header_peer_id = req
        .headers()
        .get("X-Peer-Id")
        .ok()
        .flatten()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty());
    let peer_id = match header_peer_id {
        Some(p) => Some(p),
        None => req
            .url()
            .ok()
            .and_then(|u| parse_query_peer_id(u.as_str())),
    };
    if let Some(peer_id) = peer_id {
        attachment = attachment.with_host_peer_id(peer_id);
    }

    if let Err(err) = server.attach_host_secret(&attachment) {
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

/// Returns the current UNIX epoch time in milliseconds as `f64`.
pub fn now_ms() -> f64 {
    #[cfg(target_arch = "wasm32")]
    {
        worker::js_sys::Date::now()
    }
    #[cfg(not(target_arch = "wasm32"))]
    {
        use std::time::{SystemTime, UNIX_EPOCH};
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_millis() as f64)
            .unwrap_or(0.0)
    }
}

/// Generates 32 cryptographically-random bytes for a fresh room secret.
///
/// Uses the platform CSPRNG (`crypto.getRandomValues` on wasm, `getrandom` on native).
/// Panics only if the platform CSPRNG is unavailable, which is a fatal misconfiguration.
pub fn generate_room_secret() -> [u8; 32] {
    let mut buf = [0u8; 32];
    fill_secure_random(&mut buf)
        .expect("platform CSPRNG unavailable: cannot generate room secret");
    buf
}

/// Fills `buf` with cryptographically-secure random bytes from the platform CSPRNG.
pub fn fill_secure_random(buf: &mut [u8]) -> std::result::Result<(), String> {
    #[cfg(target_arch = "wasm32")]
    {
        use worker::js_sys;
        let len = buf.len();
        let arr = js_sys::Uint8Array::new_with_length(len as u32);
        let crypto = js_sys::Reflect::get(&js_sys::global(), &js_sys::JsString::from("crypto"))
            .ok()
            .filter(|c| !c.is_undefined() && !c.is_null())
            .ok_or_else(|| "crypto object unavailable".to_string())?;
        let get_random_values =
            js_sys::Reflect::get(&crypto, &js_sys::JsString::from("getRandomValues"))
                .ok()
                .and_then(|f| f.dyn_ref::<js_sys::Function>().cloned())
                .ok_or_else(|| "crypto.getRandomValues unavailable".to_string())?;
        // Web Crypto requires the `Crypto` object as `this`; passing UNDEFINED throws.
        get_random_values
            .call1(&crypto, &arr)
            .map_err(|_| "crypto.getRandomValues failed".to_string())?;
        arr.copy_to(buf);
        Ok(())
    }
    #[cfg(not(target_arch = "wasm32"))]
    {
        getrandom::getrandom(buf).map_err(|e| format!("getrandom failed: {e}"))
    }
}

/// Loads the authoritative room secret from DO storage, generating and persisting one if absent.
pub async fn load_or_init_room_secret(state: &State) -> Result<[u8; 32]> {
    let storage = state.storage();
    if let Ok(Some(hex_secret)) = storage.get::<String>(ROOM_SECRET_STORAGE_KEY).await {
        if let Ok(bytes) = hex::decode(hex_secret.trim()) {
            if bytes.len() == 32 {
                let mut secret = [0u8; 32];
                secret.copy_from_slice(&bytes);
                return Ok(secret);
            }
        }
    }
    let secret = generate_room_secret();
    storage
        .put(ROOM_SECRET_STORAGE_KEY, hex::encode(secret))
        .await?;
    Ok(secret)
}

/// Scans host sockets for the first unburned staged invite, returning it if present.
pub fn find_staged_invite<S: HibernatingSocket>(
    room_state: &EphemeralRoomState,
    host_sockets: &[S],
) -> Option<InvitePayload> {
    for sock in host_sockets.iter() {
        if let Ok(Some(att)) = sock.recover_host_secret() {
            if let Some(ref inv) = att.staged_invite {
                if !room_state.is_burned(&inv.invite_uuid) {
                    return Some(inv.clone());
                }
            }
        }
    }
    None
}

/// Atomically reserves the first unburned, unreserved staged invite for a joiner.
///
/// On success the invite UUID is marked reserved in `room_state` so a concurrent joiner
/// cannot receive the same invite. Returns `None` if no invite is available.
pub fn reserve_staged_invite<S: HibernatingSocket>(
    room_state: &mut EphemeralRoomState,
    host_sockets: &[S],
) -> Option<InvitePayload> {
    for sock in host_sockets.iter() {
        if let Ok(Some(att)) = sock.recover_host_secret() {
            if let Some(ref inv) = att.staged_invite {
                if room_state.is_burned(&inv.invite_uuid) || room_state.is_reserved(&inv.invite_uuid)
                {
                    continue;
                }
                if room_state.reserve_uuid(inv.invite_uuid.clone()) {
                    return Some(inv.clone());
                }
            }
        }
    }
    None
}

/// Reserves the first unburned, unreserved staged invite belonging to `active_host_peer_id`
/// for `joiner_peer_id`. Idempotent: if `joiner_peer_id` already holds a reservation, the
/// same invite is returned without consuming another.
///
/// Returns `None` if no invite is available from the active host.
pub fn reserve_staged_invite_for_peer<S: HibernatingSocket>(
    room_state: &mut EphemeralRoomState,
    host_sockets: &[S],
    active_host_peer_id: &str,
    joiner_peer_id: &str,
) -> Option<InvitePayload> {
    // Idempotent: return the joiner's existing reservation if still valid AND
    // still staged by the currently-active host. Reservations tied to a stale
    // (expired) host are discarded so the joiner can be re-matched.
    if let Some(existing) = room_state.reserved_invite_for(joiner_peer_id) {
        if !room_state.is_burned(&existing.invite_uuid) {
            let still_owned_by_active_host = host_sockets.iter().any(|sock| {
                sock.recover_host_secret()
                    .ok()
                    .flatten()
                    .map(|att| {
                        att.host_peer_id.as_deref() == Some(active_host_peer_id)
                            && att
                                .staged_invite
                                .as_ref()
                                .map(|inv| inv.invite_uuid == existing.invite_uuid)
                                .unwrap_or(false)
                    })
                    .unwrap_or(false)
            });
            if still_owned_by_active_host {
                return Some(existing);
            }
            // Stale reservation: drop it so a fresh invite can be reserved below.
            room_state.clear_reservation(&existing.invite_uuid, joiner_peer_id);
        }
    }

    for sock in host_sockets.iter() {
        if let Ok(Some(att)) = sock.recover_host_secret() {
            // Only serve invites staged by the currently-elected active host.
            // Sockets belonging to stale/dead hosts are ignored.
            let owner_matches = att
                .host_peer_id
                .as_deref()
                .map(|owner| owner == active_host_peer_id)
                .unwrap_or(false);
            if !owner_matches {
                continue;
            }
            if let Some(ref inv) = att.staged_invite {
                if room_state.is_burned(&inv.invite_uuid) || room_state.is_reserved(&inv.invite_uuid)
                {
                    continue;
                }
                if room_state.reserve_uuid_for_peer(inv.invite_uuid.clone(), joiner_peer_id) {
                    room_state.record_reserved_invite(joiner_peer_id, inv.clone());
                    return Some(inv.clone());
                }
            }
        }
    }
    None
}

/// In-memory host election state owned by the Durable Object actor.
///
/// All reads/writes happen synchronously within a single DO actor instance, so host
/// election and invite reservation are strictly serial and atomic.
#[derive(Debug, Default, Clone)]
pub struct HostElectionState {
    pub host_peer_id: Option<String>,
    pub host_claimed_at: Option<f64>,
    pub room_secret: Option<[u8; 32]>,
}

impl HostElectionState {
    pub fn new() -> Self {
        Self::default()
    }

    /// Returns `true` if a host is currently elected and its lease has not expired.
    pub fn is_host_active(&self, now: f64) -> bool {
        match (self.host_peer_id.as_ref(), self.host_claimed_at) {
            (Some(_), Some(ts)) => now <= ts + HOST_TTL_MS,
            _ => false,
        }
    }

    /// Restores host election state from DO storage on cold start.
    ///
    /// Reads `host_peer_id`, `host_claimed_at`, and `room_secret` from persistent
    /// storage. Missing or malformed values are ignored (leaving the field `None`),
    /// which safely falls back to lazy re-election on the next `/match`.
    pub async fn restore_from_storage(&mut self, state: &State) -> Result<()> {
        let storage = state.storage();

        if let Ok(Some(peer_id)) = storage.get::<String>(HOST_PEER_ID_STORAGE_KEY).await {
            let trimmed = peer_id.trim();
            if !trimmed.is_empty() {
                self.host_peer_id = Some(trimmed.to_string());
            }
        }

        if let Ok(Some(claimed_at)) = storage.get::<f64>(HOST_CLAIMED_AT_STORAGE_KEY).await {
            if claimed_at.is_finite() && claimed_at > 0.0 {
                self.host_claimed_at = Some(claimed_at);
            }
        }

        if let Ok(Some(hex_secret)) = storage.get::<String>(ROOM_SECRET_STORAGE_KEY).await {
            if let Ok(bytes) = hex::decode(hex_secret.trim()) {
                if bytes.len() == 32 {
                    let mut secret = [0u8; 32];
                    secret.copy_from_slice(&bytes);
                    self.room_secret = Some(secret);
                }
            }
        }

        Ok(())
    }
}

/// Cloudflare Durable Object adapter for `GET /match/:do_id`.
///
/// Requires a non-empty `X-Peer-Id` header (400 otherwise). Resolves the caller's role
/// using strictly serial in-memory host election:
/// 1. If the caller is the current host (lease valid), refresh the lease and return `status: "host"`.
/// 2. If no host is active, atomically elect the caller as host and return `status: "host"`.
/// 3. Otherwise the caller is a joiner: idempotently reserve a staged invite from the active host.
/// 4. If no invite is available, return `status: "waiting"`.
pub async fn handle_do_match(
    state: &State,
    ephemeral: &RefCell<EphemeralRoomState>,
    election: &mut HostElectionState,
    do_id: &str,
    caller_peer_id: Option<&str>,
) -> Result<Response> {
    // M3: X-Peer-Id is strictly required.
    let peer = match validate_peer_id(caller_peer_id) {
        Ok(p) => p,
        Err(_) => {
            return with_cors(Response::error("Missing or empty X-Peer-Id header", 400)?);
        }
    };

    // H2: Initialize the room secret exactly once, persist it, and cache it in memory.
    // NOTE: `load_or_init_room_secret` awaits, so we must not hold any RefCell borrow here.
    let room_secret = match election.room_secret {
        Some(secret) => secret,
        None => {
            let secret = load_or_init_room_secret(state).await?;
            election.room_secret = Some(secret);
            secret
        }
    };
    // Borrow is scoped and dropped immediately after the synchronous set.
    {
        ephemeral.borrow_mut().set_room_secret(room_secret);
    }
    let room_secret_hex = hex::encode(room_secret);

    let storage = state.storage();
    let now = now_ms();

    // H1: Host-first check — refresh lease if caller is the current host.
    if election.host_peer_id.as_deref() == Some(peer.as_str()) {
        election.host_claimed_at = Some(now);
        storage.put(HOST_CLAIMED_AT_STORAGE_KEY, now).await?;
        let body = serde_json::json!({
            "status": "host",
            "do_id": do_id,
            "room_secret": room_secret_hex,
        });
        let mut resp = Response::ok(serde_json::to_string(&body).unwrap_or_default())?;
        resp.headers_mut().set("Content-Type", "application/json")?;
        return with_cors(resp);
    }

    // H1: If no host is active, atomically elect the caller as host.
    if !election.is_host_active(now) {
        election.host_peer_id = Some(peer.clone());
        election.host_claimed_at = Some(now);
        storage.put(HOST_PEER_ID_STORAGE_KEY, peer.clone()).await?;
        storage.put(HOST_CLAIMED_AT_STORAGE_KEY, now).await?;
        let body = serde_json::json!({
            "status": "host",
            "do_id": do_id,
            "room_secret": room_secret_hex,
        });
        let mut resp = Response::ok(serde_json::to_string(&body).unwrap_or_default())?;
        resp.headers_mut().set("Content-Type", "application/json")?;
        return with_cors(resp);
    }

    // H3/M4/M5: Caller is a joiner. Idempotently reserve an invite from the active host.
    let active_host = election.host_peer_id.clone().unwrap_or_default();
    let mut sockets = state.get_websockets_with_tag(HOST_WEBSOCKET_TAG);
    if sockets.is_empty() {
        sockets = state.get_websockets();
    }
    // Scope the RefCell borrow so it is dropped before any subsequent await.
    let reserved_invite = {
        let mut room_state = ephemeral.borrow_mut();
        reserve_staged_invite_for_peer(&mut room_state, &sockets, &active_host, &peer)
    };

    if let Some(invite) = reserved_invite {
        let body = serde_json::json!({
            "status": "joiner",
            "do_id": do_id,
            "room_secret": room_secret_hex,
            "assigned_peer_id": peer,
            "invite": invite,
        });
        let mut resp = Response::ok(serde_json::to_string(&body).unwrap_or_default())?;
        resp.headers_mut().set("Content-Type", "application/json")?;
        return with_cors(resp);
    }

    // No invite available: caller waits for the active host to stage one.
    let body = serde_json::json!({
        "status": "waiting",
        "do_id": do_id,
        "room_secret": room_secret_hex,
        "host_peer_id": election.host_peer_id,
    });
    let mut resp = Response::ok(serde_json::to_string(&body).unwrap_or_default())?;
    resp.headers_mut().set("Content-Type", "application/json")?;
    with_cors(resp)
}

/// Extracts `?peer_id=<value>` from a URL or query string.
///
/// Used as a fallback for browser WebSocket clients that cannot set the
/// `X-Peer-Id` header on the upgrade request.
pub fn parse_query_peer_id(url_or_query: &str) -> Option<String> {
    let query_part = if let Some(idx) = url_or_query.find('?') {
        &url_or_query[idx + 1..]
    } else {
        url_or_query
    };

    for pair in query_part.split('&') {
        let mut parts = pair.splitn(2, '=');
        let key = parts.next()?.trim();
        if key == "peer_id" {
            let value = parts.next().unwrap_or("").trim();
            if !value.is_empty() {
                return Some(value.to_string());
            }
        }
    }
    None
}

/// Extracts the caller's peer id, preferring the `X-Peer-Id` header over the
/// `?peer_id=` URL query parameter. Returns `None` if neither is present or
/// both are empty after trimming.
pub fn extract_peer_id(
    x_peer_id: Option<&str>,
    query_peer_id: Option<&str>,
) -> Option<String> {
    if let Some(header) = x_peer_id {
        let trimmed = header.trim();
        if !trimmed.is_empty() {
            return Some(trimmed.to_string());
        }
    }
    if let Some(query) = query_peer_id {
        let trimmed = query.trim();
        if !trimmed.is_empty() {
            return Some(trimmed.to_string());
        }
    }
    None
}

/// Validates and normalizes the caller's `X-Peer-Id` header value.
///
/// Returns `Ok(peer_id)` when a non-empty trimmed peer id is present, or
/// `Err(NetworkError::Unauthorized)` (mapped to HTTP 400 by the caller) when
/// the header is missing or empty.
pub fn validate_peer_id(caller_peer_id: Option<&str>) -> std::result::Result<String, NetworkError> {
    match caller_peer_id.map(|s| s.trim()).filter(|s| !s.is_empty()) {
        Some(p) => Ok(p.to_string()),
        None => Err(NetworkError::Unauthorized),
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
