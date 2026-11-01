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

/// Target-independent HTTP response representation returned by protocol handlers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HttpResponse {
    pub status: u16,
    pub body: String,
}

/// Signaling protocol errors mapped deterministically to HTTP status codes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NetworkError {
    MissingUpgradeHeader,
    InvalidHostSecret,
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
        return Ok(HttpResponse { status: 200, body });
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
    Ok(HttpResponse { status: 200, body })
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
            };
        }
    }
    HttpResponse {
        status: 200,
        body: serde_json::to_string(&default_ice_servers_json()).unwrap_or_default(),
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
    let upgrade = req.headers().get("Upgrade")?;
    let mut secret = req.headers().get("X-Host-Secret")?;
    if secret.is_none() {
        secret = req.headers().get("Authorization")?;
    }
    if secret.is_none() {
        if let Ok(url) = req.url() {
            for (k, v) in url.query_pairs() {
                if k == "secret" || k == "host_secret" {
                    secret = Some(v.into_owned());
                    break;
                }
            }
        }
    }

    match upgrade.as_deref() {
        Some(val) if val.trim().eq_ignore_ascii_case("websocket") => {}
        _ => {
            let err = NetworkError::MissingUpgradeHeader;
            return Response::error(err.to_string(), err.status_code());
        }
    }

    let raw_secret = match secret.as_deref() {
        Some(s) => s,
        None => {
            let err = NetworkError::InvalidHostSecret;
            return Response::error(err.to_string(), err.status_code());
        }
    };

    if let Err(err) = parse_host_secret(raw_secret) {
        return Response::error(err.to_string(), err.status_code());
    }

    let pair = WebSocketPair::new()?;
    let mut server = pair.server;
    let client = pair.client;

    if let Err(err) = process_host_upgrade(upgrade.as_deref(), Some(raw_secret), &mut server) {
        return Response::error(err.to_string(), err.status_code());
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
        Ok(_) => Response::from_json(&serde_json::json!({ "status": "ok" })),
        Err(err) => Response::error(err.to_string(), err.status_code()),
    }
}

/// Cloudflare Durable Object adapter for `POST /stage/:do_id`.
pub async fn handle_do_stage_invite(
    req: &mut Request,
    state: &State,
    ephemeral: &RefCell<EphemeralRoomState>,
) -> Result<Response> {
    let mut secret = req.headers().get("X-Host-Secret")?;
    if secret.is_none() {
        secret = req.headers().get("Authorization")?;
    }
    if secret.is_none() {
        if let Ok(url) = req.url() {
            for (k, v) in url.query_pairs() {
                if k == "secret" || k == "host_secret" {
                    secret = Some(v.into_owned());
                    break;
                }
            }
        }
    }

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
        Ok(_) => Response::from_json(&serde_json::json!({ "status": "ok" })),
        Err(err) => Response::error(err.to_string(), err.status_code()),
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
            Ok(resp)
        }
        Err(err) => Response::error(err.to_string(), err.status_code()),
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
