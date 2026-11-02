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
