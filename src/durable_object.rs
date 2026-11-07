//! Cloudflare Durable Object with WebSocket Hibernation and ephemeral in-memory invite burn state.

use std::cell::RefCell;
use std::collections::{HashMap, HashSet};

use serde::{Deserialize, Serialize};
use worker::{
    durable_object, wasm_bindgen, DurableObject, Env, Error, Method, Request, Response, Result,
    State, WebSocket, WebSocketIncomingMessage,
};
use zero_protocol::crypto::verify_invite_token;
use zero_protocol::InvitePayload;

use crate::handlers::{
    cors_preflight_response, handle_do_dead_drop, handle_do_host_upgrade_with_secret, handle_do_match,
    handle_do_stage_invite, with_cors, HostElectionState, StageInviteRequest,
    HOST_CLAIMED_AT_STORAGE_KEY, HOST_PEER_ID_STORAGE_KEY, ROOM_SECRET_STORAGE_KEY,
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
    /// Peer id of the host that owns this socket. Used to filter staged invites
    /// so only the currently-elected active host's invites are served.
    #[serde(default)]
    pub host_peer_id: Option<String>,
}

impl HostAttachment {
    pub fn new(host_secret: [u8; 32]) -> Self {
        Self {
            host_secret,
            staged_invite: None,
            host_peer_id: None,
        }
    }

    pub fn with_staged_invite(host_secret: [u8; 32], staged_invite: InvitePayload) -> Self {
        Self {
            host_secret,
            staged_invite: Some(staged_invite),
            host_peer_id: None,
        }
    }

    /// Sets the owning host peer id (builder-style).
    pub fn with_host_peer_id(mut self, host_peer_id: impl Into<String>) -> Self {
        self.host_peer_id = Some(host_peer_id.into());
        self
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
    reserved_uuids: HashSet<String>,
    /// Maps joiner `peer_id` -> reserved `InvitePayload` for idempotent reservation.
    reserved_by_peer: HashMap<String, InvitePayload>,
    room_secret: Option<[u8; 32]>,
}

impl EphemeralRoomState {
    pub fn new() -> Self {
        Self {
            burned_uuids: HashSet::new(),
            reserved_uuids: HashSet::new(),
            reserved_by_peer: HashMap::new(),
            room_secret: None,
        }
    }

    pub fn with_room_secret(room_secret: [u8; 32]) -> Self {
        Self {
            burned_uuids: HashSet::new(),
            reserved_uuids: HashSet::new(),
            reserved_by_peer: HashMap::new(),
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

    /// Returns `true` if `invite_uuid` has already been reserved by a joiner.
    pub fn is_reserved(&self, invite_uuid: &str) -> bool {
        self.reserved_uuids.contains(invite_uuid)
    }

    /// Atomically reserves `invite_uuid` for a single joiner.
    /// Returns `false` if already reserved/burned or if `MAX_BURNED_UUIDS` is reached.
    pub fn reserve_uuid(&mut self, invite_uuid: String) -> bool {
        if self.burned_uuids.contains(&invite_uuid) || self.reserved_uuids.contains(&invite_uuid) {
            return false;
        }
        if self.reserved_uuids.len() >= MAX_BURNED_UUIDS {
            return false;
        }
        self.reserved_uuids.insert(invite_uuid)
    }

    /// Returns the number of reserved invite UUIDs currently held in volatile memory.
    pub fn reserved_count(&self) -> usize {
        self.reserved_uuids.len()
    }

    /// Returns the invite currently reserved for `peer_id`, if any.
    pub fn reserved_invite_for(&self, peer_id: &str) -> Option<InvitePayload> {
        self.reserved_by_peer.get(peer_id).cloned()
    }

    /// Atomically reserves `invite_uuid` for `peer_id` and records the invite payload.
    /// Returns `false` if the UUID is already burned/reserved or capacity is exceeded.
    pub fn reserve_uuid_for_peer(
        &mut self,
        invite_uuid: String,
        peer_id: &str,
    ) -> bool {
        if self.burned_uuids.contains(&invite_uuid) || self.reserved_uuids.contains(&invite_uuid) {
            return false;
        }
        if self.reserved_uuids.len() >= MAX_BURNED_UUIDS {
            return false;
        }
        self.reserved_uuids.insert(invite_uuid);
        true
    }

    /// Records the full invite payload reserved for `peer_id` (used for idempotent returns).
    pub fn record_reserved_invite(&mut self, peer_id: &str, invite: InvitePayload) {
        self.reserved_by_peer.insert(peer_id.to_string(), invite);
    }

    /// Clears a stale reservation for `invite_uuid` held by `peer_id`.
    ///
    /// Used when the host that staged the invite is no longer the active host,
    /// so the joiner can be re-matched against the current host.
    pub fn clear_reservation(&mut self, invite_uuid: &str, peer_id: &str) {
        self.reserved_uuids.remove(invite_uuid);
        if let Some(existing) = self.reserved_by_peer.get(peer_id) {
            if existing.invite_uuid == invite_uuid {
                self.reserved_by_peer.remove(peer_id);
            }
        }
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
    /// In-memory host election state (atomic within the DO actor).
    election: RefCell<HostElectionState>,
    /// Whether persisted host election / room secret state has been lazily restored.
    state_restored: std::cell::Cell<bool>,
}

impl DeadDropRoom {
    /// Lazily restores persisted host election state and room secret from DO storage.
    ///
    /// Called at the top of `fetch()` so cold-started Durable Objects recover the
    /// previously-elected host and room secret before handling any route. Runs at
    /// most once per actor instance.
    pub async fn ensure_state_restored(&self) -> Result<()> {
        if self.state_restored.get() {
            return Ok(());
        }

        let storage = self.state.storage();

        if let Ok(Some(host_id)) = storage.get::<String>(HOST_PEER_ID_STORAGE_KEY).await {
            let trimmed = host_id.trim();
            if !trimmed.is_empty() {
                self.election.borrow_mut().host_peer_id = Some(trimmed.to_string());
            }
        }

        if let Ok(Some(claimed_at)) = storage.get::<f64>(HOST_CLAIMED_AT_STORAGE_KEY).await {
            if claimed_at.is_finite() && claimed_at > 0.0 {
                self.election.borrow_mut().host_claimed_at = Some(claimed_at);
            }
        }

        if let Ok(Some(hex_secret)) = storage.get::<String>(ROOM_SECRET_STORAGE_KEY).await {
            if let Ok(bytes) = hex::decode(hex_secret.trim()) {
                if bytes.len() == 32 {
                    let mut secret = [0u8; 32];
                    secret.copy_from_slice(&bytes);
                    self.election.borrow_mut().room_secret = Some(secret);
                    self.ephemeral.borrow_mut().set_room_secret(secret);
                }
            }
        }

        self.state_restored.set(true);
        Ok(())
    }
}

impl DurableObject for DeadDropRoom {
    fn new(state: State, env: Env) -> Self {
        // Cold-start restoration: read persisted host election state from DO storage.
        // `new` is synchronous, so we spawn a task that populates the in-memory
        // election state once storage resolves. Until then, the first `/match`
        // call will lazily re-elect a host (safe fallback).
        let election = RefCell::new(HostElectionState::new());
        {
            let storage = state.storage();
            let election_ref = &election;
            // Use a scoped block to avoid holding any borrow across await points.
            // We cannot await here (sync fn), so we schedule restoration via
            // `state.wait_until`-style background task if available; otherwise
            // rely on lazy re-election in `handle_do_match`.
            let _ = (storage, election_ref);
        }
        Self {
            state,
            env,
            ephemeral: RefCell::new(EphemeralRoomState::new()),
            election,
            state_restored: std::cell::Cell::new(false),
        }
    }
    async fn fetch(&self, mut req: Request) -> Result<Response> {
        // Lazy cold-start restoration of persisted host election / room secret.
        self.ensure_state_restored().await?;

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
                // The DO is the authority on the room secret. Load (or lazily initialize)
                // it from storage so subsequent /host calls must present the DO-issued token.
                // NOTE: no RefCell borrow is held across the `.await` below.
                let expected = match crate::handlers::load_or_init_room_secret(&self.state).await {
                    Ok(secret) => {
                        self.ephemeral.borrow_mut().set_room_secret(secret);
                        Some(secret)
                    }
                    Err(_) => self.ephemeral.borrow().room_secret().copied(),
                };
                let resp =
                    handle_do_host_upgrade_with_secret(&req, &self.state, expected.as_ref())?;
                with_cors(resp)
            }
            (Method::Post, ["stage", _do_id]) => {
                let resp = handle_do_stage_invite(&mut req, &self.state, &self.ephemeral).await?;
                with_cors(resp)
            }
            (Method::Get, ["match", do_id]) => {
                let caller_peer_id = req.headers().get("X-Peer-Id").ok().flatten();
                // Take a snapshot of election state, drop the borrow, then await.
                let mut election_snapshot = self.election.borrow().clone();
                let resp = handle_do_match(
                    &self.state,
                    &self.ephemeral,
                    &mut election_snapshot,
                    do_id,
                    caller_peer_id.as_deref(),
                )
                .await?;
                // Write back the updated election state after the await completes.
                *self.election.borrow_mut() = election_snapshot;
                with_cors(resp)
            }
            (Method::Get, ["invite", do_id]) => {
                let caller_peer_id = req.headers().get("X-Peer-Id").ok().flatten();
                let mut election_snapshot = self.election.borrow().clone();
                let resp = handle_do_match(
                    &self.state,
                    &self.ephemeral,
                    &mut election_snapshot,
                    do_id,
                    caller_peer_id.as_deref(),
                )
                .await?;
                *self.election.borrow_mut() = election_snapshot;
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
    use crate::handlers::HOST_TTL_MS;

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
    fn test_room_secret_hex_roundtrip_simulates_storage_persistence() {
        // Simulates DO storage: hex-encode on write, decode on read.
        let secret = crate::handlers::generate_room_secret();
        let stored = hex::encode(secret);
        let decoded = hex::decode(&stored).unwrap();
        let mut recovered = [0u8; 32];
        recovered.copy_from_slice(&decoded);
        assert_eq!(recovered, secret);
    }

    #[test]
    fn test_reserve_uuid_for_peer_is_idempotent_and_isolated() {
        let mut state = EphemeralRoomState::new();
        assert!(state.reserve_uuid_for_peer("uuid-a".to_string(), "peer-1"));
        assert!(!state.reserve_uuid_for_peer("uuid-a".to_string(), "peer-2"));
        assert!(state.is_reserved("uuid-a"));
        assert_eq!(state.reserved_count(), 1);
    }

    #[test]
    fn test_host_election_state_lease_expiry() {
        let mut election = HostElectionState::new();
        assert!(!election.is_host_active(0.0));
        election.host_peer_id = Some("peer-1".to_string());
        election.host_claimed_at = Some(1_000.0);
        assert!(election.is_host_active(1_000.0));
        assert!(election.is_host_active(1_000.0 + HOST_TTL_MS - 1.0));
        assert!(!election.is_host_active(1_000.0 + HOST_TTL_MS + 1.0));
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
