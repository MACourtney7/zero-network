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
                // The DO is the authority on the room secret. Load (or lazily initialize)
                // it from storage so subsequent /host calls must present the DO-issued token.
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
                let caller_peer_id = req
                    .headers()
                    .get("X-Peer-Id")
                    .ok()
                    .flatten()
                    .filter(|s| !s.trim().is_empty());
                let resp = handle_do_match(
                    &self.state,
                    &self.ephemeral,
                    do_id,
                    caller_peer_id.as_deref(),
                )
                .await?;
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
