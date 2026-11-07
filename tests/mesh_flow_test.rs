//! Mesh flow integration tests for zero_network: CSPRNG, host-first match, and invite reservation.

use std::cell::RefCell;

use zero_network::durable_object::{EphemeralRoomState, HibernatingSocket, HostAttachment, MockHostSocket};
use zero_network::handlers::{
    generate_room_secret, reserve_staged_invite, reserve_staged_invite_for_peer, validate_peer_id,
    HOST_TTL_MS,
};
use zero_protocol::InvitePayload;

fn sample_invite(uuid: &str, token: &str) -> InvitePayload {
    InvitePayload {
        do_id: "room-test".to_string(),
        invite_uuid: uuid.to_string(),
        token: token.to_string(),
        host_public_key: [0x11u8; 32],
        host_peer_id: None,
        assigned_peer_id: None,
        guest_private_key: None,
        host_signing_key: None,
        sdp_offer: zero_protocol::SdpOffer {
            sdp: "v=0\r\n".to_string(),
        },
    }
}

#[test]
fn test_generate_room_secret_returns_32_bytes_without_throwing() {
    let secret = generate_room_secret();
    assert_eq!(secret.len(), 32);
    assert!(secret.iter().any(|b| *b != 0), "secret should not be all zeros");
}

#[test]
fn test_generate_room_secret_varies_between_calls() {
    let a = generate_room_secret();
    let b = generate_room_secret();
    assert_ne!(a, b, "two generated secrets should differ");
}

#[test]
fn test_reserve_staged_invite_is_unique_per_joiner() {
    let host_secret = [0x42u8; 32];
    let mut socket = MockHostSocket::new();
    socket
        .attach_host_secret(&HostAttachment::with_staged_invite(
            host_secret,
            sample_invite("invite-001", "tok-001"),
        ))
        .unwrap();
    let sockets = vec![socket];
    let mut room_state = EphemeralRoomState::new();

    // First joiner reserves the invite.
    let first = reserve_staged_invite(&mut room_state, &sockets);
    assert!(first.is_some(), "first joiner should receive the invite");
    assert_eq!(first.unwrap().invite_uuid, "invite-001");
    assert_eq!(room_state.reserved_count(), 1);

    // Second joiner must NOT receive the same invite.
    let second = reserve_staged_invite(&mut room_state, &sockets);
    assert!(second.is_none(), "second joiner must not get a duplicate invite");
    assert_eq!(room_state.reserved_count(), 1);
}

#[test]
fn test_reserve_staged_invite_skips_burned() {
    let host_secret = [0x43u8; 32];
    let mut socket = MockHostSocket::new();
    socket
        .attach_host_secret(&HostAttachment::with_staged_invite(
            host_secret,
            sample_invite("invite-burned", "tok"),
        ))
        .unwrap();
    let sockets = vec![socket];
    let mut room_state = EphemeralRoomState::new();
    room_state.burn_uuid("invite-burned".to_string());

    let reserved = reserve_staged_invite(&mut room_state, &sockets);
    assert!(reserved.is_none(), "burned invites must not be reserved");
}

#[test]
fn test_host_ttl_constant_is_positive_and_short() {
    assert!(HOST_TTL_MS > 0.0);
    assert!(HOST_TTL_MS <= 30_000.0);
}

#[test]
fn test_ephemeral_room_state_reservation_helpers() {
    let mut state = EphemeralRoomState::new();
    assert!(!state.is_reserved("uuid-x"));
    assert!(state.reserve_uuid("uuid-x".to_string()));
    assert!(state.is_reserved("uuid-x"));
    assert!(!state.reserve_uuid("uuid-x".to_string()), "duplicate reservation rejected");
    assert_eq!(state.reserved_count(), 1);
}

#[test]
fn test_refcell_ephemeral_state_supports_reservation() {
    // Mirrors the DO's RefCell<EphemeralRoomState> usage pattern.
    let ephemeral = RefCell::new(EphemeralRoomState::new());
    {
        let mut state = ephemeral.borrow_mut();
        assert!(state.reserve_uuid("uuid-a".to_string()));
    }
    assert!(ephemeral.borrow().is_reserved("uuid-a"));
}

#[test]
fn test_reserve_staged_invite_for_peer_rejects_non_active_host() {
    // Two host sockets: one owned by the active host, one by a stale host.
    let active_secret = [0x10u8; 32];
    let stale_secret = [0x20u8; 32];

    let mut active_socket = MockHostSocket::new();
    active_socket
        .attach_host_secret(
            &HostAttachment::with_staged_invite(
                active_secret,
                sample_invite("invite-active", "tok-active"),
            )
            .with_host_peer_id("host-active"),
        )
        .unwrap();

    let mut stale_socket = MockHostSocket::new();
    stale_socket
        .attach_host_secret(
            &HostAttachment::with_staged_invite(
                stale_secret,
                sample_invite("invite-stale", "tok-stale"),
            )
            .with_host_peer_id("host-stale"),
        )
        .unwrap();

    let sockets = vec![stale_socket, active_socket];
    let mut room_state = EphemeralRoomState::new();

    // Only the active host's invite should be served.
    let reserved =
        reserve_staged_invite_for_peer(&mut room_state, &sockets, "host-active", "joiner-1");
    assert!(reserved.is_some(), "active host invite should be reserved");
    assert_eq!(reserved.unwrap().invite_uuid, "invite-active");

    // A second joiner must not receive the stale host's invite.
    let second =
        reserve_staged_invite_for_peer(&mut room_state, &sockets, "host-active", "joiner-2");
    assert!(
        second.is_none(),
        "stale host invites must not be served to joiners"
    );
}

#[test]
fn test_match_without_peer_id_is_rejected() {
    // `/match` requires a non-empty X-Peer-Id header; missing/empty must be rejected
    // (mapped to HTTP 400 by `handle_do_match`).
    assert!(validate_peer_id(None).is_err());
    assert!(validate_peer_id(Some("")).is_err());
    assert!(validate_peer_id(Some("   ")).is_err());
    assert_eq!(validate_peer_id(Some("peer-1")).unwrap(), "peer-1");
    assert_eq!(validate_peer_id(Some("  peer-2  ")).unwrap(), "peer-2");
}

#[test]
fn test_reserve_staged_invite_for_peer_ignores_sockets_without_peer_id() {
    // A socket with no recorded host_peer_id must not be treated as the active host.
    let mut socket = MockHostSocket::new();
    socket
        .attach_host_secret(&HostAttachment::with_staged_invite(
            [0x30u8; 32],
            sample_invite("invite-anon", "tok-anon"),
        ))
        .unwrap();

    let sockets = vec![socket];
    let mut room_state = EphemeralRoomState::new();

    let reserved =
        reserve_staged_invite_for_peer(&mut room_state, &sockets, "host-active", "joiner-1");
    assert!(
        reserved.is_none(),
        "sockets without host_peer_id must not be served"
    );
}
