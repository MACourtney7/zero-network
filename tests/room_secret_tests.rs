//! Tests for DO-issued room secret persistence and host election primitives.

use zero_network::handlers::{
    generate_room_secret, now_ms, HOST_TTL_MS, ROOM_SECRET_STORAGE_KEY,
};

#[test]
fn test_generate_room_secret_is_32_bytes_and_nonzero() {
    let secret = generate_room_secret();
    assert_eq!(secret.len(), 32);
    assert!(secret.iter().any(|b| *b != 0));
}

#[test]
fn test_generate_room_secret_varies_between_calls() {
    let a = generate_room_secret();
    let b = generate_room_secret();
    assert_ne!(a, b, "two generated secrets should differ");
}

#[test]
fn test_room_secret_storage_key_is_stable() {
    assert_eq!(ROOM_SECRET_STORAGE_KEY, "room_secret");
}

#[test]
fn test_host_ttl_is_short_and_positive() {
    assert!(HOST_TTL_MS > 0.0);
    assert!(HOST_TTL_MS <= 30_000.0);
}

#[test]
fn test_now_ms_is_monotonic_nonzero() {
    let t1 = now_ms();
    let t2 = now_ms();
    assert!(t1 > 0.0);
    assert!(t2 >= t1);
}

#[test]
fn test_room_secret_hex_roundtrip_persists_identical_value() {
    // Simulates two separate /match invocations reading the same stored hex value.
    let secret = generate_room_secret();
    let stored = hex::encode(secret);

    let decode = |s: &str| -> [u8; 32] {
        let bytes = hex::decode(s).unwrap();
        let mut out = [0u8; 32];
        out.copy_from_slice(&bytes);
        out
    };

    let first_read = decode(&stored);
    let second_read = decode(&stored);
    assert_eq!(first_read, second_read);
    assert_eq!(first_read, secret);
}
