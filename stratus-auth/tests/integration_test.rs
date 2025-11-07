//! Integration test to verify password hashes from CLI work with server
//!
//! This test ensures that the stratus-hashgen CLI and stratus server
//! use consistent password hashing.

use stratus_auth::{hash_password, verify_password};

#[test]
fn test_cli_server_hash_consistency() {
    // Generate a hash (same as CLI does)
    let password = "testpassword123";
    let hash = hash_password(password).unwrap();

    // Verify it works (same as server does)
    assert!(verify_password(password, &hash).unwrap());
    assert!(!verify_password("wrongpassword", &hash).unwrap());
}

#[test]
fn test_verify_with_known_hash() {
    // This is a hash from the example users.toml
    // Generated with the correct parameters (m=65536,t=3,p=4)
    let hash = "$argon2id$v=19$m=65536,t=3,p=4$Y7cQzI7q+5bn/h5VmZw+Qg$xxK+4zLF11OJA5pUj95/kuNvjysSZPpX1nQPhlpZb8M";

    // Server should be able to verify it
    assert!(verify_password("admin123", hash).unwrap());
    assert!(!verify_password("wrong", hash).unwrap());
}

#[test]
fn test_multiple_hashes_same_password() {
    let password = "samepassword";

    // Generate multiple hashes (as users might do with CLI)
    let hash1 = hash_password(password).unwrap();
    let hash2 = hash_password(password).unwrap();

    // They should be different (different salts)
    assert_ne!(hash1, hash2);

    // But both should verify correctly with server
    assert!(verify_password(password, &hash1).unwrap());
    assert!(verify_password(password, &hash2).unwrap());
}
