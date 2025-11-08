//! Stratus authentication utilities
//!
//! This library provides password hashing and verification using Argon2id.
//! It is used by both the Stratus server and the password hash generation CLI tool.

use argon2::password_hash::{PasswordHasher, PasswordVerifier, SaltString};
use argon2::{Algorithm, Argon2, Params, PasswordHash, Version};
use rand::rngs::OsRng;

/// Authentication errors
#[derive(Debug, thiserror::Error)]
pub enum AuthError {
    #[error("Failed to hash password: {0}")]
    HashError(String),

    #[error("Invalid password hash format: {0}")]
    InvalidHashFormat(String),

    #[error("Password verification failed: {0}")]
    VerificationError(String),
}

/// Argon2id parameters used for password hashing
///
/// These parameters provide a good balance between security and performance:
/// - Memory cost: 64 MiB (65536 KiB)
/// - Time cost: 3 iterations
/// - Parallelism: 4 threads
///
/// These match the parameters used in the example users.toml hashes.
pub fn get_argon2_params() -> Argon2<'static> {
    let params = Params::new(
        65536, // m_cost: 64 MiB
        3,     // t_cost: 3 iterations
        4,     // p_cost: 4 threads
        None,  // output length (use default)
    )
    .expect("Invalid Argon2 parameters");

    Argon2::new(Algorithm::Argon2id, Version::V0x13, params)
}

/// Hash a password using Argon2id
///
/// This function generates a new random salt and hashes the password using Argon2id.
/// The resulting hash is in PHC string format, suitable for storage in the users.toml file.
///
/// # Arguments
/// * `password` - The plaintext password to hash
///
/// # Returns
/// A PHC-formatted hash string (e.g., "$argon2id$v=19$m=65536,t=3,p=4$...")
///
/// # Example
/// ```
/// use stratus_auth::hash_password;
///
/// let hash = hash_password("my-secret-password").unwrap();
/// println!("Password hash: {}", hash);
/// ```
pub fn hash_password(password: &str) -> Result<String, AuthError> {
    let salt = SaltString::generate(&mut OsRng);
    let argon2 = get_argon2_params();

    let password_hash = argon2
        .hash_password(password.as_bytes(), &salt)
        .map_err(|e| AuthError::HashError(e.to_string()))?
        .to_string();

    Ok(password_hash)
}

/// Verify a password against a stored hash
///
/// This function verifies that the provided password matches the stored Argon2id hash.
///
/// # Arguments
/// * `password` - The plaintext password to verify
/// * `hash` - The stored PHC-formatted hash string
///
/// # Returns
/// `Ok(true)` if the password matches, `Ok(false)` if it doesn't match,
/// or `Err` if the hash is malformed
///
/// # Example
/// ```
/// use stratus_auth::{hash_password, verify_password};
///
/// let hash = hash_password("my-secret-password").unwrap();
/// assert!(verify_password("my-secret-password", &hash).unwrap());
/// assert!(!verify_password("wrong-password", &hash).unwrap());
/// ```
pub fn verify_password(password: &str, hash: &str) -> Result<bool, AuthError> {
    let parsed_hash =
        PasswordHash::new(hash).map_err(|e| AuthError::InvalidHashFormat(e.to_string()))?;

    let argon2 = get_argon2_params();

    match argon2.verify_password(password.as_bytes(), &parsed_hash) {
        Ok(()) => Ok(true),
        Err(argon2::password_hash::Error::Password) => Ok(false),
        Err(e) => Err(AuthError::VerificationError(e.to_string())),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hash_and_verify() {
        let password = "test-password-123";
        let hash = hash_password(password).unwrap();

        // Verify correct password
        assert!(verify_password(password, &hash).unwrap());

        // Verify incorrect password
        assert!(!verify_password("wrong-password", &hash).unwrap());
    }

    #[test]
    fn test_hash_format() {
        let hash = hash_password("test").unwrap();

        // Should start with argon2id identifier
        assert!(hash.starts_with("$argon2id$"));
    }

    #[test]
    fn test_verify_known_hash() {
        // Test with a known hash
        let hash = "$argon2id$v=19$m=65536,t=3,p=4$Y7cQzI7q+5bn/h5VmZw+Qg$xxK+4zLF11OJA5pUj95/kuNvjysSZPpX1nQPhlpZb8M";

        assert!(verify_password("admin123", hash).unwrap());
        assert!(!verify_password("wrong", hash).unwrap());
    }

    #[test]
    fn test_different_salts() {
        let password = "same-password";
        let hash1 = hash_password(password).unwrap();
        let hash2 = hash_password(password).unwrap();

        // Hashes should be different due to different salts
        assert_ne!(hash1, hash2);

        // But both should verify correctly
        assert!(verify_password(password, &hash1).unwrap());
        assert!(verify_password(password, &hash2).unwrap());
    }
}
