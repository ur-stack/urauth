use argon2::password_hash::{rand_core::OsRng, SaltString};
use argon2::{Argon2, PasswordHasher as Argon2Hasher, PasswordVerifier};

use crate::errors::AuthError;

/// Supported password hashing algorithms.
#[derive(Clone, Debug, Default)]
pub enum HashAlgorithm {
    #[default]
    Bcrypt,
    Argon2,
}

/// Configurable password hasher that supports bcrypt and Argon2.
#[derive(Clone, Debug)]
pub struct PasswordHasher {
    algorithm: HashAlgorithm,
    bcrypt_cost: u32,
}

impl Default for PasswordHasher {
    fn default() -> Self {
        Self {
            algorithm: HashAlgorithm::default(),
            bcrypt_cost: 12,
        }
    }
}

impl PasswordHasher {
    /// Create a new hasher with default settings (bcrypt, cost 12).
    pub fn new() -> Self {
        Self::default()
    }

    /// Create a hasher configured for the given algorithm.
    pub fn with_algorithm(algorithm: HashAlgorithm) -> Self {
        Self {
            algorithm,
            ..Self::default()
        }
    }

    /// Create a bcrypt hasher with a specific cost factor.
    pub fn with_bcrypt_cost(cost: u32) -> Self {
        Self {
            bcrypt_cost: cost,
            ..Self::default()
        }
    }

    /// Hash a password using the configured algorithm.
    pub fn hash(&self, password: &str) -> Result<String, AuthError> {
        match self.algorithm {
            HashAlgorithm::Bcrypt => {
                bcrypt::hash(password, self.bcrypt_cost).map_err(|e| AuthError::PasswordHash {
                    detail: format!("bcrypt hash failed: {e}"),
                })
            }
            HashAlgorithm::Argon2 => {
                let salt = SaltString::generate(&mut OsRng);
                let argon2 = Argon2::default();
                argon2
                    .hash_password(password.as_bytes(), &salt)
                    .map(|h| h.to_string())
                    .map_err(|e| AuthError::PasswordHash {
                        detail: format!("argon2 hash failed: {e}"),
                    })
            }
        }
    }

    /// Verify a password against a hash string.
    ///
    /// Auto-detects the algorithm from the hash prefix:
    /// - `$2b$` or `$2a$` -> bcrypt
    /// - `$argon2` -> Argon2
    pub fn verify(&self, password: &str, hash: &str) -> Result<bool, AuthError> {
        if hash.starts_with("$argon2") {
            let parsed = argon2::password_hash::PasswordHash::new(hash).map_err(|e| {
                AuthError::PasswordHash {
                    detail: format!("invalid argon2 hash: {e}"),
                }
            })?;
            Ok(Argon2::default()
                .verify_password(password.as_bytes(), &parsed)
                .is_ok())
        } else if hash.starts_with("$2b$") || hash.starts_with("$2a$") || hash.starts_with("$2y$")
        {
            bcrypt::verify(password, hash).map_err(|e| AuthError::PasswordHash {
                detail: format!("bcrypt verify failed: {e}"),
            })
        } else {
            Err(AuthError::PasswordHash {
                detail: "unrecognized hash format".to_string(),
            })
        }
    }
}
