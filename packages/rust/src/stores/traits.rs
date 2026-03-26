use serde::{Deserialize, Serialize};

use crate::errors::AuthError;

/// Data associated with an active session.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionData {
    pub user_id: String,
    pub data: serde_json::Value,
    pub expires_at: i64,
}

/// Persistent store for JWT token metadata and revocation state.
#[async_trait::async_trait]
pub trait TokenStore: Send + Sync {
    /// Record a newly-issued token.
    async fn add_token(
        &self,
        jti: &str,
        user_id: &str,
        token_type: &str,
        expires_at: i64,
        family_id: Option<&str>,
    ) -> Result<(), AuthError>;

    /// Check whether a token has been revoked.
    async fn is_revoked(&self, jti: &str) -> Result<bool, AuthError>;

    /// Revoke a single token by its JTI.
    async fn revoke(&self, jti: &str, expires_at: i64) -> Result<(), AuthError>;

    /// Revoke every token belonging to the given user.
    async fn revoke_all_for_user(&self, user_id: &str) -> Result<(), AuthError>;

    /// Return the refresh-token family ID associated with the given JTI.
    async fn get_family_id(&self, jti: &str) -> Result<Option<String>, AuthError>;

    /// Revoke all tokens that share the given family ID (rotation-based revocation).
    async fn revoke_family(&self, family_id: &str) -> Result<(), AuthError>;
}

/// Persistent store for server-side sessions.
#[async_trait::async_trait]
pub trait SessionStore: Send + Sync {
    /// Create a new session with the given TTL (in seconds).
    async fn create(
        &self,
        session_id: &str,
        user_id: &str,
        data: serde_json::Value,
        ttl: u64,
    ) -> Result<(), AuthError>;

    /// Retrieve a session by ID. Returns `None` if expired or missing.
    async fn get(&self, session_id: &str) -> Result<Option<SessionData>, AuthError>;

    /// Delete a single session.
    async fn delete(&self, session_id: &str) -> Result<(), AuthError>;

    /// Delete all sessions belonging to the given user.
    async fn delete_all_for_user(&self, user_id: &str) -> Result<(), AuthError>;
}
