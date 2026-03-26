use std::sync::Arc;

use crate::errors::AuthError;
use crate::stores::TokenStore;

/// Service responsible for token revocation checks and operations.
pub struct RevocationService {
    store: Arc<dyn TokenStore>,
}

impl RevocationService {
    pub fn new(store: Arc<dyn TokenStore>) -> Self {
        Self { store }
    }

    /// Check whether the token identified by `jti` has been revoked.
    pub async fn is_revoked(&self, jti: &str) -> Result<bool, AuthError> {
        self.store.is_revoked(jti).await
    }

    /// Revoke a single token by its JTI.
    pub async fn revoke(&self, jti: &str, expires_at: i64) -> Result<(), AuthError> {
        self.store.revoke(jti, expires_at).await
    }

    /// Revoke every token belonging to the given user.
    pub async fn revoke_all_for_user(&self, user_id: &str) -> Result<(), AuthError> {
        self.store.revoke_all_for_user(user_id).await
    }
}
