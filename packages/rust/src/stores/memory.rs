use std::collections::{HashMap, HashSet};

use tokio::sync::RwLock;

use crate::errors::AuthError;
use super::traits::{SessionData, SessionStore, TokenStore};

// ---------------------------------------------------------------------------
// Token store
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
struct TokenRecord {
    jti: String,
    user_id: String,
    token_type: String,
    expires_at: i64,
    family_id: Option<String>,
    revoked: bool,
}

struct TokenStoreInner {
    tokens: HashMap<String, TokenRecord>,
    user_tokens: HashMap<String, HashSet<String>>,
}

/// In-memory [`TokenStore`] suitable for development and testing.
///
/// When `strict` is `true` (the default), any lookup of an unknown JTI is
/// treated as revoked (fail-closed). Use [`MemoryTokenStore::new_lenient`] to
/// create a store where unknown JTIs are treated as *not* revoked.
pub struct MemoryTokenStore {
    inner: RwLock<TokenStoreInner>,
    strict: bool,
}

impl MemoryTokenStore {
    /// Create a new store in **strict** mode (unknown JTIs are treated as revoked).
    pub fn new() -> Self {
        Self {
            inner: RwLock::new(TokenStoreInner {
                tokens: HashMap::new(),
                user_tokens: HashMap::new(),
            }),
            strict: true,
        }
    }

    /// Create a new store in **lenient** mode (unknown JTIs are treated as valid).
    pub fn new_lenient() -> Self {
        Self {
            inner: RwLock::new(TokenStoreInner {
                tokens: HashMap::new(),
                user_tokens: HashMap::new(),
            }),
            strict: false,
        }
    }
}

impl Default for MemoryTokenStore {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait::async_trait]
impl TokenStore for MemoryTokenStore {
    async fn add_token(
        &self,
        jti: &str,
        user_id: &str,
        token_type: &str,
        expires_at: i64,
        family_id: Option<&str>,
    ) -> Result<(), AuthError> {
        let mut inner = self.inner.write().await;
        let record = TokenRecord {
            jti: jti.to_owned(),
            user_id: user_id.to_owned(),
            token_type: token_type.to_owned(),
            expires_at,
            family_id: family_id.map(|s| s.to_owned()),
            revoked: false,
        };
        inner.tokens.insert(jti.to_owned(), record);
        inner
            .user_tokens
            .entry(user_id.to_owned())
            .or_default()
            .insert(jti.to_owned());
        Ok(())
    }

    async fn is_revoked(&self, jti: &str) -> Result<bool, AuthError> {
        let inner = self.inner.read().await;
        match inner.tokens.get(jti) {
            Some(record) => Ok(record.revoked),
            None => Ok(self.strict), // fail-closed when strict
        }
    }

    async fn revoke(&self, jti: &str, expires_at: i64) -> Result<(), AuthError> {
        let mut inner = self.inner.write().await;
        if let Some(record) = inner.tokens.get_mut(jti) {
            record.revoked = true;
        } else {
            // Insert a revoked placeholder so subsequent lookups see it as revoked
            // regardless of strict mode.
            let record = TokenRecord {
                jti: jti.to_owned(),
                user_id: String::new(),
                token_type: String::new(),
                expires_at,
                family_id: None,
                revoked: true,
            };
            inner.tokens.insert(jti.to_owned(), record);
        }
        Ok(())
    }

    async fn revoke_all_for_user(&self, user_id: &str) -> Result<(), AuthError> {
        let mut inner = self.inner.write().await;
        if let Some(jtis) = inner.user_tokens.get(user_id) {
            let jtis: Vec<String> = jtis.iter().cloned().collect();
            for jti in jtis {
                if let Some(record) = inner.tokens.get_mut(&jti) {
                    record.revoked = true;
                }
            }
        }
        Ok(())
    }

    async fn get_family_id(&self, jti: &str) -> Result<Option<String>, AuthError> {
        let inner = self.inner.read().await;
        Ok(inner.tokens.get(jti).and_then(|r| r.family_id.clone()))
    }

    async fn revoke_family(&self, family_id: &str) -> Result<(), AuthError> {
        let mut inner = self.inner.write().await;
        for record in inner.tokens.values_mut() {
            if record.family_id.as_deref() == Some(family_id) {
                record.revoked = true;
            }
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Session store
// ---------------------------------------------------------------------------

struct SessionStoreInner {
    sessions: HashMap<String, SessionData>,
    user_sessions: HashMap<String, HashSet<String>>,
}

/// In-memory [`SessionStore`] suitable for development and testing.
pub struct MemorySessionStore {
    inner: RwLock<SessionStoreInner>,
}

impl MemorySessionStore {
    pub fn new() -> Self {
        Self {
            inner: RwLock::new(SessionStoreInner {
                sessions: HashMap::new(),
                user_sessions: HashMap::new(),
            }),
        }
    }
}

impl Default for MemorySessionStore {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait::async_trait]
impl SessionStore for MemorySessionStore {
    async fn create(
        &self,
        session_id: &str,
        user_id: &str,
        data: serde_json::Value,
        ttl: u64,
    ) -> Result<(), AuthError> {
        let expires_at = chrono::Utc::now().timestamp() + ttl as i64;
        let session = SessionData {
            user_id: user_id.to_owned(),
            data,
            expires_at,
        };
        let mut inner = self.inner.write().await;
        inner.sessions.insert(session_id.to_owned(), session);
        inner
            .user_sessions
            .entry(user_id.to_owned())
            .or_default()
            .insert(session_id.to_owned());
        Ok(())
    }

    async fn get(&self, session_id: &str) -> Result<Option<SessionData>, AuthError> {
        let now = chrono::Utc::now().timestamp();
        let mut inner = self.inner.write().await;
        if let Some(session) = inner.sessions.get(session_id) {
            if session.expires_at <= now {
                // Auto-cleanup expired session.
                let user_id = session.user_id.clone();
                inner.sessions.remove(session_id);
                if let Some(ids) = inner.user_sessions.get_mut(&user_id) {
                    ids.remove(session_id);
                }
                return Ok(None);
            }
            Ok(Some(session.clone()))
        } else {
            Ok(None)
        }
    }

    async fn delete(&self, session_id: &str) -> Result<(), AuthError> {
        let mut inner = self.inner.write().await;
        if let Some(session) = inner.sessions.remove(session_id) {
            if let Some(ids) = inner.user_sessions.get_mut(&session.user_id) {
                ids.remove(session_id);
            }
        }
        Ok(())
    }

    async fn delete_all_for_user(&self, user_id: &str) -> Result<(), AuthError> {
        let mut inner = self.inner.write().await;
        if let Some(ids) = inner.user_sessions.remove(user_id) {
            for session_id in ids {
                inner.sessions.remove(&session_id);
            }
        }
        Ok(())
    }
}
