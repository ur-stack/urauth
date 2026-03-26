use std::collections::HashMap;
use std::sync::Arc;

use async_trait::async_trait;

use crate::config::{validate_config, AuthConfig};
use crate::context::{AuthContext, AuthContextBuilder};
use crate::errors::AuthError;
use crate::lifecycle::TokenLifecycle;
use crate::password::PasswordHasher;
use crate::stores::{MemoryTokenStore, TokenStore};
use crate::tenant::TenantPath;
use crate::types::{IssuedTokenPair, IssueRequest, TokenPayload};

// ---------------------------------------------------------------------------
// AuthCallbacks -- dependency-injection seam for business logic
// ---------------------------------------------------------------------------

#[async_trait]
pub trait AuthCallbacks: Send + Sync {
    type User: Send + Sync + Clone + std::fmt::Debug;

    async fn get_user(&self, user_id: &str) -> Result<Option<Self::User>, AuthError>;
    async fn get_user_by_username(&self, username: &str) -> Result<Option<Self::User>, AuthError>;
    fn get_user_id(&self, user: &Self::User) -> String;
    async fn verify_password(&self, user: &Self::User, password: &str) -> Result<bool, AuthError>;

    async fn get_user_roles(&self, _user: &Self::User) -> Result<Vec<String>, AuthError> {
        Ok(vec![])
    }

    async fn get_user_permissions(&self, _user: &Self::User) -> Result<Vec<String>, AuthError> {
        Ok(vec![])
    }

    async fn resolve_tenant_path(
        &self,
        _user: &Self::User,
        _payload: &TokenPayload,
    ) -> Result<Option<HashMap<String, String>>, AuthError> {
        Ok(None)
    }

    async fn get_tenant_permissions(
        &self,
        _user: &Self::User,
        _level: &str,
        _tenant_id: &str,
    ) -> Result<Vec<String>, AuthError> {
        Ok(vec![])
    }
}

// ---------------------------------------------------------------------------
// Auth -- central orchestrator
// ---------------------------------------------------------------------------

pub struct Auth<C: AuthCallbacks> {
    config: AuthConfig,
    callbacks: Arc<C>,
    lifecycle: TokenLifecycle,
    password_hasher: PasswordHasher,
}

impl<C: AuthCallbacks> Auth<C> {
    pub fn new(
        config: AuthConfig,
        callbacks: C,
        store: Option<Arc<dyn TokenStore>>,
    ) -> Result<Self, AuthError> {
        validate_config(&config)?;

        let store = store.unwrap_or_else(|| Arc::new(MemoryTokenStore::new()));
        let lifecycle = TokenLifecycle::new(config.clone(), store);
        let password_hasher = PasswordHasher::new();

        Ok(Self {
            config,
            callbacks: Arc::new(callbacks),
            lifecycle,
            password_hasher,
        })
    }

    // -- context resolution ---------------------------------------------------

    pub async fn build_context(
        &self,
        raw_token: Option<&str>,
        optional: bool,
    ) -> Result<AuthContext, AuthError> {
        let token = match raw_token {
            Some(t) if !t.is_empty() => t,
            _ if optional => return Ok(AuthContext::anonymous()),
            _ => {
                return Err(AuthError::Unauthorized {
                    detail: "No token provided".into(),
                })
            }
        };

        let payload = self.lifecycle.validate(token).await?;

        let user = self
            .callbacks
            .get_user(&payload.sub)
            .await?
            .ok_or_else(|| AuthError::Unauthorized {
                detail: "User not found".into(),
            })?;

        // Roles: prefer token-embedded, fall back to callback.
        let roles = match &payload.roles {
            Some(r) if !r.is_empty() => r.clone(),
            _ => self.callbacks.get_user_roles(&user).await?,
        };

        // Permissions: prefer token-embedded, fall back to callback.
        let permissions = match &payload.permissions {
            Some(p) if !p.is_empty() => p.clone(),
            _ => self.callbacks.get_user_permissions(&user).await?,
        };

        // Tenant resolution.
        let tenant_path = match &payload.tenant_path {
            Some(tp) if !tp.is_empty() => Some(tp.clone()),
            _ => self.callbacks.resolve_tenant_path(&user, &payload).await?,
        };

        let mut builder = AuthContextBuilder::new()
            .user_id(&payload.sub)
            .roles(roles)
            .permissions(permissions)
            .token(payload)
            .authenticated(true);

        if let Some(tp) = tenant_path {
            let tenant = TenantPath::from_claim(&tp);
            builder = builder.tenant(tenant);
        }

        Ok(builder.build())
    }

    // -- authentication -------------------------------------------------------

    pub async fn authenticate(
        &self,
        username: &str,
        password: &str,
    ) -> Result<IssuedTokenPair, AuthError> {
        let user = self
            .callbacks
            .get_user_by_username(username)
            .await?
            .ok_or_else(|| AuthError::Unauthorized {
                detail: "Invalid credentials".into(),
            })?;

        let valid = self.callbacks.verify_password(&user, password).await?;
        if !valid {
            return Err(AuthError::Unauthorized {
                detail: "Invalid credentials".into(),
            });
        }

        let user_id = self.callbacks.get_user_id(&user);
        let roles = self.callbacks.get_user_roles(&user).await?;

        // Build a dummy payload for tenant resolution.
        let dummy_payload = TokenPayload {
            sub: user_id.clone(),
            jti: String::new(),
            iat: 0,
            exp: 0,
            token_type: "access".into(),
            scopes: None,
            roles: Some(roles.clone()),
            permissions: None,
            tenant_id: None,
            tenant_path: None,
            fresh: Some(true),
            family_id: None,
            extra: HashMap::new(),
        };

        let tenant_path = self
            .callbacks
            .resolve_tenant_path(&user, &dummy_payload)
            .await?;

        let request = IssueRequest {
            user_id,
            scopes: None,
            roles: Some(roles),
            tenant_id: None,
            tenant_path,
            fresh: Some(true),
            extra_claims: None,
        };

        self.lifecycle.issue(request).await
    }

    // -- token operations -----------------------------------------------------

    pub async fn refresh(&self, raw_refresh_token: &str) -> Result<IssuedTokenPair, AuthError> {
        self.lifecycle.refresh(raw_refresh_token).await
    }

    pub async fn revoke(&self, raw_token: &str) -> Result<(), AuthError> {
        self.lifecycle.revoke(raw_token).await
    }

    pub async fn revoke_all(&self, user_id: &str) -> Result<(), AuthError> {
        self.lifecycle.revoke_all(user_id).await
    }

    pub async fn validate(&self, raw_access_token: &str) -> Result<TokenPayload, AuthError> {
        self.lifecycle.validate(raw_access_token).await
    }

    // -- accessors ------------------------------------------------------------

    pub fn lifecycle(&self) -> &TokenLifecycle {
        &self.lifecycle
    }

    pub fn config(&self) -> &AuthConfig {
        &self.config
    }

    pub fn password_hasher(&self) -> &PasswordHasher {
        &self.password_hasher
    }
}
