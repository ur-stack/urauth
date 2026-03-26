//! Test helper utilities for building mock auth contexts and token payloads.

use std::collections::HashMap;

use chrono::Utc;
use uuid::Uuid;

use crate::context::{AuthContext, AuthContextBuilder};
use crate::tenant::hierarchy::TenantPath;
use crate::types::TokenPayload;

// ---------------------------------------------------------------------------
// AuthContext overrides
// ---------------------------------------------------------------------------

/// Optional overrides for [`mock_context`].
#[derive(Debug, Default)]
pub struct AuthContextOverrides {
    pub user_id: Option<String>,
    pub roles: Option<Vec<String>>,
    pub permissions: Option<Vec<String>>,
    pub relations: Option<Vec<String>>,
    pub scopes: Option<HashMap<String, Vec<String>>>,
    pub tenant: Option<TenantPath>,
    pub authenticated: Option<bool>,
}

/// Build a mock [`AuthContext`] with sensible defaults.
///
/// Defaults: `user_id = "test-user"`, `authenticated = true`, no roles or
/// permissions. Supply [`AuthContextOverrides`] to customise.
pub fn mock_context(overrides: Option<AuthContextOverrides>) -> AuthContext {
    let o = overrides.unwrap_or_default();

    let mut builder = AuthContextBuilder::new()
        .user_id(o.user_id.unwrap_or_else(|| "test-user".to_string()));

    if let Some(roles) = o.roles {
        builder = builder.roles(roles);
    }
    if let Some(permissions) = o.permissions {
        builder = builder.permissions(permissions);
    }
    if let Some(relations) = o.relations {
        builder = builder.relations(relations);
    }
    if let Some(scopes) = o.scopes {
        builder = builder.scopes(scopes);
    }
    if let Some(tenant) = o.tenant {
        builder = builder.tenant(tenant);
    }
    if let Some(authenticated) = o.authenticated {
        builder = builder.authenticated(authenticated);
    }

    builder.build()
}

/// Build a mock admin context with role `"admin"` and wildcard permission `"*"`.
pub fn mock_admin_context() -> AuthContext {
    mock_context(Some(AuthContextOverrides {
        user_id: Some("admin".to_string()),
        roles: Some(vec!["admin".to_string()]),
        permissions: Some(vec!["*".to_string()]),
        ..Default::default()
    }))
}

/// Build a mock anonymous (unauthenticated) context.
pub fn mock_anonymous_context() -> AuthContext {
    AuthContext::anonymous()
}

// ---------------------------------------------------------------------------
// TokenPayload overrides
// ---------------------------------------------------------------------------

/// Optional overrides for [`mock_payload`].
#[derive(Debug, Default)]
pub struct PayloadOverrides {
    pub sub: Option<String>,
    pub token_type: Option<String>,
    pub scopes: Option<Vec<String>>,
    pub roles: Option<Vec<String>>,
    pub fresh: Option<bool>,
}

/// Build a mock [`TokenPayload`] with sensible defaults.
///
/// Defaults: `sub = "test-user"`, `jti = random UUID`, `iat = now`,
/// `exp = now + 900s`, `type = "access"`.
pub fn mock_payload(overrides: Option<PayloadOverrides>) -> TokenPayload {
    let o = overrides.unwrap_or_default();
    let now = Utc::now().timestamp();

    TokenPayload {
        sub: o.sub.unwrap_or_else(|| "test-user".to_string()),
        jti: Uuid::new_v4().to_string(),
        iat: now,
        exp: now + 900,
        token_type: o.token_type.unwrap_or_else(|| "access".to_string()),
        scopes: o.scopes,
        roles: o.roles,
        permissions: None,
        tenant_id: None,
        tenant_path: None,
        fresh: o.fresh,
        family_id: None,
        extra: HashMap::new(),
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mock_context_defaults() {
        let ctx = mock_context(None);
        assert_eq!(ctx.user_id.as_deref(), Some("test-user"));
        assert!(ctx.is_authenticated());
        assert!(ctx.roles.is_empty());
        assert!(ctx.permissions.is_empty());
    }

    #[test]
    fn mock_context_with_overrides() {
        let ctx = mock_context(Some(AuthContextOverrides {
            user_id: Some("bob".to_string()),
            roles: Some(vec!["viewer".to_string()]),
            ..Default::default()
        }));
        assert_eq!(ctx.user_id.as_deref(), Some("bob"));
        assert_eq!(ctx.roles, vec!["viewer"]);
    }

    #[test]
    fn mock_admin_has_wildcard_permission() {
        let ctx = mock_admin_context();
        assert!(ctx.has_permission("anything:at_all"));
        assert!(ctx.has_role("admin"));
    }

    #[test]
    fn mock_anonymous_is_unauthenticated() {
        let ctx = mock_anonymous_context();
        assert!(!ctx.is_authenticated());
        assert!(ctx.user_id.is_none());
    }

    #[test]
    fn mock_payload_defaults() {
        let payload = mock_payload(None);
        assert_eq!(payload.sub, "test-user");
        assert_eq!(payload.token_type, "access");
        assert!(payload.exp > payload.iat);
    }

    #[test]
    fn mock_payload_with_overrides() {
        let payload = mock_payload(Some(PayloadOverrides {
            sub: Some("custom".to_string()),
            token_type: Some("refresh".to_string()),
            fresh: Some(true),
            ..Default::default()
        }));
        assert_eq!(payload.sub, "custom");
        assert_eq!(payload.token_type, "refresh");
        assert_eq!(payload.fresh, Some(true));
    }
}
