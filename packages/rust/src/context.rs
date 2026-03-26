use std::collections::HashMap;

use crate::authz::primitives::match_permission;
use crate::authz::requirement::Requirement;
use crate::tenant::hierarchy::TenantPath;
use crate::types::TokenPayload;

/// Central identity model carrying all authentication and authorization state.
#[derive(Clone, Debug)]
pub struct AuthContext {
    /// Generic user object (framework-specific deserialization left to the caller).
    pub user: Option<serde_json::Value>,

    /// Subject identifier extracted from the token.
    pub user_id: Option<String>,

    /// Roles assigned to the current identity.
    pub roles: Vec<String>,

    /// Flat permission strings (e.g. "docs:read", "billing:*").
    pub permissions: Vec<String>,

    /// Zanzibar-style relation strings (e.g. "doc:readme#owner").
    pub relations: Vec<String>,

    /// Tenant-scoped permissions keyed by hierarchy level.
    pub scopes: HashMap<String, Vec<String>>,

    /// The decoded token payload, if available.
    pub token: Option<TokenPayload>,

    /// The tenant path for the current request context.
    pub tenant: Option<TenantPath>,

    /// Whether the context represents an authenticated identity.
    pub authenticated: bool,
}

impl AuthContext {
    /// Create an unauthenticated (anonymous) context.
    pub fn anonymous() -> Self {
        Self {
            user: None,
            user_id: None,
            roles: Vec::new(),
            permissions: Vec::new(),
            relations: Vec::new(),
            scopes: HashMap::new(),
            token: None,
            tenant: None,
            authenticated: false,
        }
    }

    /// Returns `true` if this context represents an authenticated identity.
    pub fn is_authenticated(&self) -> bool {
        self.authenticated
    }

    /// Check whether the context holds a permission matching `permission`.
    ///
    /// Supports wildcards: `"*"` matches everything, `"resource:*"` matches
    /// all actions on a resource.
    pub fn has_permission(&self, permission: &str) -> bool {
        self.permissions
            .iter()
            .any(|p| match_permission(p, permission))
    }

    /// Check whether the context holds the given role.
    pub fn has_role(&self, role: &str) -> bool {
        self.roles.iter().any(|r| r == role)
    }

    /// Check whether any of the given roles are present.
    pub fn has_any_role(&self, roles: &[&str]) -> bool {
        roles.iter().any(|r| self.has_role(r))
    }

    /// Check whether the context holds a relation matching the given
    /// relation string and resource id.
    ///
    /// A relation string in `self.relations` is expected to follow the
    /// Zanzibar tuple format (e.g. `"doc:readme#owner"`).
    pub fn has_relation(&self, relation: &str, resource_id: &str) -> bool {
        self.relations
            .iter()
            .any(|r| r == relation || r == &format!("{}@{}", relation, resource_id))
    }

    /// Evaluate a composite [`Requirement`] against this context.
    pub fn satisfies(&self, requirement: &Requirement) -> bool {
        requirement.evaluate(self)
    }

    /// Returns `true` if the tenant path contains a node with the given id.
    pub fn in_tenant(&self, tenant_id: &str) -> bool {
        self.tenant
            .as_ref()
            .map(|tp| tp.is_descendant_of(tenant_id))
            .unwrap_or(false)
    }

    /// Get the tenant id at a specific hierarchy level.
    pub fn at_level(&self, level: &str) -> Option<&str> {
        self.tenant.as_ref().and_then(|tp| tp.id_at(level))
    }

    /// Get the leaf (deepest) tenant id. Provided for backward compatibility
    /// with flat-tenancy code paths.
    pub fn tenant_id(&self) -> Option<&str> {
        self.tenant.as_ref().and_then(|tp| tp.leaf_id())
    }
}

// ---------------------------------------------------------------------------
// Builder
// ---------------------------------------------------------------------------

/// Fluent builder for constructing an [`AuthContext`].
#[derive(Debug, Default)]
pub struct AuthContextBuilder {
    user: Option<serde_json::Value>,
    user_id: Option<String>,
    roles: Option<Vec<String>>,
    permissions: Option<Vec<String>>,
    relations: Option<Vec<String>>,
    scopes: Option<HashMap<String, Vec<String>>>,
    token: Option<TokenPayload>,
    tenant: Option<TenantPath>,
    authenticated: Option<bool>,
}

impl AuthContextBuilder {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn user(mut self, user: serde_json::Value) -> Self {
        self.user = Some(user);
        self
    }

    pub fn user_id(mut self, user_id: impl Into<String>) -> Self {
        self.user_id = Some(user_id.into());
        self
    }

    pub fn roles(mut self, roles: Vec<String>) -> Self {
        self.roles = Some(roles);
        self
    }

    pub fn permissions(mut self, permissions: Vec<String>) -> Self {
        self.permissions = Some(permissions);
        self
    }

    pub fn relations(mut self, relations: Vec<String>) -> Self {
        self.relations = Some(relations);
        self
    }

    pub fn scopes(mut self, scopes: HashMap<String, Vec<String>>) -> Self {
        self.scopes = Some(scopes);
        self
    }

    pub fn token(mut self, token: TokenPayload) -> Self {
        self.token = Some(token);
        self
    }

    pub fn tenant(mut self, tenant: TenantPath) -> Self {
        self.tenant = Some(tenant);
        self
    }

    pub fn authenticated(mut self, authenticated: bool) -> Self {
        self.authenticated = Some(authenticated);
        self
    }

    /// Consume the builder and produce an [`AuthContext`].
    ///
    /// If `authenticated` was not explicitly set, it defaults to `true` when a
    /// `user_id` is present, and `false` otherwise.
    pub fn build(self) -> AuthContext {
        let has_user = self.user_id.is_some();
        AuthContext {
            user: self.user,
            user_id: self.user_id,
            roles: self.roles.unwrap_or_default(),
            permissions: self.permissions.unwrap_or_default(),
            relations: self.relations.unwrap_or_default(),
            scopes: self.scopes.unwrap_or_default(),
            token: self.token,
            tenant: self.tenant,
            authenticated: self.authenticated.unwrap_or(has_user),
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tenant::hierarchy::TenantNode;

    #[test]
    fn anonymous_context_is_unauthenticated() {
        let ctx = AuthContext::anonymous();
        assert!(!ctx.is_authenticated());
        assert!(ctx.user_id.is_none());
    }

    #[test]
    fn builder_defaults_authenticated_from_user_id() {
        let ctx = AuthContextBuilder::new()
            .user_id("alice")
            .build();
        assert!(ctx.is_authenticated());

        let ctx = AuthContextBuilder::new().build();
        assert!(!ctx.is_authenticated());
    }

    #[test]
    fn has_permission_with_wildcards() {
        let ctx = AuthContextBuilder::new()
            .permissions(vec!["docs:*".to_string()])
            .build();
        assert!(ctx.has_permission("docs:read"));
        assert!(ctx.has_permission("docs:write"));
        assert!(!ctx.has_permission("billing:read"));
    }

    #[test]
    fn has_permission_star_matches_all() {
        let ctx = AuthContextBuilder::new()
            .permissions(vec!["*".to_string()])
            .build();
        assert!(ctx.has_permission("anything:here"));
    }

    #[test]
    fn has_role_and_has_any_role() {
        let ctx = AuthContextBuilder::new()
            .roles(vec!["admin".to_string(), "editor".to_string()])
            .build();
        assert!(ctx.has_role("admin"));
        assert!(!ctx.has_role("viewer"));
        assert!(ctx.has_any_role(&["viewer", "editor"]));
        assert!(!ctx.has_any_role(&["viewer", "guest"]));
    }

    #[test]
    fn tenant_queries() {
        let path = TenantPath::new(vec![
            TenantNode {
                id: "acme".into(),
                level: "org".into(),
            },
            TenantNode {
                id: "sales".into(),
                level: "group".into(),
            },
        ]);
        let ctx = AuthContextBuilder::new()
            .user_id("alice")
            .tenant(path)
            .build();

        assert!(ctx.in_tenant("acme"));
        assert!(!ctx.in_tenant("other"));
        assert_eq!(ctx.at_level("org"), Some("acme"));
        assert_eq!(ctx.at_level("region"), None);
        assert_eq!(ctx.tenant_id(), Some("sales"));
    }
}
