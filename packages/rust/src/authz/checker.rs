use std::collections::{HashMap, HashSet};

use async_trait::async_trait;

use crate::context::AuthContext;
use crate::errors::AuthError;
use super::primitives::match_permission;

// ---------------------------------------------------------------------------
// Trait
// ---------------------------------------------------------------------------

/// Pluggable permission-checking strategy.
#[async_trait]
pub trait PermissionChecker: Send + Sync {
    /// Check whether the given context is allowed `action` on `resource`.
    ///
    /// When `scope` is provided the checker should look at scoped permission
    /// sets rather than the top-level permissions list.
    async fn has_permission(
        &self,
        ctx: &AuthContext,
        resource: &str,
        action: &str,
        scope: Option<&str>,
    ) -> Result<bool, AuthError>;
}

// ---------------------------------------------------------------------------
// StringChecker – default, in-memory implementation
// ---------------------------------------------------------------------------

/// Checks permissions by doing wildcard-aware string matching against the
/// permission strings stored in [`AuthContext`].
#[derive(Debug, Default)]
pub struct StringChecker;

impl StringChecker {
    pub fn new() -> Self {
        Self
    }
}

#[async_trait]
impl PermissionChecker for StringChecker {
    async fn has_permission(
        &self,
        ctx: &AuthContext,
        resource: &str,
        action: &str,
        scope: Option<&str>,
    ) -> Result<bool, AuthError> {
        let target = format!("{}:{}", resource, action);

        let permission_set: &[String] = match scope {
            Some(scope_key) => match ctx.scopes.get(scope_key) {
                Some(perms) => perms.as_slice(),
                None => return Ok(false),
            },
            None => ctx.permissions.as_slice(),
        };

        let matched = permission_set
            .iter()
            .any(|p| match_permission(p, &target));

        Ok(matched)
    }
}

// ---------------------------------------------------------------------------
// RoleExpandingChecker – expands roles to permissions via a hierarchy
// ---------------------------------------------------------------------------

/// Resolves a user's roles (including inherited roles) and collects every
/// permission granted by those roles before performing the match.
#[derive(Debug, Clone)]
pub struct RoleExpandingChecker {
    /// role name -> set of permission strings granted directly by this role
    pub role_permissions: HashMap<String, HashSet<String>>,
    /// role name -> list of roles it inherits from
    pub hierarchy: HashMap<String, Vec<String>>,
}

impl RoleExpandingChecker {
    pub fn new(
        role_permissions: HashMap<String, HashSet<String>>,
        hierarchy: HashMap<String, Vec<String>>,
    ) -> Self {
        Self {
            role_permissions,
            hierarchy,
        }
    }

    /// Compute the full set of effective roles for the given user roles by
    /// walking the hierarchy graph. Circular dependencies are detected and
    /// short-circuited.
    pub fn effective_roles(&self, user_roles: &[String]) -> HashSet<String> {
        let mut visited = HashSet::new();
        let mut stack: Vec<String> = user_roles.to_vec();

        while let Some(role) = stack.pop() {
            if !visited.insert(role.clone()) {
                // Already visited – skip (handles circular deps).
                continue;
            }
            if let Some(parents) = self.hierarchy.get(&role) {
                for parent in parents {
                    if !visited.contains(parent) {
                        stack.push(parent.clone());
                    }
                }
            }
        }

        visited
    }
}

#[async_trait]
impl PermissionChecker for RoleExpandingChecker {
    async fn has_permission(
        &self,
        ctx: &AuthContext,
        resource: &str,
        action: &str,
        _scope: Option<&str>,
    ) -> Result<bool, AuthError> {
        let effective = self.effective_roles(&ctx.roles);
        let target = format!("{}:{}", resource, action);

        // Collect every permission string from effective roles.
        let matched = effective.iter().any(|role| {
            self.role_permissions
                .get(role)
                .map_or(false, |perms| {
                    perms.iter().any(|p| match_permission(p, &target))
                })
        });

        // Also check context-level permissions (direct grants).
        if matched {
            return Ok(true);
        }

        let direct = ctx.permissions.iter().any(|p| match_permission(p, &target));
        Ok(direct)
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn ctx_with_perms(perms: &[&str]) -> AuthContext {
        AuthContext {
            roles: vec![],
            permissions: perms.iter().map(|s| s.to_string()).collect(),
            scopes: HashMap::new(),
        }
    }

    #[tokio::test]
    async fn string_checker_exact_match() {
        let checker = StringChecker::new();
        let ctx = ctx_with_perms(&["docs:read", "docs:write"]);
        assert!(checker.has_permission(&ctx, "docs", "read", None).await.unwrap());
        assert!(!checker.has_permission(&ctx, "docs", "delete", None).await.unwrap());
    }

    #[tokio::test]
    async fn string_checker_wildcard() {
        let checker = StringChecker::new();
        let ctx = ctx_with_perms(&["docs:*"]);
        assert!(checker.has_permission(&ctx, "docs", "read", None).await.unwrap());
        assert!(checker.has_permission(&ctx, "docs", "write", None).await.unwrap());
        assert!(!checker.has_permission(&ctx, "users", "read", None).await.unwrap());
    }

    #[tokio::test]
    async fn string_checker_scoped() {
        let checker = StringChecker::new();
        let mut scopes = HashMap::new();
        scopes.insert("tenant_a".to_string(), vec!["docs:read".to_string()]);
        let ctx = AuthContext {
            roles: vec![],
            permissions: vec!["docs:write".to_string()],
            scopes,
        };
        assert!(checker.has_permission(&ctx, "docs", "read", Some("tenant_a")).await.unwrap());
        assert!(!checker.has_permission(&ctx, "docs", "write", Some("tenant_a")).await.unwrap());
        assert!(!checker.has_permission(&ctx, "docs", "read", Some("tenant_b")).await.unwrap());
    }

    #[tokio::test]
    async fn role_expanding_checker_basic() {
        let mut role_perms = HashMap::new();
        role_perms.insert("editor".to_string(), HashSet::from(["docs:read".into(), "docs:write".into()]));
        role_perms.insert("viewer".to_string(), HashSet::from(["docs:read".into()]));

        let hierarchy = HashMap::new();
        let checker = RoleExpandingChecker::new(role_perms, hierarchy);

        let ctx = AuthContext {
            roles: vec!["editor".to_string()],
            permissions: vec![],
            scopes: HashMap::new(),
        };

        assert!(checker.has_permission(&ctx, "docs", "write", None).await.unwrap());
        assert!(!checker.has_permission(&ctx, "docs", "delete", None).await.unwrap());
    }

    #[tokio::test]
    async fn role_expanding_checker_hierarchy() {
        let mut role_perms = HashMap::new();
        role_perms.insert("admin".to_string(), HashSet::from(["users:delete".into()]));
        role_perms.insert("editor".to_string(), HashSet::from(["docs:write".into()]));
        role_perms.insert("viewer".to_string(), HashSet::from(["docs:read".into()]));

        let mut hierarchy = HashMap::new();
        hierarchy.insert("admin".to_string(), vec!["editor".to_string()]);
        hierarchy.insert("editor".to_string(), vec!["viewer".to_string()]);

        let checker = RoleExpandingChecker::new(role_perms, hierarchy);

        let ctx = AuthContext {
            roles: vec!["admin".to_string()],
            permissions: vec![],
            scopes: HashMap::new(),
        };

        // admin inherits editor inherits viewer
        assert!(checker.has_permission(&ctx, "docs", "read", None).await.unwrap());
        assert!(checker.has_permission(&ctx, "docs", "write", None).await.unwrap());
        assert!(checker.has_permission(&ctx, "users", "delete", None).await.unwrap());
    }

    #[test]
    fn effective_roles_circular_dependency() {
        let role_perms = HashMap::new();
        let mut hierarchy = HashMap::new();
        hierarchy.insert("a".to_string(), vec!["b".to_string()]);
        hierarchy.insert("b".to_string(), vec!["a".to_string()]);

        let checker = RoleExpandingChecker::new(role_perms, hierarchy);
        let effective = checker.effective_roles(&["a".to_string()]);
        assert!(effective.contains("a"));
        assert!(effective.contains("b"));
    }
}
