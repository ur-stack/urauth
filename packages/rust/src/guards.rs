use crate::authz::requirement::Requirement;
use crate::context::AuthContext;
use crate::errors::AuthError;

/// Verify that the context is authenticated, returning `Unauthorized` if not.
fn check_auth(ctx: &AuthContext) -> Result<(), AuthError> {
    if !ctx.is_authenticated() {
        return Err(AuthError::unauthorized());
    }
    Ok(())
}

/// Require an authenticated identity. Returns `Unauthorized` if the context
/// is anonymous.
pub fn require_auth(ctx: &AuthContext) -> Result<(), AuthError> {
    check_auth(ctx)
}

/// Require a specific permission expressed as `resource:action`.
///
/// Returns `Unauthorized` if not authenticated, `Forbidden` if the
/// permission is not held.
pub fn require_permission(
    ctx: &AuthContext,
    resource: &str,
    action: &str,
) -> Result<(), AuthError> {
    check_auth(ctx)?;
    let perm = format!("{}:{}", resource, action);
    if !ctx.has_permission(&perm) {
        return Err(AuthError::forbidden(format!(
            "Missing permission: {}:{}",
            resource, action
        )));
    }
    Ok(())
}

/// Require that the identity holds the given role.
pub fn require_role(ctx: &AuthContext, role: &str) -> Result<(), AuthError> {
    check_auth(ctx)?;
    if !ctx.has_role(role) {
        return Err(AuthError::forbidden(format!("Missing role: {}", role)));
    }
    Ok(())
}

/// Require that **at least one** of the given requirements is satisfied.
pub fn require_any(ctx: &AuthContext, requirements: &[Requirement]) -> Result<(), AuthError> {
    check_auth(ctx)?;
    if requirements.iter().any(|r| r.evaluate(ctx)) {
        Ok(())
    } else {
        Err(AuthError::forbidden(
            "None of the required conditions were met",
        ))
    }
}

/// Require that **all** of the given requirements are satisfied.
pub fn require_all(ctx: &AuthContext, requirements: &[Requirement]) -> Result<(), AuthError> {
    check_auth(ctx)?;
    if requirements.iter().all(|r| r.evaluate(ctx)) {
        Ok(())
    } else {
        Err(AuthError::forbidden(
            "Not all required conditions were met",
        ))
    }
}

/// Evaluate a single [`Requirement`] against the context.
pub fn guard(ctx: &AuthContext, requirement: &Requirement) -> Result<(), AuthError> {
    check_auth(ctx)?;
    if requirement.evaluate(ctx) {
        Ok(())
    } else {
        Err(AuthError::forbidden(format!(
            "Requirement not satisfied: {:?}",
            requirement
        )))
    }
}

/// Require that the context has a tenant at the given hierarchy level.
pub fn require_tenant(ctx: &AuthContext, level: &str) -> Result<(), AuthError> {
    check_auth(ctx)?;
    if ctx.at_level(level).is_none() {
        return Err(AuthError::forbidden(format!(
            "Missing tenant at level: {}",
            level
        )));
    }
    Ok(())
}

/// Evaluate an arbitrary policy function against the context.
///
/// Returns `Unauthorized` if not authenticated, `Forbidden` if the check
/// returns `false`.
pub fn policy(ctx: &AuthContext, check: impl Fn(&AuthContext) -> bool) -> Result<(), AuthError> {
    check_auth(ctx)?;
    if check(ctx) {
        Ok(())
    } else {
        Err(AuthError::forbidden("Policy check failed"))
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::context::AuthContextBuilder;
    use crate::tenant::hierarchy::{TenantNode, TenantPath};

    fn authed_ctx() -> AuthContext {
        AuthContextBuilder::new()
            .user_id("alice")
            .roles(vec!["editor".to_string()])
            .permissions(vec!["docs:read".to_string(), "docs:write".to_string()])
            .build()
    }

    #[test]
    fn require_auth_passes_for_authenticated() {
        assert!(require_auth(&authed_ctx()).is_ok());
    }

    #[test]
    fn require_auth_fails_for_anonymous() {
        let ctx = AuthContext::anonymous();
        assert!(require_auth(&ctx).is_err());
    }

    #[test]
    fn require_permission_passes() {
        assert!(require_permission(&authed_ctx(), "docs", "read").is_ok());
    }

    #[test]
    fn require_permission_fails() {
        assert!(require_permission(&authed_ctx(), "docs", "delete").is_err());
    }

    #[test]
    fn require_role_passes() {
        assert!(require_role(&authed_ctx(), "editor").is_ok());
    }

    #[test]
    fn require_role_fails() {
        assert!(require_role(&authed_ctx(), "admin").is_err());
    }

    #[test]
    fn require_tenant_passes() {
        let ctx = AuthContextBuilder::new()
            .user_id("alice")
            .tenant(TenantPath::new(vec![TenantNode {
                id: "acme".into(),
                level: "org".into(),
            }]))
            .build();
        assert!(require_tenant(&ctx, "org").is_ok());
    }

    #[test]
    fn require_tenant_fails_missing_level() {
        let ctx = authed_ctx();
        assert!(require_tenant(&ctx, "org").is_err());
    }

    #[test]
    fn policy_passes() {
        let ctx = authed_ctx();
        assert!(policy(&ctx, |c| c.has_role("editor")).is_ok());
    }

    #[test]
    fn policy_fails() {
        let ctx = authed_ctx();
        assert!(policy(&ctx, |c| c.has_role("admin")).is_err());
    }

    #[test]
    fn policy_fails_unauthenticated() {
        let ctx = AuthContext::anonymous();
        assert!(policy(&ctx, |_| true).is_err());
    }
}
