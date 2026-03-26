use std::fmt;

use crate::context::AuthContext;

// ---------------------------------------------------------------------------
// Leaf requirement data
// ---------------------------------------------------------------------------

pub struct PermissionReq {
    pub resource: String,
    pub action: String,
}

pub struct RoleReq {
    pub name: String,
}

pub struct RelationReq {
    pub resource: String,
    pub name: String,
}

// ---------------------------------------------------------------------------
// Requirement enum
// ---------------------------------------------------------------------------

/// A composable, tree-structured authorization requirement.
pub enum Requirement {
    Permission(PermissionReq),
    Role(RoleReq),
    Relation(RelationReq),
    AllOf(Vec<Requirement>),
    AnyOf(Vec<Requirement>),
    Custom(Box<dyn Fn(&AuthContext) -> bool + Send + Sync>),
}

impl Requirement {
    /// Evaluate the requirement against the given auth context.
    pub fn evaluate(&self, ctx: &AuthContext) -> bool {
        match self {
            Requirement::Permission(req) => {
                let perm = format!("{}:{}", req.resource, req.action);
                ctx.has_permission(&perm)
            }
            Requirement::Role(req) => ctx.has_role(&req.name),
            Requirement::Relation(req) => {
                let rel = format!("{}#{}", req.resource, req.name);
                ctx.has_relation(&rel, &req.resource)
            }
            Requirement::AllOf(reqs) => reqs.iter().all(|r| r.evaluate(ctx)),
            Requirement::AnyOf(reqs) => reqs.iter().any(|r| r.evaluate(ctx)),
            Requirement::Custom(f) => f(ctx),
        }
    }

    /// Combine two requirements with AND semantics.
    ///
    /// If either side is already an `AllOf`, its children are flattened into the
    /// result to avoid unnecessary nesting.
    pub fn and(self, other: Requirement) -> Requirement {
        let mut items = Vec::new();
        match self {
            Requirement::AllOf(v) => items.extend(v),
            other_self => items.push(other_self),
        }
        match other {
            Requirement::AllOf(v) => items.extend(v),
            other_other => items.push(other_other),
        }
        Requirement::AllOf(items)
    }

    /// Combine two requirements with OR semantics.
    ///
    /// If either side is already an `AnyOf`, its children are flattened into the
    /// result to avoid unnecessary nesting.
    pub fn or(self, other: Requirement) -> Requirement {
        let mut items = Vec::new();
        match self {
            Requirement::AnyOf(v) => items.extend(v),
            other_self => items.push(other_self),
        }
        match other {
            Requirement::AnyOf(v) => items.extend(v),
            other_other => items.push(other_other),
        }
        Requirement::AnyOf(items)
    }
}

// ---------------------------------------------------------------------------
// Debug (manual, because Box<dyn Fn> is not Debug)
// ---------------------------------------------------------------------------

impl fmt::Debug for Requirement {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Requirement::Permission(req) => {
                write!(f, "Permission({}:{})", req.resource, req.action)
            }
            Requirement::Role(req) => write!(f, "Role({})", req.name),
            Requirement::Relation(req) => write!(f, "Relation({}#{})", req.resource, req.name),
            Requirement::AllOf(reqs) => f.debug_tuple("AllOf").field(reqs).finish(),
            Requirement::AnyOf(reqs) => f.debug_tuple("AnyOf").field(reqs).finish(),
            Requirement::Custom(_) => write!(f, "Custom(<fn>)"),
        }
    }
}

// ---------------------------------------------------------------------------
// Convenience constructors
// ---------------------------------------------------------------------------

/// Require a specific permission (resource + action).
pub fn permission(resource: &str, action: &str) -> Requirement {
    Requirement::Permission(PermissionReq {
        resource: resource.to_string(),
        action: action.to_string(),
    })
}

/// Require a specific role.
pub fn role(name: &str) -> Requirement {
    Requirement::Role(RoleReq {
        name: name.to_string(),
    })
}

/// Require a relation on a resource.
pub fn relation(resource: &str, name: &str) -> Requirement {
    Requirement::Relation(RelationReq {
        resource: resource.to_string(),
        name: name.to_string(),
    })
}

/// All of the given requirements must be satisfied.
pub fn all_of(requirements: Vec<Requirement>) -> Requirement {
    Requirement::AllOf(requirements)
}

/// At least one of the given requirements must be satisfied.
pub fn any_of(requirements: Vec<Requirement>) -> Requirement {
    Requirement::AnyOf(requirements)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn mock_ctx() -> AuthContext {
        use crate::context::AuthContextBuilder;
        AuthContextBuilder::new()
            .user_id("test")
            .roles(vec!["admin".to_string()])
            .permissions(vec!["docs:read".to_string(), "docs:write".to_string()])
            .build()
    }

    #[test]
    fn permission_requirement_evaluates() {
        let ctx = mock_ctx();
        assert!(permission("docs", "read").evaluate(&ctx));
        assert!(!permission("docs", "delete").evaluate(&ctx));
    }

    #[test]
    fn role_requirement_evaluates() {
        let ctx = mock_ctx();
        assert!(role("admin").evaluate(&ctx));
        assert!(!role("viewer").evaluate(&ctx));
    }

    #[test]
    fn all_of_requires_all() {
        let ctx = mock_ctx();
        let req = permission("docs", "read").and(role("admin"));
        assert!(req.evaluate(&ctx));

        let req = permission("docs", "read").and(role("viewer"));
        assert!(!req.evaluate(&ctx));
    }

    #[test]
    fn any_of_requires_one() {
        let ctx = mock_ctx();
        let req = permission("docs", "delete").or(role("admin"));
        assert!(req.evaluate(&ctx));
    }

    #[test]
    fn custom_requirement() {
        let ctx = mock_ctx();
        let req = Requirement::Custom(Box::new(|ctx| ctx.roles.contains(&"admin".to_string())));
        assert!(req.evaluate(&ctx));
    }

    #[test]
    fn debug_output() {
        let req = permission("docs", "read").and(role("admin"));
        let dbg = format!("{:?}", req);
        assert!(dbg.contains("Permission"));
        assert!(dbg.contains("Role"));
    }
}
