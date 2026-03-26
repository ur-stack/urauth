// ---------------------------------------------------------------------------
// urauth – Rust authentication & authorization library
// ---------------------------------------------------------------------------

pub mod errors;
pub mod types;
pub mod config;
pub mod password;
pub mod tokens;
pub mod lifecycle;
pub mod stores;
pub mod authz;
pub mod context;
pub mod guards;
pub mod ratelimit;
pub mod transport;
pub mod tenant;
pub mod auth;
pub mod testing;

// ---------------------------------------------------------------------------
// Re-exports – key types available at crate root for convenience
// ---------------------------------------------------------------------------

pub use errors::AuthError;
pub use types::{IssuedTokenPair, IssueRequest, TokenPair, TokenPayload};
pub use config::{AuthConfig, AuthConfigBuilder, Environment};
pub use password::{HashAlgorithm, PasswordHasher};
pub use context::{AuthContext, AuthContextBuilder};
pub use auth::{Auth, AuthCallbacks};
pub use lifecycle::TokenLifecycle;
pub use stores::{MemorySessionStore, MemoryTokenStore, SessionData, SessionStore, TokenStore};
pub use guards::{guard, policy, require_all, require_any, require_auth, require_permission, require_role, require_tenant};
pub use ratelimit::{KeyStrategy, RateLimitResult, RateLimiter, RateLimiterOptions};
pub use transport::{extract_bearer_token, Transport};
pub use tokens::jwt::TokenService;
pub use tokens::refresh::RefreshService;
pub use tokens::revocation::RevocationService;
pub use authz::{
    match_permission, MemoryRoleCache, Permission, PermissionChecker, Relation, RelationTuple,
    Requirement, Role, RoleCache, RoleExpandingChecker, RoleLoader, RoleRegistry, StringChecker,
};
pub use tenant::{
    RoleTemplate, TenantDefaults, TenantHierarchy, TenantLevel, TenantNode, TenantPath,
    TenantRoleProvisioner, TenantStore,
};
pub use testing::{mock_admin_context, mock_anonymous_context, mock_context, mock_payload};
