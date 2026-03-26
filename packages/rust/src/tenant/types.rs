use async_trait::async_trait;

use crate::errors::AuthError;
use super::hierarchy::{TenantNode, TenantPath};

/// Async storage backend for tenant data.
#[async_trait]
pub trait TenantStore: Send + Sync {
    /// Retrieve a single tenant node by its id.
    async fn get_tenant(&self, tenant_id: &str) -> Result<Option<TenantNode>, AuthError>;

    /// Return the ancestor chain for the given tenant, ordered root-first.
    async fn get_ancestors(&self, tenant_id: &str) -> Result<Vec<TenantNode>, AuthError>;

    /// Return immediate children of the given tenant.
    async fn get_children(&self, tenant_id: &str) -> Result<Vec<TenantNode>, AuthError>;

    /// Build the full path from root to the given tenant.
    async fn resolve_path(&self, tenant_id: &str) -> Result<Option<TenantPath>, AuthError>;
}

/// Provisions default roles when a new tenant is created.
#[async_trait]
pub trait TenantRoleProvisioner: Send + Sync {
    /// Create the given role templates for a tenant at the specified level.
    async fn provision(
        &self,
        tenant_id: &str,
        level: &str,
        templates: &[super::defaults::RoleTemplate],
    ) -> Result<(), AuthError>;
}
