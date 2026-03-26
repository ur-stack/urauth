use std::collections::HashMap;

use crate::errors::AuthError;
use super::types::TenantRoleProvisioner;

/// A blueprint for a role that should be auto-created for new tenants.
#[derive(Clone, Debug)]
pub struct RoleTemplate {
    pub name: String,
    pub permissions: Vec<String>,
    pub description: Option<String>,
}

impl RoleTemplate {
    /// Create a new template with the given name and permissions.
    pub fn new(name: &str, permissions: &[&str]) -> Self {
        Self {
            name: name.to_owned(),
            permissions: permissions.iter().map(|s| s.to_string()).collect(),
            description: None,
        }
    }

    /// Set an optional human-readable description (builder pattern).
    pub fn with_description(mut self, desc: &str) -> Self {
        self.description = Some(desc.to_owned());
        self
    }
}

/// Registry of default role templates keyed by hierarchy level.
pub struct TenantDefaults {
    templates: HashMap<String, Vec<RoleTemplate>>,
}

impl TenantDefaults {
    pub fn new() -> Self {
        Self {
            templates: HashMap::new(),
        }
    }

    /// Register a set of role templates for a given hierarchy level.
    pub fn register(&mut self, level: &str, templates: Vec<RoleTemplate>) -> &mut Self {
        self.templates.insert(level.to_owned(), templates);
        self
    }

    /// Retrieve the templates registered for a level.
    pub fn templates_for(&self, level: &str) -> Option<&[RoleTemplate]> {
        self.templates.get(level).map(|v| v.as_slice())
    }

    /// List all levels that have registered templates.
    pub fn levels(&self) -> Vec<&str> {
        self.templates.keys().map(|k| k.as_str()).collect()
    }

    /// Provision default roles for a tenant at the given level using the
    /// supplied provisioner backend.
    pub async fn provision(
        &self,
        tenant_id: &str,
        level: &str,
        provisioner: &dyn TenantRoleProvisioner,
    ) -> Result<(), AuthError> {
        if let Some(templates) = self.templates_for(level) {
            provisioner.provision(tenant_id, level, templates).await?;
        }
        Ok(())
    }
}

impl Default for TenantDefaults {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_role_template_builder() {
        let t = RoleTemplate::new("admin", &["read", "write", "delete"])
            .with_description("Full access");
        assert_eq!(t.name, "admin");
        assert_eq!(t.permissions, vec!["read", "write", "delete"]);
        assert_eq!(t.description.as_deref(), Some("Full access"));
    }

    #[test]
    fn test_tenant_defaults_registration() {
        let mut defaults = TenantDefaults::new();
        defaults.register("org", vec![
            RoleTemplate::new("owner", &["*"]),
            RoleTemplate::new("member", &["read"]),
        ]);
        defaults.register("group", vec![
            RoleTemplate::new("admin", &["read", "write"]),
        ]);

        assert_eq!(defaults.templates_for("org").unwrap().len(), 2);
        assert_eq!(defaults.templates_for("group").unwrap().len(), 1);
        assert!(defaults.templates_for("region").is_none());

        let mut levels = defaults.levels();
        levels.sort();
        assert_eq!(levels, vec!["group", "org"]);
    }
}
