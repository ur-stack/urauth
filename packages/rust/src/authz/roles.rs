use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::{Duration, Instant};

use async_trait::async_trait;
use tokio::sync::RwLock;

use crate::errors::AuthError;
use super::checker::RoleExpandingChecker;

// ---------------------------------------------------------------------------
// Traits
// ---------------------------------------------------------------------------

/// Loads role definitions and hierarchy from an external source (database,
/// config service, etc.).
#[async_trait]
pub trait RoleLoader: Send + Sync {
    /// Load role name -> permission strings mapping.
    async fn load_roles(&self) -> Result<HashMap<String, HashSet<String>>, AuthError>;
    /// Load role name -> inherited role names mapping.
    async fn load_hierarchy(&self) -> Result<HashMap<String, Vec<String>>, AuthError>;
}

/// Simple cache interface used by [`RoleRegistry`] to avoid repeated loads.
#[async_trait]
pub trait RoleCache: Send + Sync {
    async fn get(&self, key: &str) -> Option<String>;
    async fn set(&self, key: &str, value: &str, ttl: u64) -> Result<(), AuthError>;
    async fn invalidate(&self, key: &str) -> Result<(), AuthError>;
}

// ---------------------------------------------------------------------------
// MemoryRoleCache
// ---------------------------------------------------------------------------

struct CacheEntry {
    value: String,
    expires_at: Instant,
}

/// In-memory TTL cache suitable for single-process deployments.
pub struct MemoryRoleCache {
    store: RwLock<HashMap<String, CacheEntry>>,
}

impl MemoryRoleCache {
    pub fn new() -> Self {
        Self {
            store: RwLock::new(HashMap::new()),
        }
    }
}

impl Default for MemoryRoleCache {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl RoleCache for MemoryRoleCache {
    async fn get(&self, key: &str) -> Option<String> {
        let store = self.store.read().await;
        store.get(key).and_then(|entry| {
            if Instant::now() < entry.expires_at {
                Some(entry.value.clone())
            } else {
                None
            }
        })
    }

    async fn set(&self, key: &str, value: &str, ttl: u64) -> Result<(), AuthError> {
        let mut store = self.store.write().await;
        store.insert(
            key.to_string(),
            CacheEntry {
                value: value.to_string(),
                expires_at: Instant::now() + Duration::from_secs(ttl),
            },
        );
        Ok(())
    }

    async fn invalidate(&self, key: &str) -> Result<(), AuthError> {
        let mut store = self.store.write().await;
        store.remove(key);
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// RoleRegistry
// ---------------------------------------------------------------------------

/// Central registry that combines static role definitions with optional
/// dynamic loading and caching.
pub struct RoleRegistry {
    /// role name -> permission strings
    pub roles: HashMap<String, HashSet<String>>,
    /// role name -> inherited roles
    pub hierarchy: HashMap<String, Vec<String>>,
    loader: Option<Arc<dyn RoleLoader>>,
    cache: Option<Arc<dyn RoleCache>>,
    cache_ttl: u64,
}

impl RoleRegistry {
    pub fn new() -> Self {
        Self {
            roles: HashMap::new(),
            hierarchy: HashMap::new(),
            loader: None,
            cache: None,
            cache_ttl: 300,
        }
    }

    /// Register a role with its granted permissions and optional parent roles
    /// it inherits from.
    pub fn role(
        &mut self,
        name: &str,
        permissions: &[&str],
        inherits: Option<&[&str]>,
    ) -> &mut Self {
        let perm_set: HashSet<String> = permissions.iter().map(|s| s.to_string()).collect();
        self.roles
            .entry(name.to_string())
            .or_default()
            .extend(perm_set);

        if let Some(parents) = inherits {
            let parent_list: Vec<String> = parents.iter().map(|s| s.to_string()).collect();
            self.hierarchy
                .entry(name.to_string())
                .or_default()
                .extend(parent_list);
        }

        self
    }

    /// Merge all roles and hierarchy entries from another registry into this one.
    pub fn include(&mut self, other: &RoleRegistry) -> &mut Self {
        for (role_name, perms) in &other.roles {
            self.roles
                .entry(role_name.clone())
                .or_default()
                .extend(perms.clone());
        }
        for (role_name, parents) in &other.hierarchy {
            self.hierarchy
                .entry(role_name.clone())
                .or_default()
                .extend(parents.clone());
        }
        self
    }

    /// Attach a dynamic loader and optional cache.
    pub fn with_loader(
        &mut self,
        loader: Arc<dyn RoleLoader>,
        cache: Option<Arc<dyn RoleCache>>,
        cache_ttl: u64,
    ) -> &mut Self {
        self.loader = Some(loader);
        self.cache = cache;
        self.cache_ttl = cache_ttl;
        self
    }

    /// Load roles from the configured loader and merge them with the
    /// statically registered roles.
    pub async fn load(&mut self) -> Result<(), AuthError> {
        let loader = match &self.loader {
            Some(l) => Arc::clone(l),
            None => return Ok(()),
        };

        let loaded_roles = loader.load_roles().await?;
        let loaded_hierarchy = loader.load_hierarchy().await?;

        for (role_name, perms) in loaded_roles {
            self.roles.entry(role_name).or_default().extend(perms);
        }
        for (role_name, parents) in loaded_hierarchy {
            self.hierarchy.entry(role_name).or_default().extend(parents);
        }

        Ok(())
    }

    /// Build a [`RoleExpandingChecker`] from the current state of the registry.
    pub fn build_checker(&self) -> RoleExpandingChecker {
        RoleExpandingChecker::new(self.roles.clone(), self.hierarchy.clone())
    }
}

impl Default for RoleRegistry {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn register_roles_and_build_checker() {
        let mut registry = RoleRegistry::new();
        registry
            .role("viewer", &["docs:read"], None)
            .role("editor", &["docs:write"], Some(&["viewer"]))
            .role("admin", &["users:delete"], Some(&["editor"]));

        let checker = registry.build_checker();

        // admin -> editor -> viewer
        let effective = checker.effective_roles(&["admin".to_string()]);
        assert!(effective.contains("admin"));
        assert!(effective.contains("editor"));
        assert!(effective.contains("viewer"));
    }

    #[test]
    fn include_merges_registries() {
        let mut base = RoleRegistry::new();
        base.role("viewer", &["docs:read"], None);

        let mut extra = RoleRegistry::new();
        extra.role("editor", &["docs:write"], Some(&["viewer"]));

        base.include(&extra);

        assert!(base.roles.contains_key("editor"));
        assert!(base.hierarchy.contains_key("editor"));
    }

    #[tokio::test]
    async fn memory_cache_basic() {
        let cache = MemoryRoleCache::new();
        cache.set("key", "value", 60).await.unwrap();
        assert_eq!(cache.get("key").await, Some("value".to_string()));

        cache.invalidate("key").await.unwrap();
        assert_eq!(cache.get("key").await, None);
    }

    #[tokio::test]
    async fn memory_cache_ttl_expiry() {
        let cache = MemoryRoleCache::new();
        // TTL of 0 means it expires immediately.
        cache.set("key", "value", 0).await.unwrap();
        // Instant comparison: expires_at = now + 0s, so now >= expires_at.
        // The get implementation uses strict less-than, so this should be None.
        tokio::time::sleep(std::time::Duration::from_millis(5)).await;
        assert_eq!(cache.get("key").await, None);
    }
}
