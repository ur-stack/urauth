use std::collections::HashMap;
use std::fmt;

/// A single level in a tenant hierarchy (e.g. "org", "region", "group").
#[derive(Clone, Debug, PartialEq)]
pub struct TenantLevel {
    pub name: String,
    pub depth: usize,
}

/// A concrete tenant node: an id at a specific level.
#[derive(Clone, Debug, PartialEq)]
pub struct TenantNode {
    pub id: String,
    pub level: String,
}

/// An ordered path of tenant nodes from root to leaf.
#[derive(Clone, Debug)]
pub struct TenantPath {
    pub nodes: Vec<TenantNode>,
}

impl TenantPath {
    pub fn new(nodes: Vec<TenantNode>) -> Self {
        Self { nodes }
    }

    /// The id of the deepest (leaf) node.
    pub fn leaf_id(&self) -> Option<&str> {
        self.nodes.last().map(|n| n.id.as_str())
    }

    /// The level name of the deepest (leaf) node.
    pub fn leaf_level(&self) -> Option<&str> {
        self.nodes.last().map(|n| n.level.as_str())
    }

    /// Find the tenant id at the given hierarchy level.
    pub fn id_at(&self, level: &str) -> Option<&str> {
        self.nodes
            .iter()
            .find(|n| n.level == level)
            .map(|n| n.id.as_str())
    }

    /// Returns true if this path is an ancestor of (or equal to) `other`.
    ///
    /// A path *contains* another if every node in `self` appears in `other`
    /// at the matching level with the same id.
    pub fn contains(&self, other: &TenantPath) -> bool {
        self.nodes.iter().all(|node| {
            other
                .nodes
                .iter()
                .any(|o| o.level == node.level && o.id == node.id)
        })
    }

    /// Returns true if any node in this path has the given id.
    pub fn is_descendant_of(&self, ancestor_id: &str) -> bool {
        self.nodes.iter().any(|n| n.id == ancestor_id)
    }

    /// Serialise the path as a level->id map suitable for JWT claims.
    pub fn to_claim(&self) -> HashMap<String, String> {
        self.nodes
            .iter()
            .map(|n| (n.level.clone(), n.id.clone()))
            .collect()
    }

    /// Reconstruct a path from a JWT claim map.
    ///
    /// Node ordering follows the natural iteration order of the map; callers
    /// that need a deterministic depth order should sort afterwards against a
    /// [`TenantHierarchy`].
    pub fn from_claim(claim: &HashMap<String, String>) -> Self {
        let nodes = claim
            .iter()
            .map(|(level, id)| TenantNode {
                id: id.clone(),
                level: level.clone(),
            })
            .collect();
        Self { nodes }
    }

    /// Create a single-node path (flat tenancy).
    pub fn from_flat(tenant_id: &str, level: &str) -> Self {
        Self {
            nodes: vec![TenantNode {
                id: tenant_id.to_owned(),
                level: level.to_owned(),
            }],
        }
    }
}

impl fmt::Display for TenantPath {
    /// Renders as "org:acme/region:us-west/group:sales".
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let parts: Vec<String> = self
            .nodes
            .iter()
            .map(|n| format!("{}:{}", n.level, n.id))
            .collect();
        write!(f, "{}", parts.join("/"))
    }
}

impl<'a> IntoIterator for &'a TenantPath {
    type Item = &'a TenantNode;
    type IntoIter = std::slice::Iter<'a, TenantNode>;

    fn into_iter(self) -> Self::IntoIter {
        self.nodes.iter()
    }
}

// ---------------------------------------------------------------------------
// TenantHierarchy
// ---------------------------------------------------------------------------

/// Defines the ordered set of levels in a multi-tenant hierarchy.
#[derive(Clone, Debug)]
pub struct TenantHierarchy {
    pub levels: Vec<TenantLevel>,
}

impl TenantHierarchy {
    /// Create a hierarchy from an ordered slice of level names.
    /// Depths are assigned sequentially starting at 0.
    pub fn new(level_names: &[&str]) -> Self {
        let levels = level_names
            .iter()
            .enumerate()
            .map(|(i, name)| TenantLevel {
                name: name.to_string(),
                depth: i,
            })
            .collect();
        Self { levels }
    }

    /// Create a hierarchy from pre-built levels.
    pub fn from_levels(levels: Vec<TenantLevel>) -> Self {
        Self { levels }
    }

    /// Return the depth of a level, if it exists.
    pub fn depth_of(&self, level_name: &str) -> Option<usize> {
        self.levels
            .iter()
            .find(|l| l.name == level_name)
            .map(|l| l.depth)
    }

    /// Return the name of the parent level (one depth less), if any.
    pub fn parent_of(&self, level_name: &str) -> Option<&str> {
        let depth = self.depth_of(level_name)?;
        if depth == 0 {
            return None;
        }
        self.levels
            .iter()
            .find(|l| l.depth == depth - 1)
            .map(|l| l.name.as_str())
    }

    /// Return the names of all immediate child levels (one depth greater).
    pub fn children_of(&self, level_name: &str) -> Vec<&str> {
        let depth = match self.depth_of(level_name) {
            Some(d) => d,
            None => return vec![],
        };
        self.levels
            .iter()
            .filter(|l| l.depth == depth + 1)
            .map(|l| l.name.as_str())
            .collect()
    }

    /// Look up a level by name.
    pub fn get(&self, level_name: &str) -> Option<&TenantLevel> {
        self.levels.iter().find(|l| l.name == level_name)
    }

    /// The shallowest level (depth 0).
    pub fn root(&self) -> Option<&TenantLevel> {
        self.levels.iter().min_by_key(|l| l.depth)
    }

    /// The deepest level.
    pub fn leaf(&self) -> Option<&TenantLevel> {
        self.levels.iter().max_by_key(|l| l.depth)
    }

    /// Returns true if a level with the given name exists.
    pub fn has(&self, level_name: &str) -> bool {
        self.levels.iter().any(|l| l.name == level_name)
    }
}

impl fmt::Display for TenantHierarchy {
    /// Renders as "org > region > group".
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let names: Vec<&str> = self.levels.iter().map(|l| l.name.as_str()).collect();
        write!(f, "{}", names.join(" > "))
    }
}

impl<'a> IntoIterator for &'a TenantHierarchy {
    type Item = &'a TenantLevel;
    type IntoIter = std::slice::Iter<'a, TenantLevel>;

    fn into_iter(self) -> Self::IntoIter {
        self.levels.iter()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hierarchy_basics() {
        let h = TenantHierarchy::new(&["org", "region", "group"]);
        assert_eq!(h.depth_of("org"), Some(0));
        assert_eq!(h.depth_of("region"), Some(1));
        assert_eq!(h.depth_of("group"), Some(2));
        assert_eq!(h.parent_of("region"), Some("org"));
        assert_eq!(h.parent_of("org"), None);
        assert_eq!(h.children_of("org"), vec!["region"]);
        assert!(h.has("group"));
        assert!(!h.has("team"));
        assert_eq!(h.root().unwrap().name, "org");
        assert_eq!(h.leaf().unwrap().name, "group");
    }

    #[test]
    fn test_tenant_path_display() {
        let path = TenantPath::new(vec![
            TenantNode { id: "acme".into(), level: "org".into() },
            TenantNode { id: "us-west".into(), level: "region".into() },
            TenantNode { id: "sales".into(), level: "group".into() },
        ]);
        assert_eq!(path.to_string(), "org:acme/region:us-west/group:sales");
    }

    #[test]
    fn test_tenant_path_queries() {
        let path = TenantPath::new(vec![
            TenantNode { id: "acme".into(), level: "org".into() },
            TenantNode { id: "sales".into(), level: "group".into() },
        ]);
        assert_eq!(path.leaf_id(), Some("sales"));
        assert_eq!(path.leaf_level(), Some("group"));
        assert_eq!(path.id_at("org"), Some("acme"));
        assert_eq!(path.id_at("region"), None);
        assert!(path.is_descendant_of("acme"));
        assert!(!path.is_descendant_of("nobody"));
    }

    #[test]
    fn test_tenant_path_contains() {
        let parent = TenantPath::new(vec![
            TenantNode { id: "acme".into(), level: "org".into() },
        ]);
        let child = TenantPath::new(vec![
            TenantNode { id: "acme".into(), level: "org".into() },
            TenantNode { id: "sales".into(), level: "group".into() },
        ]);
        assert!(parent.contains(&child));
        assert!(!child.contains(&parent));
    }

    #[test]
    fn test_tenant_path_claim_roundtrip() {
        let path = TenantPath::new(vec![
            TenantNode { id: "acme".into(), level: "org".into() },
            TenantNode { id: "us-west".into(), level: "region".into() },
        ]);
        let claim = path.to_claim();
        assert_eq!(claim.get("org"), Some(&"acme".to_string()));
        assert_eq!(claim.get("region"), Some(&"us-west".to_string()));

        let restored = TenantPath::from_claim(&claim);
        assert_eq!(restored.nodes.len(), 2);
    }

    #[test]
    fn test_tenant_path_from_flat() {
        let path = TenantPath::from_flat("tenant-1", "org");
        assert_eq!(path.nodes.len(), 1);
        assert_eq!(path.leaf_id(), Some("tenant-1"));
        assert_eq!(path.leaf_level(), Some("org"));
    }

    #[test]
    fn test_hierarchy_display() {
        let h = TenantHierarchy::new(&["org", "region", "group"]);
        assert_eq!(h.to_string(), "org > region > group");
    }
}
