use std::fmt;

const SEPARATORS: &[char] = &[':', '.', '@', '#', '|', '/', '$', '&'];

// ---------------------------------------------------------------------------
// Permission
// ---------------------------------------------------------------------------

#[derive(Clone, Debug, PartialEq)]
pub struct Permission {
    pub resource: String,
    pub action: String,
}

impl Permission {
    pub fn new(resource: &str, action: &str) -> Self {
        Self {
            resource: resource.to_string(),
            action: action.to_string(),
        }
    }

    /// Parse a permission string using any of the supported separators.
    ///
    /// Accepted forms:
    ///   "*"             -> resource="*", action="*"
    ///   "resource:*"    -> resource="resource", action="*"
    ///   "resource:read" -> resource="resource", action="read"
    ///   "resource"      -> resource="resource", action="*"
    pub fn parse(s: &str) -> Self {
        let s = s.trim();
        if s == "*" {
            return Self::new("*", "*");
        }
        for &sep in SEPARATORS {
            if let Some(pos) = s.find(sep) {
                let resource = &s[..pos];
                let action = &s[pos + sep.len_utf8()..];
                return Self::new(resource, action);
            }
        }
        // No separator found – treat the whole string as a resource with wildcard action.
        Self::new(s, "*")
    }

    /// Semantic matching with wildcard support.
    ///
    /// `self` is the *pattern*, `other` is the *target* being checked.
    ///   - `*:*`  matches everything
    ///   - `docs:*` matches any action on the `docs` resource
    ///   - Exact match is case-sensitive
    pub fn matches(&self, other: &Permission) -> bool {
        let resource_ok = self.resource == "*" || self.resource == other.resource;
        let action_ok = self.action == "*" || self.action == other.action;
        resource_ok && action_ok
    }
}

impl From<&str> for Permission {
    fn from(s: &str) -> Self {
        Permission::parse(s)
    }
}

impl fmt::Display for Permission {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}:{}", self.resource, self.action)
    }
}

/// Convenience: check whether a pattern permission string matches a target.
pub fn match_permission(pattern: &str, target: &str) -> bool {
    let pat = Permission::parse(pattern);
    let tgt = Permission::parse(target);
    pat.matches(&tgt)
}

// ---------------------------------------------------------------------------
// Role
// ---------------------------------------------------------------------------

#[derive(Clone, Debug, PartialEq)]
pub struct Role {
    pub name: String,
    pub permissions: Vec<Permission>,
}

impl Role {
    pub fn new(name: &str, permissions: Vec<Permission>) -> Self {
        Self {
            name: name.to_string(),
            permissions,
        }
    }
}

impl fmt::Display for Role {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.name)
    }
}

// ---------------------------------------------------------------------------
// Relation
// ---------------------------------------------------------------------------

#[derive(Clone, Debug, PartialEq)]
pub struct Relation {
    pub resource: String,
    pub name: String,
}

impl Relation {
    pub fn new(resource: &str, name: &str) -> Self {
        Self {
            resource: resource.to_string(),
            name: name.to_string(),
        }
    }

    /// Parse `"resource#name"` or `"resource:name"`.
    pub fn parse(s: &str) -> Self {
        let s = s.trim();
        if let Some(pos) = s.find('#') {
            let resource = &s[..pos];
            let name = &s[pos + 1..];
            return Self::new(resource, name);
        }
        if let Some(pos) = s.find(':') {
            let resource = &s[..pos];
            let name = &s[pos + 1..];
            return Self::new(resource, name);
        }
        Self::new(s, "")
    }

    /// Create a full relation tuple with an object id and optional subject.
    pub fn tuple(&self, object_id: &str, subject: Option<&str>) -> RelationTuple {
        RelationTuple {
            relation: self.clone(),
            object_id: object_id.to_string(),
            subject: subject.map(|s| s.to_string()),
        }
    }
}

impl From<&str> for Relation {
    fn from(s: &str) -> Self {
        Relation::parse(s)
    }
}

impl fmt::Display for Relation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}#{}", self.resource, self.name)
    }
}

// ---------------------------------------------------------------------------
// RelationTuple
// ---------------------------------------------------------------------------

#[derive(Clone, Debug, PartialEq)]
pub struct RelationTuple {
    pub relation: Relation,
    pub object_id: String,
    pub subject: Option<String>,
}

impl RelationTuple {
    /// Parse the Zanzibar-style format `"resource:object_id#relation@subject"`.
    ///
    /// Examples:
    ///   `"doc:readme#owner@user:alice"`
    ///   `"folder:root#viewer"`  (no subject)
    pub fn parse(s: &str) -> Option<Self> {
        let s = s.trim();

        // Split resource:object_id from relation(@subject)?
        let colon_pos = s.find(':')?;
        let resource = &s[..colon_pos];
        let rest = &s[colon_pos + 1..];

        // rest = "readme#owner@user:alice" or "readme#owner"
        let hash_pos = rest.find('#')?;
        let object_id = &rest[..hash_pos];
        let after_hash = &rest[hash_pos + 1..];

        let (relation_name, subject) = if let Some(at_pos) = after_hash.find('@') {
            let rel = &after_hash[..at_pos];
            let subj = &after_hash[at_pos + 1..];
            (rel, Some(subj.to_string()))
        } else {
            (after_hash, None)
        };

        Some(Self {
            relation: Relation::new(resource, relation_name),
            object_id: object_id.to_string(),
            subject,
        })
    }
}

impl fmt::Display for RelationTuple {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}:{}#{}", self.relation.resource, self.object_id, self.relation.name)?;
        if let Some(ref subject) = self.subject {
            write!(f, "@{}", subject)?;
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn permission_wildcard_matches_everything() {
        let pat = Permission::new("*", "*");
        let target = Permission::new("docs", "read");
        assert!(pat.matches(&target));
    }

    #[test]
    fn permission_resource_wildcard() {
        let pat = Permission::new("docs", "*");
        assert!(pat.matches(&Permission::new("docs", "read")));
        assert!(pat.matches(&Permission::new("docs", "write")));
        assert!(!pat.matches(&Permission::new("users", "read")));
    }

    #[test]
    fn permission_exact_match() {
        let pat = Permission::new("docs", "read");
        assert!(pat.matches(&Permission::new("docs", "read")));
        assert!(!pat.matches(&Permission::new("docs", "write")));
    }

    #[test]
    fn permission_parse_various_separators() {
        assert_eq!(Permission::parse("docs:read"), Permission::new("docs", "read"));
        assert_eq!(Permission::parse("docs.read"), Permission::new("docs", "read"));
        assert_eq!(Permission::parse("docs@read"), Permission::new("docs", "read"));
        assert_eq!(Permission::parse("docs#read"), Permission::new("docs", "read"));
        assert_eq!(Permission::parse("*"), Permission::new("*", "*"));
        assert_eq!(Permission::parse("docs"), Permission::new("docs", "*"));
    }

    #[test]
    fn match_permission_convenience() {
        assert!(match_permission("docs:*", "docs:read"));
        assert!(!match_permission("docs:write", "docs:read"));
    }

    #[test]
    fn relation_parse() {
        let rel = Relation::parse("doc#owner");
        assert_eq!(rel.resource, "doc");
        assert_eq!(rel.name, "owner");
    }

    #[test]
    fn relation_tuple_parse_with_subject() {
        let tuple = RelationTuple::parse("doc:readme#owner@user:alice").unwrap();
        assert_eq!(tuple.relation.resource, "doc");
        assert_eq!(tuple.relation.name, "owner");
        assert_eq!(tuple.object_id, "readme");
        assert_eq!(tuple.subject, Some("user:alice".to_string()));
    }

    #[test]
    fn relation_tuple_parse_without_subject() {
        let tuple = RelationTuple::parse("folder:root#viewer").unwrap();
        assert_eq!(tuple.relation.resource, "folder");
        assert_eq!(tuple.relation.name, "viewer");
        assert_eq!(tuple.object_id, "root");
        assert_eq!(tuple.subject, None);
    }

    #[test]
    fn relation_tuple_roundtrip() {
        let input = "doc:readme#owner@user:alice";
        let tuple = RelationTuple::parse(input).unwrap();
        assert_eq!(tuple.to_string(), input);
    }
}
