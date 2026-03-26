use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Decoded JWT token payload, matching the Node/TS `TokenPayload` interface.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenPayload {
    /// Subject (user ID).
    pub sub: String,

    /// Unique token identifier.
    pub jti: String,

    /// Issued-at timestamp (Unix epoch seconds).
    pub iat: i64,

    /// Expiration timestamp (Unix epoch seconds).
    pub exp: i64,

    /// Token type (e.g. "access", "refresh").
    #[serde(rename = "type")]
    pub token_type: String,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scopes: Option<Vec<String>>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub roles: Option<Vec<String>>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub permissions: Option<Vec<String>>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tenant_id: Option<String>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tenant_path: Option<HashMap<String, String>>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fresh: Option<bool>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub family_id: Option<String>,

    /// Any additional claims not covered by the named fields.
    #[serde(flatten, default)]
    pub extra: HashMap<String, serde_json::Value>,
}

/// A pair of encoded JWT strings returned to the client.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenPair {
    pub access_token: String,
    pub refresh_token: String,

    #[serde(default = "default_token_type")]
    pub token_type: String,
}

/// A token pair together with the decoded access-token payload (server-side use).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IssuedTokenPair {
    pub access_token: String,
    pub refresh_token: String,
    pub token_type: String,
    pub payload: TokenPayload,
}

/// Parameters for issuing a new token pair.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IssueRequest {
    pub user_id: String,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scopes: Option<Vec<String>>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub roles: Option<Vec<String>>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tenant_id: Option<String>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tenant_path: Option<HashMap<String, String>>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fresh: Option<bool>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub extra_claims: Option<HashMap<String, serde_json::Value>>,
}

fn default_token_type() -> String {
    "Bearer".to_string()
}
