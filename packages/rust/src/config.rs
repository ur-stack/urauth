use serde::{Deserialize, Serialize};
use std::fmt;

use crate::errors::AuthError;

// ---------------------------------------------------------------------------
// Environment
// ---------------------------------------------------------------------------

/// Runtime environment for security-policy decisions.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Environment {
    Development,
    Production,
    Testing,
}

impl Default for Environment {
    fn default() -> Self {
        Environment::Development
    }
}

impl fmt::Display for Environment {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let label = match self {
            Environment::Development => "development",
            Environment::Production => "production",
            Environment::Testing => "testing",
        };
        f.write_str(label)
    }
}

// ---------------------------------------------------------------------------
// AuthConfig
// ---------------------------------------------------------------------------

const DEFAULT_SECRET: &str = "CHANGE-ME-IN-PRODUCTION";

/// Core authentication configuration.
///
/// Mirrors the config surface of the Node (`@urauth/node`) and Python
/// (`urauth`) packages so behaviour is consistent across runtimes.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AuthConfig {
    pub secret_key: String,

    #[serde(default = "default_algorithm")]
    pub algorithm: String,

    #[serde(default)]
    pub issuer: Option<String>,

    #[serde(default)]
    pub audience: Option<String>,

    /// Access-token lifetime in seconds (default 900 = 15 min).
    #[serde(default = "default_access_token_ttl")]
    pub access_token_ttl: u64,

    /// Refresh-token lifetime in seconds (default 604_800 = 7 days).
    #[serde(default = "default_refresh_token_ttl")]
    pub refresh_token_ttl: u64,

    /// Whether to rotate refresh tokens on each use.
    #[serde(default = "default_rotate_refresh_tokens")]
    pub rotate_refresh_tokens: bool,

    /// Session lifetime in seconds (default 86_400 = 24 hours).
    #[serde(default = "default_session_ttl")]
    pub session_ttl: u64,

    #[serde(default)]
    pub environment: Environment,

    /// When `true`, validation permits the default placeholder key.
    /// **Must** be `false` in production.
    #[serde(default)]
    pub allow_insecure_key: bool,
}

// -- serde default helpers --------------------------------------------------

fn default_algorithm() -> String {
    "HS256".to_string()
}
fn default_access_token_ttl() -> u64 {
    900
}
fn default_refresh_token_ttl() -> u64 {
    604_800
}
fn default_rotate_refresh_tokens() -> bool {
    true
}
fn default_session_ttl() -> u64 {
    86_400
}

impl Default for AuthConfig {
    fn default() -> Self {
        AuthConfig {
            secret_key: DEFAULT_SECRET.to_string(),
            algorithm: default_algorithm(),
            issuer: None,
            audience: None,
            access_token_ttl: default_access_token_ttl(),
            refresh_token_ttl: default_refresh_token_ttl(),
            rotate_refresh_tokens: default_rotate_refresh_tokens(),
            session_ttl: default_session_ttl(),
            environment: Environment::default(),
            allow_insecure_key: false,
        }
    }
}

impl AuthConfig {
    /// Start building an [`AuthConfig`] with the given secret key.
    pub fn builder(secret_key: impl Into<String>) -> AuthConfigBuilder {
        AuthConfigBuilder {
            config: AuthConfig {
                secret_key: secret_key.into(),
                ..AuthConfig::default()
            },
        }
    }
}

// ---------------------------------------------------------------------------
// Validation
// ---------------------------------------------------------------------------

/// Well-known weak secrets that are rejected regardless of length.
const WEAK_SECRETS: &[&str] = &[
    "secret",
    "password",
    "changeme",
    "test",
    "key",
    "admin",
    "123456",
    "jwt-secret",
    "my-secret",
    "super-secret",
];

/// Validate an [`AuthConfig`], returning `Err(AuthError::Config { .. })` on
/// any policy violation.
pub fn validate_config(config: &AuthConfig) -> Result<(), AuthError> {
    let key = &config.secret_key;

    // 1. Empty / whitespace-only key.
    if key.trim().is_empty() {
        return Err(AuthError::config(
            "secret_key must not be empty or whitespace-only",
        ));
    }

    let is_default_key = key == DEFAULT_SECRET;

    // 2. Default placeholder key (unless explicitly allowed).
    if is_default_key && !config.allow_insecure_key {
        return Err(AuthError::config(
            "secret_key is the default placeholder; set a real key or enable allow_insecure_key",
        ));
    }

    // 3. HMAC minimum key length.
    let hmac_algos = ["HS256", "HS384", "HS512"];
    if hmac_algos.contains(&config.algorithm.as_str()) && key.len() < 32 {
        return Err(AuthError::config(format!(
            "secret_key must be at least 32 characters for {} (got {})",
            config.algorithm,
            key.len(),
        )));
    }

    // 4. Well-known weak secrets (case-insensitive).
    let lower = key.to_lowercase();
    for weak in WEAK_SECRETS {
        if lower == *weak {
            return Err(AuthError::config(format!(
                "secret_key is a well-known weak value: \"{weak}\""
            )));
        }
    }

    // 5. Production-specific hardening.
    if config.environment == Environment::Production {
        if config.allow_insecure_key {
            return Err(AuthError::config(
                "allow_insecure_key must be false in production",
            ));
        }
        if is_default_key {
            return Err(AuthError::config(
                "default secret_key must not be used in production",
            ));
        }
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Builder
// ---------------------------------------------------------------------------

/// Fluent builder for [`AuthConfig`].
///
/// ```rust,no_run
/// use urauth::config::{AuthConfig, Environment};
///
/// let cfg = AuthConfig::builder("my-very-long-secret-key-at-least-32c")
///     .algorithm("HS512")
///     .issuer("https://auth.example.com")
///     .environment(Environment::Production)
///     .build()
///     .expect("valid config");
/// ```
pub struct AuthConfigBuilder {
    config: AuthConfig,
}

impl AuthConfigBuilder {
    pub fn algorithm(mut self, algorithm: impl Into<String>) -> Self {
        self.config.algorithm = algorithm.into();
        self
    }

    pub fn issuer(mut self, issuer: impl Into<String>) -> Self {
        self.config.issuer = Some(issuer.into());
        self
    }

    pub fn audience(mut self, audience: impl Into<String>) -> Self {
        self.config.audience = Some(audience.into());
        self
    }

    pub fn access_token_ttl(mut self, seconds: u64) -> Self {
        self.config.access_token_ttl = seconds;
        self
    }

    pub fn refresh_token_ttl(mut self, seconds: u64) -> Self {
        self.config.refresh_token_ttl = seconds;
        self
    }

    pub fn rotate_refresh_tokens(mut self, enabled: bool) -> Self {
        self.config.rotate_refresh_tokens = enabled;
        self
    }

    pub fn session_ttl(mut self, seconds: u64) -> Self {
        self.config.session_ttl = seconds;
        self
    }

    pub fn environment(mut self, env: Environment) -> Self {
        self.config.environment = env;
        self
    }

    pub fn allow_insecure_key(mut self, allow: bool) -> Self {
        self.config.allow_insecure_key = allow;
        self
    }

    /// Consume the builder, validate, and return the config.
    pub fn build(self) -> Result<AuthConfig, AuthError> {
        validate_config(&self.config)?;
        Ok(self.config)
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn valid_key() -> &'static str {
        "a]k9#mZ!pQ7xL2wR@vN4bT8cY0dF6eH" // 32 chars
    }

    #[test]
    fn default_config_uses_placeholder_key() {
        let cfg = AuthConfig::default();
        assert_eq!(cfg.secret_key, "CHANGE-ME-IN-PRODUCTION");
        assert_eq!(cfg.algorithm, "HS256");
        assert_eq!(cfg.access_token_ttl, 900);
        assert_eq!(cfg.refresh_token_ttl, 604_800);
        assert!(cfg.rotate_refresh_tokens);
        assert_eq!(cfg.session_ttl, 86_400);
        assert_eq!(cfg.environment, Environment::Development);
        assert!(!cfg.allow_insecure_key);
    }

    #[test]
    fn reject_empty_key() {
        let cfg = AuthConfig {
            secret_key: "   ".into(),
            ..AuthConfig::default()
        };
        assert!(validate_config(&cfg).is_err());
    }

    #[test]
    fn reject_default_key_without_flag() {
        let cfg = AuthConfig::default();
        assert!(validate_config(&cfg).is_err());
    }

    #[test]
    fn allow_default_key_with_flag() {
        let cfg = AuthConfig {
            allow_insecure_key: true,
            ..AuthConfig::default()
        };
        assert!(validate_config(&cfg).is_ok());
    }

    #[test]
    fn reject_short_hmac_key() {
        let cfg = AuthConfig {
            secret_key: "tooshort".into(),
            allow_insecure_key: true,
            ..AuthConfig::default()
        };
        assert!(validate_config(&cfg).is_err());
    }

    #[test]
    fn reject_weak_secret() {
        for weak in WEAK_SECRETS {
            // Pad to 32 chars is irrelevant -- the check is exact-match on
            // the lowercase value, so the raw weak word (< 32 chars for most)
            // will hit the length check first.  Test the detection by using a
            // non-HMAC algorithm.
            let cfg = AuthConfig {
                secret_key: weak.to_uppercase(),
                algorithm: "RS256".into(),
                allow_insecure_key: true,
                ..AuthConfig::default()
            };
            let err = validate_config(&cfg);
            assert!(err.is_err(), "should reject weak secret: {weak}");
        }
    }

    #[test]
    fn production_rejects_allow_insecure_key() {
        let cfg = AuthConfig {
            secret_key: valid_key().into(),
            environment: Environment::Production,
            allow_insecure_key: true,
            ..AuthConfig::default()
        };
        assert!(validate_config(&cfg).is_err());
    }

    #[test]
    fn builder_happy_path() {
        let cfg = AuthConfig::builder(valid_key())
            .algorithm("HS512")
            .issuer("https://auth.example.com")
            .audience("my-app")
            .access_token_ttl(300)
            .refresh_token_ttl(3600)
            .rotate_refresh_tokens(false)
            .session_ttl(7200)
            .environment(Environment::Production)
            .build()
            .expect("should be valid");

        assert_eq!(cfg.algorithm, "HS512");
        assert_eq!(cfg.issuer.as_deref(), Some("https://auth.example.com"));
        assert_eq!(cfg.audience.as_deref(), Some("my-app"));
        assert_eq!(cfg.access_token_ttl, 300);
        assert_eq!(cfg.refresh_token_ttl, 3600);
        assert!(!cfg.rotate_refresh_tokens);
        assert_eq!(cfg.session_ttl, 7200);
        assert_eq!(cfg.environment, Environment::Production);
    }

    #[test]
    fn builder_rejects_bad_config() {
        let result = AuthConfig::builder("short").build();
        assert!(result.is_err());
    }

    #[test]
    fn environment_display() {
        assert_eq!(Environment::Development.to_string(), "development");
        assert_eq!(Environment::Production.to_string(), "production");
        assert_eq!(Environment::Testing.to_string(), "testing");
    }

    #[test]
    fn environment_serde_lowercase() {
        let json = serde_json::to_string(&Environment::Production).unwrap();
        assert_eq!(json, "\"production\"");
        let parsed: Environment = serde_json::from_str("\"testing\"").unwrap();
        assert_eq!(parsed, Environment::Testing);
    }
}
