use std::collections::HashMap;

use jsonwebtoken::{Algorithm, DecodingKey, EncodingKey, Header, Validation};
use uuid::Uuid;

use crate::config::AuthConfig;
use crate::errors::AuthError;
use crate::types::{TokenPayload, TokenPair};

// ---- Option structs --------------------------------------------------------

#[derive(Debug, Clone, Default)]
pub struct CreateAccessTokenOptions {
    pub scopes: Option<Vec<String>>,
    pub roles: Option<Vec<String>>,
    pub tenant_id: Option<String>,
    pub tenant_path: Option<HashMap<String, String>>,
    pub fresh: Option<bool>,
    pub extra_claims: Option<HashMap<String, serde_json::Value>>,
}

#[derive(Debug, Clone, Default)]
pub struct CreateRefreshTokenOptions {
    pub family_id: Option<String>,
}

#[derive(Debug, Clone, Default)]
pub struct CreateTokenPairOptions {
    pub scopes: Option<Vec<String>>,
    pub roles: Option<Vec<String>>,
    pub tenant_id: Option<String>,
    pub tenant_path: Option<HashMap<String, String>>,
    pub fresh: Option<bool>,
    pub extra_claims: Option<HashMap<String, serde_json::Value>>,
    pub family_id: Option<String>,
}

// ---- Helpers ---------------------------------------------------------------

/// Reserved claim names that must not appear in `extra_claims`.
const RESERVED_CLAIMS: &[&str] = &[
    "sub", "jti", "iat", "exp", "type", "scopes", "roles", "permissions",
    "tenant_id", "tenant_path", "fresh", "family_id", "iss", "aud",
];

fn map_algorithm(alg: &str) -> Result<Algorithm, AuthError> {
    match alg {
        "HS256" => Ok(Algorithm::HS256),
        "HS384" => Ok(Algorithm::HS384),
        "HS512" => Ok(Algorithm::HS512),
        "RS256" => Ok(Algorithm::RS256),
        "ES256" => Ok(Algorithm::ES256),
        other => Err(AuthError::config(format!("unsupported algorithm: {other}"))),
    }
}

fn now_epoch() -> i64 {
    chrono::Utc::now().timestamp()
}

fn new_jti() -> String {
    Uuid::new_v4().as_simple().to_string()
}

// ---- TokenService ----------------------------------------------------------

/// Low-level service for creating and decoding JWT tokens.
#[derive(Debug, Clone)]
pub struct TokenService {
    config: AuthConfig,
}

impl TokenService {
    pub fn new(config: AuthConfig) -> Self {
        Self { config }
    }

    /// Create a signed access token JWT string.
    pub fn create_access_token(
        &self,
        user_id: &str,
        opts: CreateAccessTokenOptions,
    ) -> Result<String, AuthError> {
        let now = now_epoch();
        let exp = now + self.config.access_token_ttl as i64;

        let mut payload = TokenPayload {
            sub: user_id.to_string(),
            jti: new_jti(),
            iat: now,
            exp,
            token_type: "access".to_string(),
            scopes: opts.scopes,
            roles: opts.roles,
            permissions: None,
            tenant_id: opts.tenant_id,
            tenant_path: opts.tenant_path,
            fresh: opts.fresh,
            family_id: None,
            extra: HashMap::new(),
        };

        // Merge extra claims, filtering out reserved keys.
        if let Some(extra) = opts.extra_claims {
            for (k, v) in extra {
                if !RESERVED_CLAIMS.contains(&k.as_str()) {
                    payload.extra.insert(k, v);
                }
            }
        }

        self.encode(&payload)
    }

    /// Create a signed refresh token JWT string.
    pub fn create_refresh_token(
        &self,
        user_id: &str,
        opts: CreateRefreshTokenOptions,
    ) -> Result<String, AuthError> {
        let now = now_epoch();
        let exp = now + self.config.refresh_token_ttl as i64;

        let payload = TokenPayload {
            sub: user_id.to_string(),
            jti: new_jti(),
            iat: now,
            exp,
            token_type: "refresh".to_string(),
            scopes: None,
            roles: None,
            permissions: None,
            tenant_id: None,
            tenant_path: None,
            fresh: None,
            family_id: opts.family_id,
            extra: HashMap::new(),
        };

        self.encode(&payload)
    }

    /// Create a matched access + refresh token pair.
    pub fn create_token_pair(
        &self,
        user_id: &str,
        opts: CreateTokenPairOptions,
    ) -> Result<TokenPair, AuthError> {
        let access_opts = CreateAccessTokenOptions {
            scopes: opts.scopes,
            roles: opts.roles,
            tenant_id: opts.tenant_id,
            tenant_path: opts.tenant_path,
            fresh: opts.fresh,
            extra_claims: opts.extra_claims,
        };
        let refresh_opts = CreateRefreshTokenOptions {
            family_id: opts.family_id,
        };

        let access_token = self.create_access_token(user_id, access_opts)?;
        let refresh_token = self.create_refresh_token(user_id, refresh_opts)?;

        Ok(TokenPair {
            access_token,
            refresh_token,
            token_type: "Bearer".to_string(),
        })
    }

    /// Decode and verify a JWT string, returning the payload.
    pub fn decode_token(&self, token: &str) -> Result<TokenPayload, AuthError> {
        let alg = map_algorithm(&self.config.algorithm)?;

        let mut validation = Validation::new(alg);
        validation.validate_exp = true;

        if let Some(ref issuer) = self.config.issuer {
            validation.set_issuer(&[issuer]);
        }
        if let Some(ref audience) = self.config.audience {
            validation.set_audience(&[audience]);
        }

        // Required claims.
        validation.set_required_spec_claims(&["sub", "exp", "iat"]);

        let key = DecodingKey::from_secret(self.config.secret_key.as_bytes());

        let token_data = jsonwebtoken::decode::<TokenPayload>(token, &key, &validation)
            .map_err(|e| match e.kind() {
                jsonwebtoken::errors::ErrorKind::ExpiredSignature => {
                    AuthError::token_expired("token has expired")
                }
                _ => AuthError::invalid_token(format!("invalid token: {e}")),
            })?;

        Ok(token_data.claims)
    }

    /// Decode, verify, and assert that the token type is `"access"`.
    pub fn validate_access_token(&self, token: &str) -> Result<TokenPayload, AuthError> {
        let payload = self.decode_token(token)?;
        if payload.token_type != "access" {
            return Err(AuthError::invalid_token(
                "expected access token, got other type",
            ));
        }
        Ok(payload)
    }

    /// Decode, verify, and assert that the token type is `"refresh"`.
    pub fn validate_refresh_token(&self, token: &str) -> Result<TokenPayload, AuthError> {
        let payload = self.decode_token(token)?;
        if payload.token_type != "refresh" {
            return Err(AuthError::invalid_token(
                "expected refresh token, got other type",
            ));
        }
        Ok(payload)
    }

    // -- private -------------------------------------------------------------

    fn encode(&self, payload: &TokenPayload) -> Result<String, AuthError> {
        let alg = map_algorithm(&self.config.algorithm)?;
        let header = Header::new(alg);
        let key = EncodingKey::from_secret(self.config.secret_key.as_bytes());

        jsonwebtoken::encode(&header, payload, &key)
            .map_err(|e| AuthError::config(format!("failed to encode token: {e}")))
    }
}
