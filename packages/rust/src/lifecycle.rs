use std::sync::Arc;

use uuid::Uuid;

use crate::config::AuthConfig;
use crate::errors::AuthError;
use crate::stores::TokenStore;
use crate::tokens::jwt::{
    CreateAccessTokenOptions, CreateRefreshTokenOptions, TokenService,
};
use crate::tokens::refresh::RefreshService;
use crate::tokens::revocation::RevocationService;
use crate::types::{IssuedTokenPair, IssueRequest, TokenPayload};

/// High-level orchestrator for all token lifecycle operations: issue, refresh,
/// revoke, and validate.
pub struct TokenLifecycle {
    token_service: TokenService,
    store: Arc<dyn TokenStore>,
    revocation: RevocationService,
    refresh_service: RefreshService,
    #[allow(dead_code)]
    config: AuthConfig,
}

impl TokenLifecycle {
    /// Create a new lifecycle manager from a config and a token store.
    pub fn new(config: AuthConfig, store: Arc<dyn TokenStore>) -> Self {
        let token_service = TokenService::new(config.clone());
        let revocation = RevocationService::new(Arc::clone(&store));
        let refresh_service = RefreshService::new(
            TokenService::new(config.clone()),
            Arc::clone(&store),
            config.clone(),
        );

        Self {
            token_service,
            store,
            revocation,
            refresh_service,
            config,
        }
    }

    /// Issue a new access + refresh token pair, persisting both in the store.
    pub async fn issue(&self, request: IssueRequest) -> Result<IssuedTokenPair, AuthError> {
        let family_id = Uuid::new_v4().as_simple().to_string();

        // Build the access token.
        let access_opts = CreateAccessTokenOptions {
            scopes: request.scopes,
            roles: request.roles,
            tenant_id: request.tenant_id,
            tenant_path: request.tenant_path,
            fresh: request.fresh,
            extra_claims: request.extra_claims,
        };
        let access_token = self
            .token_service
            .create_access_token(&request.user_id, access_opts)?;

        // Build the refresh token.
        let refresh_opts = CreateRefreshTokenOptions {
            family_id: Some(family_id.clone()),
        };
        let refresh_token = self
            .token_service
            .create_refresh_token(&request.user_id, refresh_opts)?;

        // Decode the access token to extract its payload.
        let access_payload = self.token_service.decode_token(&access_token)?;
        let refresh_payload = self.token_service.decode_token(&refresh_token)?;

        // Persist both tokens in the store.
        self.store
            .add_token(
                &access_payload.jti,
                &request.user_id,
                "access",
                access_payload.exp,
                Some(&family_id),
            )
            .await?;

        self.store
            .add_token(
                &refresh_payload.jti,
                &request.user_id,
                "refresh",
                refresh_payload.exp,
                Some(&family_id),
            )
            .await?;

        Ok(IssuedTokenPair {
            access_token,
            refresh_token,
            token_type: "Bearer".to_string(),
            payload: access_payload,
        })
    }

    /// Rotate a refresh token, returning a new token pair.
    pub async fn refresh(&self, raw_refresh_token: &str) -> Result<IssuedTokenPair, AuthError> {
        self.refresh_service.rotate(raw_refresh_token).await
    }

    /// Revoke a single token (access or refresh). The token is decoded first
    /// to extract its JTI; expiry validation is skipped so that already-expired
    /// tokens can still be explicitly revoked.
    pub async fn revoke(&self, raw_token: &str) -> Result<(), AuthError> {
        // Decode ignoring expiry so we can revoke expired tokens too.
        let payload = self.decode_ignoring_expiry(raw_token)?;
        self.revocation.revoke(&payload.jti, payload.exp).await
    }

    /// Revoke all tokens belonging to the given user.
    pub async fn revoke_all(&self, user_id: &str) -> Result<(), AuthError> {
        self.revocation.revoke_all_for_user(user_id).await
    }

    /// Validate an access token: verify signature, expiry, type, and
    /// revocation status.
    pub async fn validate(&self, raw_access_token: &str) -> Result<TokenPayload, AuthError> {
        let payload = self.token_service.validate_access_token(raw_access_token)?;

        if self.revocation.is_revoked(&payload.jti).await? {
            return Err(AuthError::token_revoked("token has been revoked"));
        }

        Ok(payload)
    }

    // -- private -------------------------------------------------------------

    /// Decode a token without validating expiry (used for revocation).
    fn decode_ignoring_expiry(&self, token: &str) -> Result<TokenPayload, AuthError> {
        use jsonwebtoken::{DecodingKey, Validation};

        let alg = match self.config.algorithm.as_str() {
            "HS256" => jsonwebtoken::Algorithm::HS256,
            "HS384" => jsonwebtoken::Algorithm::HS384,
            "HS512" => jsonwebtoken::Algorithm::HS512,
            "RS256" => jsonwebtoken::Algorithm::RS256,
            "ES256" => jsonwebtoken::Algorithm::ES256,
            other => {
                return Err(AuthError::config(format!(
                    "unsupported algorithm: {other}"
                )))
            }
        };

        let mut validation = Validation::new(alg);
        validation.validate_exp = false;
        validation.set_required_spec_claims(&["sub", "iat"]);

        if let Some(ref issuer) = self.config.issuer {
            validation.set_issuer(&[issuer]);
        }
        if let Some(ref audience) = self.config.audience {
            validation.set_audience(&[audience]);
        }

        let key = DecodingKey::from_secret(self.config.secret_key.as_bytes());

        let token_data = jsonwebtoken::decode::<TokenPayload>(token, &key, &validation)
            .map_err(|e| AuthError::invalid_token(format!("invalid token: {e}")))?;

        Ok(token_data.claims)
    }
}
