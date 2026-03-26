use std::sync::Arc;

use uuid::Uuid;

use crate::config::AuthConfig;
use crate::errors::AuthError;
use crate::stores::TokenStore;
use crate::types::IssuedTokenPair;

use super::jwt::{
    CreateTokenPairOptions, TokenService,
};

/// Service that handles refresh-token rotation with replay-attack detection.
pub struct RefreshService {
    token_service: TokenService,
    store: Arc<dyn TokenStore>,
    #[allow(dead_code)]
    config: AuthConfig,
}

impl RefreshService {
    pub fn new(
        token_service: TokenService,
        store: Arc<dyn TokenStore>,
        config: AuthConfig,
    ) -> Self {
        Self {
            token_service,
            store,
            config,
        }
    }

    /// Rotate a refresh token: validate the old one, detect replay attacks,
    /// revoke the old token, issue a new pair, and persist the new tokens.
    ///
    /// Returns an [`IssuedTokenPair`] containing the new access and refresh
    /// tokens together with the decoded access-token payload.
    pub async fn rotate(&self, raw_refresh_token: &str) -> Result<IssuedTokenPair, AuthError> {
        // 1. Validate the refresh token (signature + expiry + type).
        let payload = self.token_service.validate_refresh_token(raw_refresh_token)?;
        let jti = &payload.jti;
        let user_id = &payload.sub;
        let family_id = payload.family_id.clone();

        // 2. Check if the token has already been revoked (replay-attack detection).
        if self.store.is_revoked(jti).await? {
            // This token was already used; this is a reuse attack.
            if let Some(ref fid) = family_id {
                // Revoke the entire token family.
                self.store.revoke_family(fid).await?;
            } else {
                // No family tracking; revoke all tokens for the user.
                self.store.revoke_all_for_user(user_id).await?;
            }
            return Err(AuthError::token_revoked(
                "refresh token reuse detected; token family revoked",
            ));
        }

        // 3. Revoke the old refresh token.
        self.store.revoke(jti, payload.exp).await?;

        // 4. Determine the family_id for the new pair.
        let new_family_id = family_id.unwrap_or_else(|| Uuid::new_v4().as_simple().to_string());

        // 5. Create a new token pair with the same family.
        let pair = self.token_service.create_token_pair(
            user_id,
            CreateTokenPairOptions {
                family_id: Some(new_family_id.clone()),
                ..Default::default()
            },
        )?;

        // 6. Decode the new access token to get its payload for storage.
        let access_payload = self.token_service.decode_token(&pair.access_token)?;
        let refresh_payload = self.token_service.decode_token(&pair.refresh_token)?;

        // 7. Store the new tokens.
        self.store
            .add_token(
                &access_payload.jti,
                user_id,
                "access",
                access_payload.exp,
                Some(&new_family_id),
            )
            .await?;

        self.store
            .add_token(
                &refresh_payload.jti,
                user_id,
                "refresh",
                refresh_payload.exp,
                Some(&new_family_id),
            )
            .await?;

        // 8. Return the issued pair.
        Ok(IssuedTokenPair {
            access_token: pair.access_token,
            refresh_token: pair.refresh_token,
            token_type: "Bearer".to_string(),
            payload: access_payload,
        })
    }
}
