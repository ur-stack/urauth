use thiserror::Error;

/// Base authentication/authorization error hierarchy for urauth.
#[derive(Debug, Clone, Error)]
pub enum AuthError {
    #[error("Invalid token: {detail}")]
    InvalidToken { detail: String },

    #[error("Token expired: {detail}")]
    TokenExpired { detail: String },

    #[error("Token revoked: {detail}")]
    TokenRevoked { detail: String },

    #[error("Unauthorized: {detail}")]
    Unauthorized { detail: String },

    #[error("Forbidden: {detail}")]
    Forbidden { detail: String },

    #[error("Configuration error: {detail}")]
    Config { detail: String },

    #[error("Password hash error: {detail}")]
    PasswordHash { detail: String },
}

impl AuthError {
    /// Returns the HTTP status code associated with this error variant.
    pub fn status_code(&self) -> u16 {
        match self {
            AuthError::InvalidToken { .. } => 401,
            AuthError::TokenExpired { .. } => 401,
            AuthError::TokenRevoked { .. } => 401,
            AuthError::Unauthorized { .. } => 401,
            AuthError::Forbidden { .. } => 403,
            AuthError::Config { .. } => 500,
            AuthError::PasswordHash { .. } => 500,
        }
    }

    /// Returns the detail message for this error.
    pub fn detail(&self) -> &str {
        match self {
            AuthError::InvalidToken { detail } => detail,
            AuthError::TokenExpired { detail } => detail,
            AuthError::TokenRevoked { detail } => detail,
            AuthError::Unauthorized { detail } => detail,
            AuthError::Forbidden { detail } => detail,
            AuthError::Config { detail } => detail,
            AuthError::PasswordHash { detail } => detail,
        }
    }

    // -- Convenience constructors --

    pub fn invalid_token(detail: impl Into<String>) -> Self {
        AuthError::InvalidToken {
            detail: detail.into(),
        }
    }

    pub fn token_expired(detail: impl Into<String>) -> Self {
        AuthError::TokenExpired {
            detail: detail.into(),
        }
    }

    pub fn token_revoked(detail: impl Into<String>) -> Self {
        AuthError::TokenRevoked {
            detail: detail.into(),
        }
    }

    pub fn unauthorized() -> Self {
        AuthError::Unauthorized {
            detail: "Not authenticated".to_string(),
        }
    }

    pub fn forbidden(detail: impl Into<String>) -> Self {
        AuthError::Forbidden {
            detail: detail.into(),
        }
    }

    pub fn config(detail: impl Into<String>) -> Self {
        AuthError::Config {
            detail: detail.into(),
        }
    }

    pub fn password_hash(detail: impl Into<String>) -> Self {
        AuthError::PasswordHash {
            detail: detail.into(),
        }
    }
}
