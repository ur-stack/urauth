/// Transport trait for extracting/setting tokens from/to HTTP requests/responses.
///
/// This is kept generic -- framework-specific packages (actix-web, axum, etc.)
/// provide concrete implementations.
pub trait Transport: Send + Sync {
    type Request;
    type Response;

    /// Extract the token string from the request (e.g. from a header or cookie).
    fn extract_token(&self, request: &Self::Request) -> Option<String>;

    /// Attach a token to the response (e.g. set a cookie or response header).
    fn set_token(&self, response: &mut Self::Response, token: &str);

    /// Remove the token from the response (e.g. clear a cookie).
    fn delete_token(&self, response: &mut Self::Response);
}

/// Extract a bearer token from an `Authorization` header value.
///
/// Parses the `"Bearer <token>"` format. Returns `None` if the header does
/// not start with the `Bearer ` prefix (case-insensitive).
pub fn extract_bearer_token(auth_header: &str) -> Option<&str> {
    let trimmed = auth_header.trim();
    if trimmed.len() > 7 && trimmed[..7].eq_ignore_ascii_case("bearer ") {
        Some(trimmed[7..].trim())
    } else {
        None
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extracts_bearer_token() {
        assert_eq!(
            extract_bearer_token("Bearer abc123"),
            Some("abc123")
        );
    }

    #[test]
    fn extracts_bearer_case_insensitive() {
        assert_eq!(
            extract_bearer_token("bearer abc123"),
            Some("abc123")
        );
        assert_eq!(
            extract_bearer_token("BEARER abc123"),
            Some("abc123")
        );
    }

    #[test]
    fn trims_whitespace() {
        assert_eq!(
            extract_bearer_token("  Bearer   xyz  "),
            Some("xyz")
        );
    }

    #[test]
    fn returns_none_for_non_bearer() {
        assert_eq!(extract_bearer_token("Basic dXNlcjpwYXNz"), None);
    }

    #[test]
    fn returns_none_for_empty() {
        assert_eq!(extract_bearer_token(""), None);
    }

    #[test]
    fn returns_none_for_bearer_only() {
        assert_eq!(extract_bearer_token("Bearer"), None);
    }
}
