use std::collections::HashMap;

use tokio::sync::RwLock;

use crate::errors::AuthError;

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

/// Strategy for building the rate-limit key.
#[derive(Clone, Debug, Default)]
pub enum KeyStrategy {
    /// Key by IP address (default).
    #[default]
    Ip,
    /// Key by authenticated user id.
    User,
    /// Key by combined IP + user id.
    IpAndUser,
}

/// Configuration for a [`RateLimiter`] instance.
#[derive(Clone, Debug)]
pub struct RateLimiterOptions {
    /// Duration window as a human-readable string: `"15m"`, `"1h"`, `"60s"`, `"1d"`.
    pub window: String,
    /// Maximum number of requests allowed within the window.
    pub max: u64,
    /// How to derive the rate-limit key.
    pub key_strategy: KeyStrategy,
}

/// Result returned from a rate-limit check.
#[derive(Clone, Debug)]
pub struct RateLimitResult {
    /// Whether the request is allowed.
    pub allowed: bool,
    /// Number of remaining requests in the current window.
    pub remaining: u64,
    /// Unix timestamp (milliseconds) at which the window resets.
    pub reset_at: u64,
}

// ---------------------------------------------------------------------------
// Internal counter
// ---------------------------------------------------------------------------

#[derive(Debug)]
struct Counter {
    count: u64,
    reset_at: u64,
}

// ---------------------------------------------------------------------------
// RateLimiter
// ---------------------------------------------------------------------------

/// In-memory sliding-window rate limiter.
///
/// Counters are stored per-key in a `tokio::sync::RwLock`-protected map, so
/// the limiter is safe to share across async tasks.
pub struct RateLimiter {
    window_ms: u64,
    max: u64,
    key_strategy: KeyStrategy,
    counters: RwLock<HashMap<String, Counter>>,
}

impl RateLimiter {
    /// Create a new rate limiter, parsing the window duration string.
    ///
    /// Returns `AuthError::Config` if the window format is invalid.
    pub fn new(options: RateLimiterOptions) -> Result<Self, AuthError> {
        let window_ms = parse_window(&options.window)?;
        Ok(Self {
            window_ms,
            max: options.max,
            key_strategy: options.key_strategy,
            counters: RwLock::new(HashMap::new()),
        })
    }

    /// Check (and increment) the counter for the given key.
    pub async fn check(&self, key: &str) -> RateLimitResult {
        let now = now_ms();
        let mut counters = self.counters.write().await;

        let counter = counters.entry(key.to_string()).or_insert_with(|| Counter {
            count: 0,
            reset_at: now + self.window_ms,
        });

        // Reset the window if it has expired.
        if now >= counter.reset_at {
            counter.count = 0;
            counter.reset_at = now + self.window_ms;
        }

        counter.count += 1;

        let allowed = counter.count <= self.max;
        let remaining = if allowed {
            self.max - counter.count
        } else {
            0
        };

        RateLimitResult {
            allowed,
            remaining,
            reset_at: counter.reset_at,
        }
    }

    /// Clear the counter for a given key.
    pub async fn reset(&self, key: &str) {
        let mut counters = self.counters.write().await;
        counters.remove(key);
    }

    /// Build a rate-limit key from optional IP and user id based on the
    /// configured [`KeyStrategy`].
    pub fn resolve_key(&self, ip: Option<&str>, user_id: Option<&str>) -> String {
        match self.key_strategy {
            KeyStrategy::Ip => ip.unwrap_or("unknown").to_string(),
            KeyStrategy::User => user_id.unwrap_or("anonymous").to_string(),
            KeyStrategy::IpAndUser => {
                let ip_part = ip.unwrap_or("unknown");
                let user_part = user_id.unwrap_or("anonymous");
                format!("{}:{}", ip_part, user_part)
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Window parsing
// ---------------------------------------------------------------------------

/// Parse a human-readable duration string into milliseconds.
///
/// Supported formats: `Ns` (seconds), `Nm` (minutes), `Nh` (hours), `Nd` (days).
fn parse_window(window: &str) -> Result<u64, AuthError> {
    let window = window.trim();
    if window.is_empty() {
        return Err(AuthError::config("Empty window string"));
    }

    let (num_str, suffix) = window.split_at(window.len() - 1);
    let value: u64 = num_str
        .parse()
        .map_err(|_| AuthError::config(format!("Invalid window number: {}", num_str)))?;

    let multiplier = match suffix {
        "s" => 1_000,
        "m" => 60_000,
        "h" => 3_600_000,
        "d" => 86_400_000,
        _ => {
            return Err(AuthError::config(format!(
                "Unknown window suffix '{}'. Expected s, m, h, or d",
                suffix
            )))
        }
    };

    Ok(value * multiplier)
}

/// Current time in milliseconds since the Unix epoch.
fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("system clock before Unix epoch")
        .as_millis() as u64
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_window_seconds() {
        assert_eq!(parse_window("60s").unwrap(), 60_000);
    }

    #[test]
    fn parse_window_minutes() {
        assert_eq!(parse_window("15m").unwrap(), 900_000);
    }

    #[test]
    fn parse_window_hours() {
        assert_eq!(parse_window("1h").unwrap(), 3_600_000);
    }

    #[test]
    fn parse_window_days() {
        assert_eq!(parse_window("1d").unwrap(), 86_400_000);
    }

    #[test]
    fn parse_window_invalid_suffix() {
        assert!(parse_window("10x").is_err());
    }

    #[test]
    fn parse_window_invalid_number() {
        assert!(parse_window("abcm").is_err());
    }

    #[test]
    fn resolve_key_ip() {
        let rl = RateLimiter::new(RateLimiterOptions {
            window: "1m".to_string(),
            max: 10,
            key_strategy: KeyStrategy::Ip,
        })
        .unwrap();
        assert_eq!(rl.resolve_key(Some("1.2.3.4"), Some("alice")), "1.2.3.4");
        assert_eq!(rl.resolve_key(None, Some("alice")), "unknown");
    }

    #[test]
    fn resolve_key_user() {
        let rl = RateLimiter::new(RateLimiterOptions {
            window: "1m".to_string(),
            max: 10,
            key_strategy: KeyStrategy::User,
        })
        .unwrap();
        assert_eq!(rl.resolve_key(Some("1.2.3.4"), Some("alice")), "alice");
        assert_eq!(rl.resolve_key(Some("1.2.3.4"), None), "anonymous");
    }

    #[test]
    fn resolve_key_ip_and_user() {
        let rl = RateLimiter::new(RateLimiterOptions {
            window: "1m".to_string(),
            max: 10,
            key_strategy: KeyStrategy::IpAndUser,
        })
        .unwrap();
        assert_eq!(
            rl.resolve_key(Some("1.2.3.4"), Some("alice")),
            "1.2.3.4:alice"
        );
    }

    #[tokio::test]
    async fn check_allows_up_to_max() {
        let rl = RateLimiter::new(RateLimiterOptions {
            window: "1m".to_string(),
            max: 3,
            key_strategy: KeyStrategy::Ip,
        })
        .unwrap();

        let r1 = rl.check("key").await;
        assert!(r1.allowed);
        assert_eq!(r1.remaining, 2);

        let r2 = rl.check("key").await;
        assert!(r2.allowed);
        assert_eq!(r2.remaining, 1);

        let r3 = rl.check("key").await;
        assert!(r3.allowed);
        assert_eq!(r3.remaining, 0);

        let r4 = rl.check("key").await;
        assert!(!r4.allowed);
        assert_eq!(r4.remaining, 0);
    }

    #[tokio::test]
    async fn reset_clears_counter() {
        let rl = RateLimiter::new(RateLimiterOptions {
            window: "1m".to_string(),
            max: 1,
            key_strategy: KeyStrategy::Ip,
        })
        .unwrap();

        let r1 = rl.check("key").await;
        assert!(r1.allowed);

        let r2 = rl.check("key").await;
        assert!(!r2.allowed);

        rl.reset("key").await;

        let r3 = rl.check("key").await;
        assert!(r3.allowed);
    }
}
