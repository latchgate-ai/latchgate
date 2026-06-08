//! Credential generation helpers.

/// Generate a random API key: `key-{name}-{32 hex chars}`.
pub fn generate_api_key(name: &str) -> String {
    use rand::RngCore;
    let mut bytes = [0u8; 16];
    rand::rngs::OsRng.fill_bytes(&mut bytes);
    format!("key-{name}-{}", hex::encode(bytes))
}

/// Generate a random webhook HMAC secret: `whsec_{64 hex chars}` (256-bit).
pub fn generate_webhook_secret() -> String {
    use rand::RngCore;
    let mut bytes = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut bytes);
    format!("whsec_{}", hex::encode(bytes))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generate_api_key_has_correct_format() {
        let key = generate_api_key("test");
        assert!(key.starts_with("key-test-"), "got: {key}");
        // 16 bytes = 32 hex chars.
        let hex_part = key.strip_prefix("key-test-").unwrap();
        assert_eq!(hex_part.len(), 32);
        assert!(hex_part.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn generate_api_key_is_unique() {
        let a = generate_api_key("x");
        let b = generate_api_key("x");
        assert_ne!(a, b, "keys must be unique");
    }

    #[test]
    fn generate_webhook_secret_has_correct_format() {
        let secret = generate_webhook_secret();
        assert!(secret.starts_with("whsec_"), "got: {secret}");
        let hex_part = secret.strip_prefix("whsec_").unwrap();
        // 32 bytes = 64 hex chars.
        assert_eq!(hex_part.len(), 64);
        assert!(hex_part.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn generate_webhook_secret_is_unique() {
        let a = generate_webhook_secret();
        let b = generate_webhook_secret();
        assert_ne!(a, b, "secrets must be unique");
    }
}
