#[cfg(test)]
mod auth_tests {
    use crate::auth::{hash_api_key, verify_jwt, JwtSecret, Claims};
    use chrono::{Duration, Utc};
    use jsonwebtoken::{encode, EncodingKey, Header};
    
    #[test]
    fn test_jwt_token_validation_valid() {
        let secret = "test-secret-key-for-jwt-validation-testing-min-32-chars";
        let claims = Claims {
            sub: "user123".to_string(),
            username: "testuser".to_string(),
            role: "admin".to_string(),
            exp: (Utc::now() + Duration::hours(1)).timestamp() as usize,
            epoch: 0,
            impersonator: None,
        };
        
        let token = encode(
            &Header::default(),
            &claims,
            &EncodingKey::from_secret(secret.as_bytes())
        ).unwrap();
        
        let result = verify_jwt(&token, secret);
        assert!(result.is_ok(), "Valid JWT should be accepted");
        
        let decoded_claims = result.unwrap();
        assert_eq!(decoded_claims.sub, "user123");
        assert_eq!(decoded_claims.username, "testuser");
        assert_eq!(decoded_claims.role, "admin");
    }
    
    #[test]
    fn test_jwt_token_validation_expired() {
        let secret = "test-secret-key-for-jwt-validation-testing-min-32-chars";
        let claims = Claims {
            sub: "user123".to_string(),
            username: "testuser".to_string(),
            role: "admin".to_string(),
            exp: (Utc::now() - Duration::hours(1)).timestamp() as usize, // Expired
            epoch: 0,
            impersonator: None,
        };
        
        let token = encode(
            &Header::default(),
            &claims,
            &EncodingKey::from_secret(secret.as_bytes())
        ).unwrap();
        
        let result = verify_jwt(&token, secret);
        assert!(result.is_err(), "Expired JWT should be rejected");
    }
    
    #[test]
    fn test_jwt_token_validation_invalid_signature() {
        let correct_secret = "correct-secret-min-32-chars-long";
        let wrong_secret = "wrong-secret-also-min-32-chars";
        
        let claims = Claims {
            sub: "user123".to_string(),
            username: "testuser".to_string(),
            role: "admin".to_string(),
            exp: (Utc::now() + Duration::hours(1)).timestamp() as usize,
            epoch: 0,
            impersonator: None,
        };
        
        // Sign with correct secret
        let token = encode(
            &Header::default(),
            &claims,
            &EncodingKey::from_secret(correct_secret.as_bytes())
        ).unwrap();
        
        // Verify with wrong secret
        let result = verify_jwt(&token, wrong_secret);
        assert!(result.is_err(), "JWT with wrong signature should be rejected");
    }
    
    #[test]
    fn test_jwt_token_validation_malformed() {
        let secret = "test-secret-min-32-chars-long";
        
        let malformed_tokens = vec![
            "not.a.jwt",
            "malformed",
            "",
            "too.many.parts.here.invalid",
        ];
        
        for token in malformed_tokens {
            let result = verify_jwt(token, secret);
            assert!(result.is_err(), "Malformed JWT '{}' should be rejected", token);
        }
    }
    
    #[test]
    fn test_api_key_hashing_consistency() {
        let api_key = "test-api-key-123456";
        
        let hash1 = hash_api_key(api_key);
        let hash2 = hash_api_key(api_key);
        
        assert_eq!(hash1, hash2, "Same API key should produce same hash");
        assert_ne!(hash1, api_key, "Hash should be different from original key");
        assert!(!hash1.is_empty(), "Hash should not be empty");
        
        // Should be hex-encoded SHA256 (64 characters)
        assert_eq!(hash1.len(), 64, "SHA256 hash should be 64 hex characters");
        assert!(hash1.chars().all(|c| c.is_ascii_hexdigit()), "Hash should be valid hex");
    }
    
    #[test]
    fn test_api_key_hashing_different_keys() {
        let key1 = "test-api-key-1";
        let key2 = "test-api-key-2";
        
        let hash1 = hash_api_key(key1);
        let hash2 = hash_api_key(key2);
        
        assert_ne!(hash1, hash2, "Different API keys should produce different hashes");
    }
    
    #[test]
    fn test_jwt_secret_comes_from_the_environment_or_fails() {
        std::env::set_var("JWT_SECRET", "test-jwt-secret-from-env-min-32-chars");
        let loaded = JwtSecret::from_env();
        std::env::remove_var("JWT_SECRET");
        let missing = JwtSecret::from_env();

        assert_eq!(loaded.expect("JWT secret should load from environment").0, "test-jwt-secret-from-env-min-32-chars");
        assert!(missing.is_err(), "Should fail when JWT_SECRET not set");
    }
}