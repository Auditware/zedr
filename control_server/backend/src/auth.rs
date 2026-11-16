use axum::{async_trait, extract::FromRequestParts, http::request::Parts};
use jsonwebtoken::{decode, encode, DecodingKey, EncodingKey, Header, Validation};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use sqlx::SqlitePool;

use crate::error::AppError;

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Claims {
    pub sub: String,
    pub username: String,
    pub role: String,
    pub exp: usize,
    #[serde(default)]
    pub epoch: i64,
    #[serde(default)]
    pub impersonator: Option<Impersonator>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Impersonator {
    pub id: String,
    pub epoch: i64,
}

#[derive(Debug, Clone)]
pub struct User {
    pub id: String,
    pub username: String,
    pub role: String,
    pub impersonator: Option<Actor>,
}

#[derive(Debug, Clone)]
pub struct Actor {
    pub id: String,
    pub username: String,
}

pub const ROLE_ADMIN: &str = "admin";
pub const ROLE_USER: &str = "user";

const MFA_CHALLENGE_TTL_MINUTES: i64 = 5;
const SESSION_HOURS: i64 = 24;
pub const IMPERSONATION_MINUTES: i64 = 30;
pub const SESSION_RECHECK_SECONDS: u64 = 30;

pub struct AdminUser(pub User);

#[async_trait]
impl<S> FromRequestParts<S> for AdminUser
where
    S: Send + Sync,
{
    type Rejection = AppError;

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        let user = parts.extensions.get::<User>().cloned().ok_or(AppError::Unauthorized)?;
        if user.role != ROLE_ADMIN {
            return Err(AppError::Forbidden);
        }
        Ok(AdminUser(user))
    }
}

#[derive(Debug, Serialize, Deserialize)]
struct MfaChallengeClaims {
    sub: String,
    exp: usize,
}

fn mfa_challenge_key(secret: &str) -> String {
    format!("{}:mfa-challenge", secret)
}

pub fn create_mfa_challenge(user_id: &str, secret: &str) -> Result<String, AppError> {
    let expiration = chrono::Utc::now()
        .checked_add_signed(chrono::Duration::minutes(MFA_CHALLENGE_TTL_MINUTES))
        .ok_or_else(|| AppError::InternalError("Invalid challenge expiry".to_string()))?
        .timestamp() as usize;

    encode(
        &Header::default(),
        &MfaChallengeClaims { sub: user_id.to_string(), exp: expiration },
        &EncodingKey::from_secret(mfa_challenge_key(secret).as_bytes()),
    )
    .map_err(|_| AppError::Unauthorized)
}

pub fn verify_mfa_challenge(token: &str, secret: &str) -> Result<String, AppError> {
    decode::<MfaChallengeClaims>(
        token,
        &DecodingKey::from_secret(mfa_challenge_key(secret).as_bytes()),
        &Validation::default(),
    )
    .map(|data| data.claims.sub)
    .map_err(|_| AppError::Unauthorized)
}

pub fn password_policy_violation(password: &str) -> Option<&'static str> {
    if password.chars().count() < 12 {
        return Some("Password must be at least 12 characters");
    }

    let has_upper = password.chars().any(|c| c.is_ascii_uppercase());
    let has_lower = password.chars().any(|c| c.is_ascii_lowercase());
    let has_digit = password.chars().any(|c| c.is_ascii_digit());
    let has_symbol = password.chars().any(|c| !c.is_ascii_alphanumeric() && !c.is_whitespace());

    if !(has_upper && has_lower && has_digit && has_symbol) {
        return Some("Password needs an uppercase letter, a lowercase letter, a number and a symbol");
    }

    None
}

pub struct JwtSecret(pub String);

impl JwtSecret {
    pub fn from_env() -> Result<Self, String> {
        let secret = std::env::var("JWT_SECRET")
            .map_err(|_| "JWT_SECRET environment variable must be set for production")?;
        Ok(Self(secret))
    }
}

fn sign_claims(claims: &Claims, secret: &str) -> Result<String, AppError> {
    encode(&Header::default(), claims, &EncodingKey::from_secret(secret.as_bytes())).map_err(|_| AppError::Unauthorized)
}

fn expiry_after(duration: chrono::Duration) -> Result<i64, AppError> {
    chrono::Utc::now()
        .checked_add_signed(duration)
        .map(|moment| moment.timestamp())
        .ok_or_else(|| AppError::InternalError("Invalid session expiry".to_string()))
}

pub fn create_jwt(user_id: &str, username: &str, role: &str, epoch: i64, secret: &str) -> Result<String, AppError> {
    let claims = Claims {
        sub: user_id.to_string(),
        username: username.to_string(),
        role: role.to_string(),
        exp: expiry_after(chrono::Duration::hours(SESSION_HOURS))? as usize,
        epoch,
        impersonator: None,
    };
    sign_claims(&claims, secret)
}

pub fn create_impersonation(
    target_id: &str,
    username: &str,
    role: &str,
    target_epoch: i64,
    admin: Impersonator,
    secret: &str,
) -> Result<(String, i64), AppError> {
    let expires_at = expiry_after(chrono::Duration::minutes(IMPERSONATION_MINUTES))?;
    let claims = Claims {
        sub: target_id.to_string(),
        username: username.to_string(),
        role: role.to_string(),
        exp: expires_at as usize,
        epoch: target_epoch,
        impersonator: Some(admin),
    };
    Ok((sign_claims(&claims, secret)?, expires_at))
}

type AccountState = (String, String, i64, Option<i64>);

async fn account_state(pool: &SqlitePool, id: &str) -> Result<AccountState, AppError> {
    sqlx::query_as("SELECT username, role, session_epoch, disabled_at FROM users WHERE id = ?")
        .bind(id)
        .fetch_optional(pool)
        .await?
        .ok_or(AppError::Unauthorized)
}

pub async fn authenticate(pool: &SqlitePool, token: &str, secret: &str) -> Result<User, AppError> {
    let claims = verify_jwt(token, secret)?;

    let (username, role, epoch, disabled_at) = account_state(pool, &claims.sub).await?;
    if disabled_at.is_some() || claims.epoch != epoch {
        return Err(AppError::Unauthorized);
    }

    let impersonator = match claims.impersonator {
        Some(admin) => {
            let (admin_name, admin_role, admin_epoch, admin_disabled_at) = account_state(pool, &admin.id).await?;
            if admin_disabled_at.is_some() || admin_role != ROLE_ADMIN || admin.epoch != admin_epoch {
                return Err(AppError::Unauthorized);
            }
            Some(Actor { id: admin.id, username: admin_name })
        }
        None => None,
    };

    Ok(User { id: claims.sub, username, role, impersonator })
}

pub async fn session_ended(pool: SqlitePool, token: String, secret: String) {
    loop {
        tokio::time::sleep(std::time::Duration::from_secs(SESSION_RECHECK_SECONDS)).await;
        if authenticate(&pool, &token, &secret).await.is_err() {
            return;
        }
    }
}

pub fn verify_jwt(token: &str, secret: &str) -> Result<Claims, AppError> {
    decode::<Claims>(
        token,
        &DecodingKey::from_secret(secret.as_bytes()),
        &Validation::default(),
    )
    .map(|data| data.claims)
    .map_err(|_| AppError::Unauthorized)
}

pub fn hash_password(password: &str) -> Result<String, AppError> {
    bcrypt::hash(password, bcrypt::DEFAULT_COST).map_err(|e| AppError::InternalError(format!("Failed to hash password: {}", e)))
}

pub fn verify_password(password: &str, hash: &str) -> Result<bool, AppError> {
    bcrypt::verify(password, hash).map_err(|e| AppError::InternalError(format!("Failed to verify password: {}", e)))
}

pub fn hash_api_key(key: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(key.as_bytes());
    format!("{:x}", hasher.finalize())
}

pub async fn seed_admin_user(pool: &SqlitePool) -> Result<(), AppError> {
    let admin_exists: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM users WHERE username = 'admin'")
        .fetch_one(pool)
        .await?;

    if admin_exists.0 > 0 {
        return Ok(());
    }

    let admin_password = std::env::var("ADMIN_PASSWORD")
        .map_err(|_| AppError::Config("ADMIN_PASSWORD environment variable must be set".to_string()))?;
    
    let password_hash = hash_password(&admin_password)?;
    let id = uuid::Uuid::new_v4().to_string();
    let now = chrono::Utc::now().timestamp();

    sqlx::query(
        "INSERT INTO users (id, username, password_hash, role, created_at) 
         VALUES (?, ?, ?, ?, ?)"
    )
    .bind(&id)
    .bind("admin")
    .bind(&password_hash)
    .bind("admin")
    .bind(now)
    .execute(pool)
    .await?;

    tracing::info!("Admin user seeded successfully");
    Ok(())
}
