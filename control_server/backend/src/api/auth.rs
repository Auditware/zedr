use axum::{extract::State, Extension, Json};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

use crate::api::AppState;
use crate::audit;
use crate::auth::{create_jwt, create_mfa_challenge, verify_mfa_challenge, verify_password, JwtSecret, User};
use crate::error::AppError;
use crate::mfa;

const MFA_ISSUER: &str = "zedr";
const MAX_LOGGED_USERNAME_CHARS: usize = 64;

#[derive(Deserialize, ToSchema)]
pub struct LoginRequest {
    pub username: String,
    pub password: String,
}

#[derive(Serialize, ToSchema)]
pub struct LoginResponse {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub token: Option<String>,
    pub username: String,
    pub role: String,
    pub mfa_required: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mfa_token: Option<String>,
}

#[derive(Deserialize, ToSchema)]
pub struct MfaLoginRequest {
    pub mfa_token: String,
    pub code: String,
}

#[derive(Deserialize, ToSchema)]
pub struct MfaCodeRequest {
    pub code: String,
}

#[derive(Serialize, ToSchema)]
pub struct MfaStatusResponse {
    pub enabled: bool,
}

#[derive(Serialize, ToSchema)]
pub struct MfaSetupResponse {
    pub secret: String,
    pub provisioning_uri: String,
}

#[derive(Serialize, ToSchema)]
pub struct MfaEnableResponse {
    pub recovery_codes: Vec<String>,
}

fn jwt_secret() -> Result<String, AppError> {
    JwtSecret::from_env().map(|secret| secret.0).map_err(AppError::Config)
}

fn now_secs() -> u64 {
    chrono::Utc::now().timestamp().max(0) as u64
}

fn decode_secret(secret_hex: &str) -> Result<Vec<u8>, AppError> {
    hex::decode(secret_hex).map_err(|_| AppError::InternalError("Stored MFA secret is corrupt".to_string()))
}

#[utoipa::path(
    post,
    path = "/api/auth/login",
    tag = "auth",
    request_body = LoginRequest,
    responses(
        (status = 200, description = "Login successful, or a second factor is required", body = LoginResponse),
        (status = 401, description = "Invalid credentials"),
        (status = 500, description = "Internal server error")
    )
)]
pub async fn login(
    State(state): State<AppState>,
    Json(req): Json<LoginRequest>,
) -> Result<Json<LoginResponse>, AppError> {
    let user: Option<(String, String, String, String, bool, i64)> = sqlx::query_as(
        "SELECT id, username, password_hash, role, mfa_enabled, session_epoch FROM users WHERE username = ? AND disabled_at IS NULL"
    )
    .bind(&req.username)
    .fetch_optional(&state.pool)
    .await?;

    let authenticated = match user {
        Some((id, username, password_hash, role, mfa_enabled, epoch)) if verify_password(&req.password, &password_hash)? => {
            Some((User { id, username, role, impersonator: None }, mfa_enabled, epoch))
        }
        _ => None,
    };

    let Some((user, mfa_enabled, epoch)) = authenticated else {
        let attempted: String = req.username.chars().take(MAX_LOGGED_USERNAME_CHARS).collect();
        audit::record(&state.pool, None, &attempted, "login.failed", None, serde_json::json!({})).await?;
        return Err(AppError::Unauthorized);
    };

    let secret = jwt_secret()?;

    if mfa_enabled {
        return Ok(Json(LoginResponse {
            token: None,
            username: user.username,
            role: user.role,
            mfa_required: true,
            mfa_token: Some(create_mfa_challenge(&user.id, &secret)?),
        }));
    }

    audit::record_by(&state.pool, &user, "login", None, serde_json::json!({ "mfa": false })).await?;
    record_login(&state, &user.id).await?;

    Ok(Json(LoginResponse {
        token: Some(create_jwt(&user.id, &user.username, &user.role, epoch, &secret)?),
        username: user.username,
        role: user.role,
        mfa_required: false,
        mfa_token: None,
    }))
}

async fn record_login(state: &AppState, user_id: &str) -> Result<(), AppError> {
    sqlx::query("UPDATE users SET last_login_at = ? WHERE id = ?")
        .bind(chrono::Utc::now().timestamp())
        .bind(user_id)
        .execute(&state.pool)
        .await?;
    Ok(())
}

#[utoipa::path(
    post,
    path = "/api/auth/login/mfa",
    tag = "auth",
    request_body = MfaLoginRequest,
    responses(
        (status = 200, description = "Second factor accepted", body = LoginResponse),
        (status = 401, description = "Invalid or expired challenge, or wrong code")
    )
)]
pub async fn login_mfa(
    State(state): State<AppState>,
    Json(req): Json<MfaLoginRequest>,
) -> Result<Json<LoginResponse>, AppError> {
    let secret = jwt_secret()?;
    let user_id = verify_mfa_challenge(&req.mfa_token, &secret)?;

    let row: Option<(String, String, Option<String>, bool, i64, i64)> = sqlx::query_as(
        "SELECT username, role, mfa_secret, mfa_enabled, mfa_last_step, session_epoch FROM users WHERE id = ? AND disabled_at IS NULL"
    )
    .bind(&user_id)
    .fetch_optional(&state.pool)
    .await?;

    let (username, role, mfa_secret, mfa_enabled, last_step, epoch) = row.ok_or(AppError::Unauthorized)?;
    let user = User { id: user_id, username, role, impersonator: None };

    let (Some(mfa_secret), true) = (mfa_secret, mfa_enabled) else {
        return Err(AppError::Unauthorized);
    };

    let method = if consume_totp(&state, &user.id, &mfa_secret, &req.code, last_step).await? {
        "totp"
    } else if consume_recovery_code(&state, &user.id, &req.code).await? {
        "recovery_code"
    } else {
        audit::record_by(&state.pool, &user, "login.mfa_failed", None, serde_json::json!({})).await?;
        return Err(AppError::Unauthorized);
    };

    audit::record_by(&state.pool, &user, "login", None, serde_json::json!({ "mfa": method })).await?;
    record_login(&state, &user.id).await?;

    Ok(Json(LoginResponse {
        token: Some(create_jwt(&user.id, &user.username, &user.role, epoch, &secret)?),
        username: user.username,
        role: user.role,
        mfa_required: false,
        mfa_token: None,
    }))
}

async fn consume_totp(
    state: &AppState,
    user_id: &str,
    secret_hex: &str,
    code: &str,
    last_step: i64,
) -> Result<bool, AppError> {
    let secret = decode_secret(secret_hex)?;
    let Some(step) = mfa::matching_step(&secret, code, now_secs(), last_step.max(0) as u64) else {
        return Ok(false);
    };

    let advanced = sqlx::query("UPDATE users SET mfa_last_step = ? WHERE id = ? AND mfa_last_step < ?")
        .bind(step as i64)
        .bind(user_id)
        .bind(step as i64)
        .execute(&state.pool)
        .await?
        .rows_affected()
        > 0;

    Ok(advanced)
}

async fn consume_recovery_code(state: &AppState, user_id: &str, code: &str) -> Result<bool, AppError> {
    let consumed = sqlx::query(
        "UPDATE mfa_recovery_codes SET used_at = ? WHERE user_id = ? AND code_hash = ? AND used_at IS NULL"
    )
    .bind(chrono::Utc::now().timestamp())
    .bind(user_id)
    .bind(mfa::recovery_code_hash(code))
    .execute(&state.pool)
    .await?
    .rows_affected()
        > 0;

    Ok(consumed)
}

#[utoipa::path(
    get,
    path = "/api/auth/mfa",
    tag = "auth",
    responses((status = 200, description = "Whether the caller has a second factor enabled", body = MfaStatusResponse))
)]
pub async fn mfa_status(
    State(state): State<AppState>,
    Extension(user): Extension<User>,
) -> Result<Json<MfaStatusResponse>, AppError> {
    let enabled: bool = sqlx::query_scalar("SELECT mfa_enabled FROM users WHERE id = ?")
        .bind(&user.id)
        .fetch_optional(&state.pool)
        .await?
        .ok_or(AppError::Unauthorized)?;

    Ok(Json(MfaStatusResponse { enabled }))
}

#[utoipa::path(
    post,
    path = "/api/auth/mfa/setup",
    tag = "auth",
    responses(
        (status = 200, description = "A pending secret to add to an authenticator app", body = MfaSetupResponse),
        (status = 409, description = "A second factor is already enabled")
    )
)]
pub async fn mfa_setup(
    State(state): State<AppState>,
    Extension(user): Extension<User>,
) -> Result<Json<MfaSetupResponse>, AppError> {
    let secret = mfa::new_secret();

    let staged = sqlx::query("UPDATE users SET mfa_secret = ?, mfa_last_step = 0 WHERE id = ? AND mfa_enabled = 0")
        .bind(hex::encode(&secret))
        .bind(&user.id)
        .execute(&state.pool)
        .await?
        .rows_affected()
        > 0;

    if !staged {
        return Err(AppError::Conflict("A second factor is already enabled".to_string()));
    }

    Ok(Json(MfaSetupResponse {
        secret: mfa::base32_encode(&secret),
        provisioning_uri: mfa::provisioning_uri(MFA_ISSUER, &user.username, &secret),
    }))
}

#[utoipa::path(
    post,
    path = "/api/auth/mfa/enable",
    tag = "auth",
    request_body = MfaCodeRequest,
    responses(
        (status = 200, description = "Second factor enabled; recovery codes are shown once", body = MfaEnableResponse),
        (status = 400, description = "No pending setup, or wrong code")
    )
)]
pub async fn mfa_enable(
    State(state): State<AppState>,
    Extension(user): Extension<User>,
    Json(req): Json<MfaCodeRequest>,
) -> Result<Json<MfaEnableResponse>, AppError> {
    let row: Option<(Option<String>, bool, i64)> = sqlx::query_as(
        "SELECT mfa_secret, mfa_enabled, mfa_last_step FROM users WHERE id = ?"
    )
    .bind(&user.id)
    .fetch_optional(&state.pool)
    .await?;

    let (Some(secret_hex), false, last_step) = row.ok_or(AppError::Unauthorized)? else {
        return Err(AppError::BadRequest("Start setup before enabling a second factor".to_string()));
    };

    if !consume_totp(&state, &user.id, &secret_hex, &req.code, last_step).await? {
        return Err(AppError::BadRequest("Code does not match".to_string()));
    }

    let recovery_codes = mfa::new_recovery_codes();

    let mut tx = state.pool.begin().await?;
    sqlx::query("DELETE FROM mfa_recovery_codes WHERE user_id = ?")
        .bind(&user.id)
        .execute(&mut *tx)
        .await?;
    for code in &recovery_codes {
        sqlx::query("INSERT INTO mfa_recovery_codes (user_id, code_hash) VALUES (?, ?)")
            .bind(&user.id)
            .bind(mfa::recovery_code_hash(code))
            .execute(&mut *tx)
            .await?;
    }
    sqlx::query("UPDATE users SET mfa_enabled = 1 WHERE id = ?")
        .bind(&user.id)
        .execute(&mut *tx)
        .await?;
    tx.commit().await?;

    audit::record_by(&state.pool, &user, "mfa.enable", Some(&user.id), serde_json::json!({})).await?;

    Ok(Json(MfaEnableResponse { recovery_codes }))
}

#[utoipa::path(
    post,
    path = "/api/auth/mfa/disable",
    tag = "auth",
    request_body = MfaCodeRequest,
    responses(
        (status = 200, description = "Second factor disabled", body = MfaStatusResponse),
        (status = 400, description = "Wrong code, or no second factor enabled")
    )
)]
pub async fn mfa_disable(
    State(state): State<AppState>,
    Extension(user): Extension<User>,
    Json(req): Json<MfaCodeRequest>,
) -> Result<Json<MfaStatusResponse>, AppError> {
    let row: Option<(Option<String>, bool, i64)> = sqlx::query_as(
        "SELECT mfa_secret, mfa_enabled, mfa_last_step FROM users WHERE id = ?"
    )
    .bind(&user.id)
    .fetch_optional(&state.pool)
    .await?;

    let (Some(secret_hex), true, last_step) = row.ok_or(AppError::Unauthorized)? else {
        return Err(AppError::BadRequest("No second factor is enabled".to_string()));
    };

    let verified = consume_totp(&state, &user.id, &secret_hex, &req.code, last_step).await?
        || consume_recovery_code(&state, &user.id, &req.code).await?;
    if !verified {
        return Err(AppError::BadRequest("Code does not match".to_string()));
    }

    let mut tx = state.pool.begin().await?;
    sqlx::query("DELETE FROM mfa_recovery_codes WHERE user_id = ?")
        .bind(&user.id)
        .execute(&mut *tx)
        .await?;
    sqlx::query("UPDATE users SET mfa_enabled = 0, mfa_secret = NULL, mfa_last_step = 0 WHERE id = ?")
        .bind(&user.id)
        .execute(&mut *tx)
        .await?;
    tx.commit().await?;

    audit::record_by(&state.pool, &user, "mfa.disable", Some(&user.id), serde_json::json!({})).await?;

    Ok(Json(MfaStatusResponse { enabled: false }))
}
