use axum::{
    extract::{Path, State},
    http::StatusCode,
    Json,
};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;
use uuid::Uuid;

use crate::api::AppState;
use crate::attempts::{self, Subject};
use crate::audit;
use crate::auth::{
    create_impersonation, hash_password, password_policy_violation, verify_password, AdminUser, Impersonator, JwtSecret, IMPERSONATION_MINUTES,
    ROLE_ADMIN, ROLE_USER,
};
use crate::error::{AppError, Result};

#[derive(Debug, Serialize, sqlx::FromRow, ToSchema)]
pub struct UserSummary {
    pub id: String,
    pub username: String,
    pub role: String,
    pub created_at: i64,
    pub mfa_enabled: bool,
    pub disabled_at: Option<i64>,
    pub last_login_at: Option<i64>,
}

const USER_COLUMNS: &str = "id, username, role, created_at, mfa_enabled, disabled_at, last_login_at";

async fn load_user(state: &AppState, id: &str) -> Result<UserSummary> {
    sqlx::query_as::<_, UserSummary>(&format!("SELECT {} FROM users WHERE id = ?", USER_COLUMNS))
        .bind(id)
        .fetch_optional(&state.pool)
        .await?
        .ok_or(AppError::NotFound)
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct UpdateUserRequest {
    pub role: Option<String>,
    pub disabled: Option<bool>,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct ResetPasswordRequest {
    pub password: String,
    pub current_password: Option<String>,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct CreateUserRequest {
    pub username: String,
    pub password: String,
    pub role: String,
}

#[utoipa::path(
    get,
    path = "/api/admin/users",
    tag = "admin",
    responses(
        (status = 200, description = "All console accounts", body = Vec<UserSummary>),
        (status = 403, description = "Admin role required")
    )
)]
pub async fn list_users(
    State(state): State<AppState>,
    AdminUser(_admin): AdminUser,
) -> Result<Json<Vec<UserSummary>>> {
    let users = sqlx::query_as::<_, UserSummary>(&format!("SELECT {} FROM users ORDER BY created_at ASC", USER_COLUMNS))
        .fetch_all(&state.pool)
        .await?;

    Ok(Json(users))
}

#[utoipa::path(
    post,
    path = "/api/admin/users",
    tag = "admin",
    request_body = CreateUserRequest,
    responses(
        (status = 201, description = "Account created", body = UserSummary),
        (status = 400, description = "Invalid username, role or password"),
        (status = 403, description = "Admin role required"),
        (status = 409, description = "Username already exists")
    )
)]
pub async fn create_user(
    State(state): State<AppState>,
    AdminUser(admin): AdminUser,
    Json(req): Json<CreateUserRequest>,
) -> Result<(StatusCode, Json<UserSummary>)> {
    let username = req.username.trim().to_string();
    if username.is_empty() || username.chars().count() > 64 {
        return Err(AppError::BadRequest("Username must be 1 to 64 characters".to_string()));
    }
    if req.role != ROLE_ADMIN && req.role != ROLE_USER {
        return Err(AppError::BadRequest("Role must be admin or user".to_string()));
    }
    if let Some(violation) = password_policy_violation(&req.password) {
        return Err(AppError::BadRequest(violation.to_string()));
    }

    let taken: bool = sqlx::query_scalar("SELECT COUNT(*) > 0 FROM users WHERE username = ?")
        .bind(&username)
        .fetch_one(&state.pool)
        .await?;
    if taken {
        return Err(AppError::Conflict("Username already exists".to_string()));
    }

    let user = UserSummary {
        id: Uuid::new_v4().to_string(),
        username,
        role: req.role,
        created_at: chrono::Utc::now().timestamp(),
        mfa_enabled: false,
        disabled_at: None,
        last_login_at: None,
    };

    sqlx::query("INSERT INTO users (id, username, password_hash, role, created_at) VALUES (?, ?, ?, ?, ?)")
        .bind(&user.id)
        .bind(&user.username)
        .bind(hash_password(&req.password)?)
        .bind(&user.role)
        .bind(user.created_at)
        .execute(&state.pool)
        .await?;

    audit::record_by(
        &state.pool,
        &admin,
        "user.create",
        Some(&user.id),
        serde_json::json!({ "username": user.username, "role": user.role }),
    )
    .await?;

    Ok((StatusCode::CREATED, Json(user)))
}

#[utoipa::path(
    delete,
    path = "/api/admin/users/{id}",
    tag = "admin",
    params(("id" = String, Path, description = "User ID")),
    responses(
        (status = 204, description = "Account deleted"),
        (status = 400, description = "Cannot delete yourself"),
        (status = 403, description = "Admin role required"),
        (status = 404, description = "User not found")
    )
)]
pub async fn delete_user(
    State(state): State<AppState>,
    AdminUser(admin): AdminUser,
    Path(id): Path<String>,
) -> Result<StatusCode> {
    if id == admin.id {
        return Err(AppError::BadRequest("You cannot delete your own account".to_string()));
    }

    let target: Option<(String, String)> = sqlx::query_as("SELECT username, role FROM users WHERE id = ?")
        .bind(&id)
        .fetch_optional(&state.pool)
        .await?;
    let (username, role) = target.ok_or(AppError::NotFound)?;

    let mut tx = state.pool.begin().await?;
    sqlx::query("DELETE FROM api_keys WHERE user_id = ?").bind(&id).execute(&mut *tx).await?;
    sqlx::query("DELETE FROM mfa_recovery_codes WHERE user_id = ?").bind(&id).execute(&mut *tx).await?;
    sqlx::query("DELETE FROM users WHERE id = ?").bind(&id).execute(&mut *tx).await?;
    tx.commit().await?;

    audit::record_by(
        &state.pool,
        &admin,
        "user.delete",
        Some(&id),
        serde_json::json!({ "username": username, "role": role }),
    )
    .await?;

    Ok(StatusCode::NO_CONTENT)
}

#[utoipa::path(
    patch,
    path = "/api/admin/users/{id}",
    tag = "admin",
    params(("id" = String, Path, description = "User ID")),
    request_body = UpdateUserRequest,
    responses(
        (status = 200, description = "Account after the change", body = UserSummary),
        (status = 400, description = "Invalid role, or the change targets your own account"),
        (status = 403, description = "Admin role required"),
        (status = 404, description = "User not found")
    )
)]
pub async fn update_user(
    State(state): State<AppState>,
    AdminUser(admin): AdminUser,
    Path(id): Path<String>,
    Json(req): Json<UpdateUserRequest>,
) -> Result<Json<UserSummary>> {
    if id == admin.id {
        return Err(AppError::BadRequest("You cannot change your own role or disable your own account".to_string()));
    }
    if let Some(role) = &req.role {
        if role != ROLE_ADMIN && role != ROLE_USER {
            return Err(AppError::BadRequest("Role must be admin or user".to_string()));
        }
    }

    let before = load_user(&state, &id).await?;

    if let Some(role) = req.role.filter(|role| *role != before.role) {
        sqlx::query("UPDATE users SET role = ? WHERE id = ?")
            .bind(&role)
            .bind(&id)
            .execute(&state.pool)
            .await?;
        audit::record_by(
            &state.pool,
            &admin,
            "user.role_change",
            Some(&id),
            serde_json::json!({ "username": before.username, "from": before.role, "to": role }),
        )
        .await?;
    }

    if let Some(disabled) = req.disabled.filter(|disabled| *disabled != before.disabled_at.is_some()) {
        let disabled_at = disabled.then(|| chrono::Utc::now().timestamp());
        sqlx::query("UPDATE users SET disabled_at = ? WHERE id = ?")
            .bind(disabled_at)
            .bind(&id)
            .execute(&state.pool)
            .await?;
        audit::record_by(
            &state.pool,
            &admin,
            if disabled { "user.disable" } else { "user.enable" },
            Some(&id),
            serde_json::json!({ "username": before.username }),
        )
        .await?;
    }

    Ok(Json(load_user(&state, &id).await?))
}

#[utoipa::path(
    post,
    path = "/api/admin/users/{id}/password",
    tag = "admin",
    params(("id" = String, Path, description = "User ID")),
    request_body = ResetPasswordRequest,
    responses(
        (status = 204, description = "Password replaced, every session of the account ended and its failed sign-ins forgotten"),
        (status = 400, description = "Password does not meet the policy, or your current password is missing"),
        (status = 401, description = "Current password is wrong"),
        (status = 403, description = "Admin role required"),
        (status = 404, description = "User not found"),
        (status = 429, description = "Too many wrong passwords for your account, Retry-After says how many seconds to wait")
    )
)]
pub async fn reset_password(
    State(state): State<AppState>,
    AdminUser(admin): AdminUser,
    Path(id): Path<String>,
    Json(req): Json<ResetPasswordRequest>,
) -> Result<StatusCode> {
    if let Some(violation) = password_policy_violation(&req.password) {
        return Err(AppError::BadRequest(violation.to_string()));
    }

    let target: Option<(String, String)> = sqlx::query_as("SELECT username, password_hash FROM users WHERE id = ?")
        .bind(&id)
        .fetch_optional(&state.pool)
        .await?;
    let (username, current_hash) = target.ok_or(AppError::NotFound)?;

    let account = Subject::account(&username);
    if id == admin.id {
        let current = req
            .current_password
            .ok_or_else(|| AppError::BadRequest("Your current password is required to change your own".to_string()))?;
        let attempt = attempts::begin(&state.pool, std::slice::from_ref(&account)).await?;
        if !verify_password(&current, &current_hash)? {
            for lock in attempt.failed() {
                audit::record_by(&state.pool, &admin, attempts::LOCKED, Some(&id), lock.detail()).await?;
            }
            return Err(AppError::Unauthorized);
        }
    }

    sqlx::query("UPDATE users SET password_hash = ?, session_epoch = session_epoch + 1 WHERE id = ?")
        .bind(hash_password(&req.password)?)
        .bind(&id)
        .execute(&state.pool)
        .await?;
    attempts::forget(&state.pool, &account).await?;

    audit::record_by(&state.pool, &admin, "user.password_reset", Some(&id), serde_json::json!({ "username": username })).await?;

    Ok(StatusCode::NO_CONTENT)
}

#[utoipa::path(
    post,
    path = "/api/admin/users/{id}/mfa/reset",
    tag = "admin",
    params(("id" = String, Path, description = "User ID")),
    responses(
        (status = 204, description = "Second factor and recovery codes removed"),
        (status = 400, description = "Your own second factor is removed with a code, not here"),
        (status = 403, description = "Admin role required"),
        (status = 404, description = "User not found")
    )
)]
pub async fn reset_mfa(
    State(state): State<AppState>,
    AdminUser(admin): AdminUser,
    Path(id): Path<String>,
) -> Result<StatusCode> {
    if id == admin.id {
        return Err(AppError::BadRequest("Turn off your own second factor with a code from it".to_string()));
    }
    let target = load_user(&state, &id).await?;

    let mut tx = state.pool.begin().await?;
    sqlx::query("UPDATE users SET mfa_enabled = 0, mfa_secret = NULL, mfa_last_step = 0 WHERE id = ?")
        .bind(&id)
        .execute(&mut *tx)
        .await?;
    sqlx::query("DELETE FROM mfa_recovery_codes WHERE user_id = ?").bind(&id).execute(&mut *tx).await?;
    tx.commit().await?;

    audit::record_by(&state.pool, &admin, "user.mfa_reset", Some(&id), serde_json::json!({ "username": target.username })).await?;

    Ok(StatusCode::NO_CONTENT)
}

#[utoipa::path(
    post,
    path = "/api/admin/users/{id}/sign-out",
    tag = "admin",
    params(("id" = String, Path, description = "User ID")),
    responses(
        (status = 204, description = "Every session of the account ended"),
        (status = 403, description = "Admin role required"),
        (status = 404, description = "User not found")
    )
)]
pub async fn sign_out(
    State(state): State<AppState>,
    AdminUser(admin): AdminUser,
    Path(id): Path<String>,
) -> Result<StatusCode> {
    let target = load_user(&state, &id).await?;

    sqlx::query("UPDATE users SET session_epoch = session_epoch + 1 WHERE id = ?")
        .bind(&id)
        .execute(&state.pool)
        .await?;

    audit::record_by(&state.pool, &admin, "user.sign_out", Some(&id), serde_json::json!({ "username": target.username })).await?;

    Ok(StatusCode::NO_CONTENT)
}

#[derive(Debug, Serialize, ToSchema)]
pub struct ImpersonationResponse {
    pub token: String,
    pub expires_at: i64,
    pub username: String,
    pub role: String,
}

#[utoipa::path(
    post,
    path = "/api/admin/users/{id}/impersonate",
    tag = "admin",
    params(("id" = String, Path, description = "User ID")),
    responses(
        (status = 200, description = "A short session as that account, with the rights of its role", body = ImpersonationResponse),
        (status = 400, description = "The account is your own, an admin or disabled"),
        (status = 403, description = "Admin role required"),
        (status = 404, description = "User not found")
    )
)]
pub async fn impersonate(
    State(state): State<AppState>,
    AdminUser(admin): AdminUser,
    Path(id): Path<String>,
) -> Result<Json<ImpersonationResponse>> {
    if id == admin.id {
        return Err(AppError::BadRequest("You cannot impersonate yourself".to_string()));
    }
    let target = load_user(&state, &id).await?;
    if target.role == ROLE_ADMIN {
        return Err(AppError::BadRequest("An admin sees what every other admin sees".to_string()));
    }
    if target.disabled_at.is_some() {
        return Err(AppError::BadRequest("A disabled account has no view to show".to_string()));
    }

    let epochs: Vec<(String, i64)> = sqlx::query_as("SELECT id, session_epoch FROM users WHERE id IN (?, ?)")
        .bind(&id)
        .bind(&admin.id)
        .fetch_all(&state.pool)
        .await?;
    let epoch_of = |account: &str| epochs.iter().find(|(id, _)| id == account).map(|(_, epoch)| *epoch).ok_or(AppError::NotFound);

    let secret = JwtSecret::from_env().map_err(AppError::Config)?;
    let (token, expires_at) = create_impersonation(
        &target.id,
        &target.username,
        &target.role,
        epoch_of(&id)?,
        Impersonator { id: admin.id.clone(), epoch: epoch_of(&admin.id)? },
        &secret.0,
    )?;

    audit::record_by(
        &state.pool,
        &admin,
        "user.impersonate",
        Some(&id),
        serde_json::json!({ "username": target.username, "minutes": IMPERSONATION_MINUTES }),
    )
    .await?;

    Ok(Json(ImpersonationResponse { token, expires_at, username: target.username, role: target.role }))
}
