use axum::{
    extract::{Path, State},
    Extension, Json,
};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;
use uuid::Uuid;

use crate::api::AppState;
use crate::audit;
use crate::auth::{AdminUser, User};
use crate::enrollment;
use crate::error::AppError;

const SECONDS_PER_DAY: i64 = 24 * 60 * 60;
const MAX_LIFETIME_DAYS: i64 = 365;
const MAX_LABEL_LENGTH: usize = 64;

#[derive(Deserialize, ToSchema)]
pub struct CreateEnrollmentTokenRequest {
    pub label: String,
    pub expires_in_days: i64,
    pub max_uses: Option<i64>,
}

#[derive(Serialize, ToSchema)]
pub struct EnrollmentTokenCreated {
    pub id: String,
    pub token: String,
    pub label: String,
    pub expires_at: i64,
    pub max_uses: Option<i64>,
    pub linux_command: String,
    pub windows_command: String,
}

#[derive(Serialize, sqlx::FromRow, ToSchema)]
pub struct EnrollmentToken {
    pub id: String,
    pub label: String,
    pub created_at: i64,
    pub created_by: String,
    pub expires_at: i64,
    pub max_uses: Option<i64>,
    pub use_count: i64,
    pub last_used_at: Option<i64>,
    pub revoked_at: Option<i64>,
    pub revoked_by: Option<String>,
}

#[derive(Serialize, ToSchema)]
pub struct EnrollmentTokensResponse {
    pub tokens: Vec<EnrollmentToken>,
}

fn label_is_valid(label: &str) -> bool {
    let mut characters = label.chars();
    let starts_alphanumeric = characters.next().is_some_and(|first| first.is_ascii_alphanumeric());

    starts_alphanumeric
        && label.len() <= MAX_LABEL_LENGTH
        && characters.all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-'))
}

#[utoipa::path(
    post,
    path = "/api/admin/enrollment-tokens",
    tag = "admin",
    request_body = CreateEnrollmentTokenRequest,
    responses(
        (status = 200, description = "Fleet enrollment token created, the token is shown once", body = EnrollmentTokenCreated),
        (status = 400, description = "Invalid label, lifetime or use cap"),
        (status = 403, description = "Admin role required")
    ),
    security(("bearer_auth" = []))
)]
pub async fn create_enrollment_token(
    State(state): State<AppState>,
    AdminUser(user): AdminUser,
    Json(req): Json<CreateEnrollmentTokenRequest>,
) -> Result<Json<EnrollmentTokenCreated>, AppError> {
    if !label_is_valid(&req.label) {
        return Err(AppError::BadRequest(
            "label must start with a letter or digit and hold at most 64 letters, digits, dots, dashes or underscores".to_string(),
        ));
    }
    if !(1..=MAX_LIFETIME_DAYS).contains(&req.expires_in_days) {
        return Err(AppError::BadRequest(format!("expires_in_days must be between 1 and {}", MAX_LIFETIME_DAYS)));
    }
    if req.max_uses.is_some_and(|max_uses| max_uses < 1) {
        return Err(AppError::BadRequest("max_uses must be at least 1".to_string()));
    }

    let server_url = std::env::var("ZEDR_SERVER_URL")
        .map_err(|_| AppError::Config("ZEDR_SERVER_URL environment variable must be set".to_string()))?;

    let id = Uuid::new_v4().to_string();
    let token = enrollment::generate_fleet_token();
    let now = chrono::Utc::now().timestamp();
    let expires_at = now + req.expires_in_days * SECONDS_PER_DAY;

    sqlx::query(
        "INSERT INTO enrollment_tokens (id, token_hash, label, created_at, created_by, expires_at, max_uses)
         VALUES (?, ?, ?, ?, ?, ?, ?)",
    )
    .bind(&id)
    .bind(enrollment::hash(&token))
    .bind(&req.label)
    .bind(now)
    .bind(&user.username)
    .bind(expires_at)
    .bind(req.max_uses)
    .execute(&state.pool)
    .await?;

    audit::record_by(
        &state.pool,
        &user,
        "enrollment_token.create",
        Some(&id),
        serde_json::json!({ "label": req.label, "expires_at": expires_at, "max_uses": req.max_uses }),
    )
    .await?;

    Ok(Json(EnrollmentTokenCreated {
        linux_command: format!(
            "curl -fsSL -H 'X-Zedr-Enrollment-Key: {}' {}/install.sh | sudo sh",
            token, server_url
        ),
        windows_command: format!("iwr -useb {}/install.ps1?key={} | iex", server_url, token),
        id,
        token,
        label: req.label,
        expires_at,
        max_uses: req.max_uses,
    }))
}

#[utoipa::path(
    get,
    path = "/api/admin/enrollment-tokens",
    tag = "admin",
    responses(
        (status = 200, description = "Fleet enrollment tokens, newest first, without the secret", body = EnrollmentTokensResponse)
    ),
    security(("bearer_auth" = []))
)]
pub async fn list_enrollment_tokens(
    State(state): State<AppState>,
    Extension(_user): Extension<User>,
) -> Result<Json<EnrollmentTokensResponse>, AppError> {
    let tokens = sqlx::query_as::<_, EnrollmentToken>(
        "SELECT id, label, created_at, created_by, expires_at, max_uses, use_count, last_used_at, revoked_at, revoked_by
         FROM enrollment_tokens
         ORDER BY created_at DESC, id",
    )
    .fetch_all(&state.pool)
    .await?;

    Ok(Json(EnrollmentTokensResponse { tokens }))
}

#[utoipa::path(
    delete,
    path = "/api/admin/enrollment-tokens/{id}",
    tag = "admin",
    params(("id" = String, Path, description = "Enrollment token id")),
    responses(
        (status = 200, description = "Token revoked, agents it already enrolled keep working", body = EnrollmentToken),
        (status = 403, description = "Admin role required"),
        (status = 404, description = "Unknown token")
    ),
    security(("bearer_auth" = []))
)]
pub async fn revoke_enrollment_token(
    State(state): State<AppState>,
    AdminUser(user): AdminUser,
    Path(id): Path<String>,
) -> Result<Json<EnrollmentToken>, AppError> {
    let newly_revoked = sqlx::query("UPDATE enrollment_tokens SET revoked_at = ?, revoked_by = ? WHERE id = ? AND revoked_at IS NULL")
        .bind(chrono::Utc::now().timestamp())
        .bind(&user.username)
        .bind(&id)
        .execute(&state.pool)
        .await?
        .rows_affected()
        > 0;

    let token = sqlx::query_as::<_, EnrollmentToken>(
        "SELECT id, label, created_at, created_by, expires_at, max_uses, use_count, last_used_at, revoked_at, revoked_by
         FROM enrollment_tokens WHERE id = ?",
    )
    .bind(&id)
    .fetch_optional(&state.pool)
    .await?
    .ok_or(AppError::NotFound)?;

    if newly_revoked {
        audit::record_by(
            &state.pool,
            &user,
            "enrollment_token.revoke",
            Some(&id),
            serde_json::json!({ "label": token.label, "use_count": token.use_count }),
        )
        .await?;
    }

    Ok(Json(token))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_labels_are_short_plain_identifiers() {
        for label in ["prod-web", "k8s.nodes_eu-1", "a", "0"] {
            assert!(label_is_valid(label), "{} is a valid label", label);
        }
        for label in ["", "-prod", "prod web", "prod/web", "prod\nweb", "prod$(id)", &"a".repeat(65)] {
            assert!(!label_is_valid(label), "{:?} is not a valid label", label);
        }
    }
}
