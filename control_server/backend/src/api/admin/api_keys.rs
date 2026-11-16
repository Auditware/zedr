use axum::{extract::State, Extension, Json};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;
use uuid::Uuid;

use crate::api::AppState;
use crate::auth::{hash_api_key, User};
use crate::error::AppError;

#[derive(Deserialize, ToSchema)]
pub struct CreateApiKeyRequest {
    pub name: String,
}

#[derive(Serialize, ToSchema)]
pub struct ApiKeyResponse {
    pub id: String,
    pub name: String,
    pub api_key: String,
    pub expires_at: i64,
}

#[derive(Serialize, ToSchema)]
pub struct ApiKeyListItem {
    pub id: String,
    pub name: String,
    pub expires_at: i64,
    pub created_at: i64,
    pub last_used_at: Option<i64>,
}

#[utoipa::path(
    post,
    path = "/api/admin/api-keys",
    tag = "admin",
    request_body = CreateApiKeyRequest,
    responses(
        (status = 200, description = "API key created", body = ApiKeyResponse),
        (status = 401, description = "Unauthorized"),
        (status = 500, description = "Internal server error")
    ),
    security(
        ("bearer_auth" = [])
    )
)]
pub async fn create_api_key(
    State(state): State<AppState>,
    Extension(user): Extension<User>,
    Json(req): Json<CreateApiKeyRequest>,
) -> Result<Json<ApiKeyResponse>, AppError> {
    let id = Uuid::new_v4().to_string();
    let api_key = format!("zedr_key_{}", Uuid::new_v4().to_string().replace("-", ""));
    let key_hash = hash_api_key(&api_key);
    
    let now = chrono::Utc::now().timestamp();
    let expires_at = now + (90 * 24 * 60 * 60); // 3 months

    sqlx::query(
        "INSERT INTO api_keys (id, user_id, key_hash, name, expires_at, created_at) 
         VALUES (?, ?, ?, ?, ?, ?)"
    )
    .bind(&id)
    .bind(&user.id)
    .bind(&key_hash)
    .bind(&req.name)
    .bind(expires_at)
    .bind(now)
    .execute(&state.pool)
    .await?;

    crate::audit::record_by(&state.pool, &user, "api_key.create", Some(&id), serde_json::json!({ "name": req.name })).await?;

    Ok(Json(ApiKeyResponse {
        id,
        name: req.name,
        api_key,
        expires_at,
    }))
}

#[utoipa::path(
    get,
    path = "/api/admin/api-keys",
    tag = "admin",
    responses(
        (status = 200, description = "List of API keys", body = Vec<ApiKeyListItem>),
        (status = 401, description = "Unauthorized"),
        (status = 500, description = "Internal server error")
    ),
    security(
        ("bearer_auth" = [])
    )
)]
pub async fn list_api_keys(
    State(state): State<AppState>,
    Extension(user): Extension<User>,
) -> Result<Json<Vec<ApiKeyListItem>>, AppError> {
    let keys: Vec<ApiKeyListItem> = sqlx::query_as(
        "SELECT id, name, expires_at, created_at, last_used_at 
         FROM api_keys 
         WHERE user_id = ? AND revoked_at IS NULL
         ORDER BY created_at DESC"
    )
    .bind(&user.id)
    .fetch_all(&state.pool)
    .await?
    .into_iter()
    .map(|(id, name, expires_at, created_at, last_used_at)| ApiKeyListItem {
        id,
        name,
        expires_at,
        created_at,
        last_used_at,
    })
    .collect();

    Ok(Json(keys))
}

#[utoipa::path(
    delete,
    path = "/api/admin/api-keys/{id}",
    tag = "admin",
    params(
        ("id" = String, Path, description = "API key ID")
    ),
    responses(
        (status = 200, description = "API key revoked"),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "API key not found"),
        (status = 500, description = "Internal server error")
    ),
    security(
        ("bearer_auth" = [])
    )
)]
pub async fn revoke_api_key(
    State(state): State<AppState>,
    Extension(user): Extension<User>,
    axum::extract::Path(id): axum::extract::Path<String>,
) -> Result<Json<()>, AppError> {
    let now = chrono::Utc::now().timestamp();
    
    let result = sqlx::query(
        "UPDATE api_keys SET revoked_at = ? WHERE id = ? AND user_id = ? AND revoked_at IS NULL"
    )
    .bind(now)
    .bind(&id)
    .bind(&user.id)
    .execute(&state.pool)
    .await?;

    if result.rows_affected() == 0 {
        return Err(AppError::NotFound);
    }

    crate::audit::record_by(&state.pool, &user, "api_key.revoke", Some(&id), serde_json::json!({})).await?;

    Ok(Json(()))
}
