use axum::{
    extract::{Path, State},
    Extension, Json,
};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;
use uuid::Uuid;
use sha2::{Sha256, Digest};

use crate::api::AppState;
use crate::audit;
use crate::auth::{AdminUser, User};
use crate::error::AppError;

#[derive(Deserialize, ToSchema)]
pub struct GenerateInstallKeyRequest {
    #[serde(default = "default_version")]
    pub agent_version: String,
}

fn default_version() -> String {
    std::env::var("ZEDR_AGENT_VERSION").unwrap_or_else(|_| "0.1.0".to_string())
}

#[derive(Serialize, ToSchema)]
pub struct InstallKeyResponse {
    pub id: String,
    pub install_key: String,
    pub expires_at: i64,
    pub agent_version: String,
    pub windows_command: String,
    pub macos_command: String,
    pub linux_command: String,
}

#[utoipa::path(
    post,
    path = "/api/admin/installers/generate",
    tag = "admin",
    responses(
        (status = 200, description = "Install key generated", body = InstallKeyResponse),
        (status = 500, description = "Internal server error")
    )
)]
pub async fn generate_install_key(
    State(state): State<AppState>,
    AdminUser(user): AdminUser,
    Json(req): Json<GenerateInstallKeyRequest>,
) -> Result<Json<InstallKeyResponse>, AppError> {
    let id = Uuid::new_v4().to_string();
    let install_key = format!("zedr_{}", Uuid::new_v4().to_string().replace("-", ""));
    
    let mut hasher = Sha256::new();
    hasher.update(install_key.as_bytes());
    let key_hash = format!("{:x}", hasher.finalize());
    
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;
    
    let expires_at = now + (24 * 60 * 60); // 24 hours
    
    sqlx::query(
        "INSERT INTO install_keys (id, key_hash, created_at, expires_at, created_by, agent_version) 
         VALUES (?, ?, ?, ?, ?, ?)"
    )
    .bind(&id)
    .bind(&key_hash)
    .bind(now)
    .bind(expires_at)
    .bind(&user.username)
    .bind(&req.agent_version)
    .execute(&state.pool)
    .await?;
    
    audit::record_by(
        &state.pool,
        &user,
        "install_key.generate",
        Some(&id),
        serde_json::json!({ "agent_version": req.agent_version }),
    )
    .await?;

    let server_url = std::env::var("ZEDR_SERVER_URL")
        .map_err(|_| AppError::Config("ZEDR_SERVER_URL environment variable must be set".to_string()))?;
    
    Ok(Json(InstallKeyResponse {
        id: id.clone(),
        install_key: install_key.clone(),
        expires_at,
        agent_version: req.agent_version.clone(),
        windows_command: format!(
            "iwr -useb {}/install.ps1?key={} | iex",
            server_url, install_key
        ),
        macos_command: format!(
            "curl -fsSL {}/install.sh?key={} | sudo bash",
            server_url, install_key
        ),
        linux_command: format!(
            "curl -fsSL {}/install.sh?key={} | sudo bash",
            server_url, install_key
        ),
    }))
}

#[derive(Serialize, ToSchema)]
pub struct InstallKey {
    pub id: String,
    pub created_at: i64,
    pub expires_at: i64,
    pub created_by: String,
    pub agent_version: String,
    pub used_at: Option<i64>,
    pub revoked_at: Option<i64>,
    pub enrolled_at: Option<i64>,
    pub enrolled_agent_id: Option<String>,
}

const INSTALL_KEY_COLUMNS: &str = "id, created_at, expires_at, created_by, agent_version, used_at, revoked_at, enrolled_at, enrolled_agent_id";

type InstallKeyRow = (String, i64, i64, String, String, Option<i64>, Option<i64>, Option<i64>, Option<String>);

impl From<InstallKeyRow> for InstallKey {
    fn from((id, created_at, expires_at, created_by, agent_version, used_at, revoked_at, enrolled_at, enrolled_agent_id): InstallKeyRow) -> Self {
        InstallKey { id, created_at, expires_at, created_by, agent_version, used_at, revoked_at, enrolled_at, enrolled_agent_id }
    }
}

#[derive(Serialize, ToSchema)]
pub struct InstallKeysResponse {
    pub keys: Vec<InstallKey>,
}

#[utoipa::path(
    get,
    path = "/api/admin/installers",
    tag = "admin",
    responses(
        (status = 200, description = "List of install keys", body = InstallKeysResponse),
        (status = 500, description = "Internal server error")
    )
)]
pub async fn list_install_keys(
    State(state): State<AppState>,
    Extension(_user): Extension<User>,
) -> Result<Json<InstallKeysResponse>, AppError> {
    let keys = sqlx::query_as::<_, InstallKeyRow>(&format!("SELECT {} FROM install_keys ORDER BY created_at DESC", INSTALL_KEY_COLUMNS))
        .fetch_all(&state.pool)
        .await?
        .into_iter()
        .map(InstallKey::from)
        .collect();

    Ok(Json(InstallKeysResponse { keys }))
}

#[utoipa::path(
    delete,
    path = "/api/admin/installers/{id}",
    tag = "admin",
    params(("id" = String, Path, description = "Install key id")),
    responses(
        (status = 200, description = "The key is revoked and downloads and enrolls nothing more. An agent it already enrolled keeps working", body = InstallKey),
        (status = 403, description = "Admin role required"),
        (status = 404, description = "Unknown key")
    ),
    security(("bearer_auth" = []))
)]
pub async fn revoke_install_key(State(state): State<AppState>, AdminUser(user): AdminUser, Path(id): Path<String>) -> Result<Json<InstallKey>, AppError> {
    let newly_revoked = sqlx::query("UPDATE install_keys SET revoked_at = ? WHERE id = ? AND revoked_at IS NULL")
        .bind(chrono::Utc::now().timestamp())
        .bind(&id)
        .execute(&state.pool)
        .await?
        .rows_affected()
        > 0;

    let key: InstallKey = sqlx::query_as::<_, InstallKeyRow>(&format!("SELECT {} FROM install_keys WHERE id = ?", INSTALL_KEY_COLUMNS))
        .bind(&id)
        .fetch_optional(&state.pool)
        .await?
        .ok_or(AppError::NotFound)?
        .into();

    if newly_revoked {
        audit::record_by(&state.pool, &user, "install_key.revoke", Some(&id), serde_json::json!({ "enrolled_agent_id": key.enrolled_agent_id })).await?;
    }

    Ok(Json(key))
}
