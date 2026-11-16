use axum::{extract::State, http::StatusCode, Json};
use chrono::Utc;
use rand::Rng;
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;
use uuid::Uuid;

use crate::api::AppState;
use crate::audit;
use crate::auth::AdminUser;
use crate::error::Result;

#[derive(Debug, Deserialize, ToSchema)]
pub struct IssueUpgradeRequest {
    pub agent_id: String,
    pub install_key_id: String,
    pub target_version: String,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct UpgradeCommandResponse {
    pub id: String,
    pub agent_id: String,
    pub target_version: String,
    pub status: String,
    pub created_at: i64,
}

#[utoipa::path(
    post,
    path = "/api/admin/upgrades",
    tag = "admin",
    request_body = IssueUpgradeRequest,
    responses(
        (status = 201, description = "Upgrade command issued", body = UpgradeCommandResponse)
    )
)]
pub async fn issue_upgrade(
    State(state): State<AppState>,
    AdminUser(user): AdminUser,
    Json(req): Json<IssueUpgradeRequest>,
) -> Result<(StatusCode, Json<UpgradeCommandResponse>)> {
    let id = Uuid::new_v4().to_string();
    let created_at = Utc::now().timestamp();

    // Verify agent exists
    sqlx::query("SELECT id FROM agents WHERE id = ?")
        .bind(&req.agent_id)
        .fetch_optional(&state.pool)
        .await?
        .ok_or(crate::error::AppError::NotFound)?;

    sqlx::query_scalar::<_, String>(
        "SELECT id FROM install_keys WHERE id = ? AND used_at IS NULL AND revoked_at IS NULL AND expires_at > ?"
    )
    .bind(&req.install_key_id)
    .bind(created_at)
    .fetch_optional(&state.pool)
    .await?
    .ok_or(crate::error::AppError::BadRequest("Invalid or expired install key".to_string()))?;

    // Get agent's current version
    let current_version: String = sqlx::query_scalar("SELECT version FROM agents WHERE id = ?")
        .bind(&req.agent_id)
        .fetch_one(&state.pool)
        .await?;

    let issued_at = created_at as u64;
    let nonce = hex::encode(rand::thread_rng().gen::<[u8; 16]>());
    
    let signature = state.signing_service.sign_upgrade_command(
        &req.agent_id,
        &req.target_version,
        &nonce,
        issued_at,
    )?;

    sqlx::query(
        "INSERT INTO upgrade_commands (id, agent_id, target_version, install_key_id, status, created_at, signature, issued_at, nonce)
         VALUES (?, ?, ?, ?, 'pending', ?, ?, ?, ?)"
    )
    .bind(&id)
    .bind(&req.agent_id)
    .bind(&req.target_version)
    .bind(&req.install_key_id)
    .bind(created_at)
    .bind(signature.to_bytes().as_slice())
    .bind(issued_at as i64)
    .bind(&nonce)
    .execute(&state.pool)
    .await?;

    // Log upgrade initiated event
    let event_id = Uuid::new_v4().to_string();
    let upgrade_event = serde_json::json!({
        "timestamp": created_at as u64,
        "from_version": current_version,
        "to_version": &req.target_version,
        "status": "Initiated",
        "source": "server",
        "requesting_user": user.username,
        "error": null
    });
    
    tracing::info!(
        "Upgrade initiated: {} -> {} for agent {} by user {}",
        current_version,
        &req.target_version,
        &req.agent_id,
        user.username
    );
    
    sqlx::query(
        "INSERT INTO events (id, agent_id, event_type, timestamp, data, received_at)
         VALUES (?, ?, 'upgrade', ?, ?, ?)"
    )
    .bind(&event_id)
    .bind(&req.agent_id)
    .bind(created_at)
    .bind(serde_json::to_string(&upgrade_event).unwrap())
    .bind(created_at)
    .execute(&state.pool)
    .await?;

    audit::record_by(
        &state.pool,
        &user,
        "upgrade.issue",
        Some(&req.agent_id),
        serde_json::json!({ "from_version": current_version, "target_version": req.target_version }),
    )
    .await?;

    Ok((
        StatusCode::CREATED,
        Json(UpgradeCommandResponse {
            id,
            agent_id: req.agent_id,
            target_version: req.target_version,
            status: "pending".to_string(),
            created_at,
        }),
    ))
}

#[utoipa::path(
    get,
    path = "/api/admin/upgrades",
    tag = "admin",
    responses(
        (status = 200, description = "List of upgrade commands")
    )
)]
pub async fn list_upgrades(
    State(state): State<AppState>,
) -> Result<Json<Vec<UpgradeCommandResponse>>> {
    let rows = sqlx::query_as::<_, (String, String, String, String, i64)>(
        "SELECT id, agent_id, target_version, status, created_at 
         FROM upgrade_commands 
         ORDER BY created_at DESC 
         LIMIT 100"
    )
    .fetch_all(&state.pool)
    .await?;

    let commands = rows
        .into_iter()
        .map(|(id, agent_id, target_version, status, created_at)| UpgradeCommandResponse {
            id,
            agent_id,
            target_version,
            status,
            created_at,
        })
        .collect();

    Ok(Json(commands))
}
