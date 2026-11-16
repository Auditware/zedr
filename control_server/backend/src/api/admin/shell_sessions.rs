use axum::{
    extract::{Path, State},
    http::StatusCode,
    Json,
};
use rand::Rng;
use serde::{Deserialize, Serialize};

use crate::{
    api::AppState,
    audit,
    auth::AdminUser,
    error::{AppError, Result},
};

#[derive(Debug, Deserialize)]
pub struct CreateSessionRequest {
    pub agent_id: String,
}

#[derive(Debug, Serialize)]
pub struct CreateSessionResponse {
    pub session_id: String,
    pub expires_at: i64,
}

#[derive(Debug, Serialize, sqlx::FromRow)]
pub struct ShellSession {
    pub id: String,
    pub agent_id: String,
    pub created_at: i64,
    pub last_activity_at: i64,
    pub expires_at: i64,
    pub terminated_at: Option<i64>,
    pub created_by_user_id: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct ExecuteCommandRequest {
    pub command_text: String,
}

#[derive(Debug, Serialize)]
pub struct ExecuteCommandResponse {
    pub command_id: String,
}

#[derive(Debug, Serialize, sqlx::FromRow)]
pub struct ShellCommandResult {
    pub id: String,
    pub command_text: String,
    pub issued_at: i64,
    pub executed_at: Option<i64>,
    pub exit_code: Option<i32>,
    pub stdout: Option<String>,
    pub stderr: Option<String>,
}

pub async fn create_session(
    State(state): State<AppState>,
    AdminUser(user): AdminUser,
    Json(req): Json<CreateSessionRequest>,
) -> Result<Json<CreateSessionResponse>> {
    let agent_exists: bool = sqlx::query_scalar("SELECT COUNT(*) > 0 FROM agents WHERE id = ?")
        .bind(&req.agent_id)
        .fetch_one(&state.pool)
        .await?;

    if !agent_exists {
        return Err(AppError::NotFound);
    }

    let active_session: Option<String> = sqlx::query_scalar(
        "SELECT id FROM shell_sessions WHERE agent_id = ? AND terminated_at IS NULL AND expires_at > ?"
    )
    .bind(&req.agent_id)
    .bind(chrono::Utc::now().timestamp())
    .fetch_optional(&state.pool)
    .await?;

    if let Some(existing_id) = active_session {
        return Err(AppError::BadRequest(format!(
            "Agent already has an active shell session: {}",
            existing_id
        )));
    }

    let session_id = uuid::Uuid::new_v4().to_string();
    let created_at = chrono::Utc::now().timestamp();
    let expires_at = created_at + (30 * 60);

    sqlx::query(
        "INSERT INTO shell_sessions (id, agent_id, created_at, last_activity_at, expires_at, created_by_user_id) VALUES (?, ?, ?, ?, ?, ?)"
    )
    .bind(&session_id)
    .bind(&req.agent_id)
    .bind(created_at)
    .bind(created_at)
    .bind(expires_at)
    .bind(&user.id)
    .execute(&state.pool)
    .await?;


    // Persist shell_session_created event to events table
    let event_id = uuid::Uuid::new_v4().to_string();
    let event_data = serde_json::json!({
        "session_id": session_id,
        "requesting_user": user.username
    }).to_string();
    sqlx::query(
        "INSERT INTO events (id, agent_id, event_type, timestamp, data, received_at) VALUES (?, ?, ?, ?, ?, ?)"
    )
    .bind(&event_id)
    .bind(&req.agent_id)
    .bind("shell_session_created")
    .bind(created_at)
    .bind(&event_data)
    .bind(created_at)
    .execute(&state.pool)
    .await?;

    let _ = state.system_events_tx.send(crate::api::SystemEventBroadcast {
        id: event_id,
        agent_id: req.agent_id.clone(),
        event_type: "shell_session_created".to_string(),
        timestamp: created_at,
        data: event_data,
        received_at: created_at,
    });

    audit::record_by(
        &state.pool,
        &user,
        "shell.session.create",
        Some(&req.agent_id),
        serde_json::json!({ "session_id": session_id }),
    )
    .await?;

    Ok(Json(CreateSessionResponse {
        session_id,
        expires_at,
    }))
}

pub async fn list_sessions(
    State(state): State<AppState>,
) -> Result<Json<Vec<ShellSession>>> {
    let sessions: Vec<ShellSession> = sqlx::query_as(
        "SELECT id, agent_id, created_at, last_activity_at, expires_at, terminated_at, created_by_user_id 
         FROM shell_sessions 
         ORDER BY created_at DESC 
         LIMIT 100"
    )
    .fetch_all(&state.pool)
    .await?;

    Ok(Json(sessions))
}

pub async fn terminate_session(
    State(state): State<AppState>,
    AdminUser(user): AdminUser,
    Path(session_id): Path<String>,
) -> Result<StatusCode> {
    let executed_commands: Vec<String> = sqlx::query_scalar(
        "SELECT command_text FROM shell_commands WHERE session_id = ? ORDER BY issued_at ASC"
    )
    .bind(&session_id)
    .fetch_all(&state.pool)
    .await?;

    let commands_json = serde_json::to_string(&executed_commands).unwrap_or_else(|_| "[]".to_string());

    let updated = sqlx::query(
        "UPDATE shell_sessions SET terminated_at = ?, termination_reason = ?, executed_commands = ? WHERE id = ? AND terminated_at IS NULL"
    )
    .bind(chrono::Utc::now().timestamp())
    .bind("manual")
    .bind(&commands_json)
    .bind(&session_id)
    .execute(&state.pool)
    .await?
    .rows_affected();

    if updated == 0 {
        return Err(AppError::NotFound);
    }

    if let Some(agent_id) = sqlx::query_scalar::<_, String>(
        "SELECT agent_id FROM shell_sessions WHERE id = ?"
    )
    .bind(&session_id)
    .fetch_optional(&state.pool)
    .await?
    {
        let event_id = uuid::Uuid::new_v4().to_string();
        let now = chrono::Utc::now().timestamp();
        let event_data = serde_json::json!({
            "session_id": session_id,
            "reason": "manual",
            "requesting_user": user.username,
            "executed_commands": executed_commands
        }).to_string();

        sqlx::query(
            "INSERT INTO events (id, agent_id, event_type, timestamp, data, received_at) VALUES (?, ?, ?, ?, ?, ?)"
        )
        .bind(&event_id)
        .bind(&agent_id)
        .bind("shell_session_terminated")
        .bind(now)
        .bind(&event_data)
        .bind(now)
        .execute(&state.pool)
        .await?;

        let _ = state.system_events_tx.send(crate::api::SystemEventBroadcast {
            id: event_id,
            agent_id,
            event_type: "shell_session_terminated".to_string(),
            timestamp: now,
            data: event_data,
            received_at: now,
        });
    }

    audit::record_by(&state.pool, &user, "shell.session.terminate", Some(&session_id), serde_json::json!({})).await?;

    Ok(StatusCode::NO_CONTENT)
}

pub async fn execute_command(
    State(state): State<AppState>,
    AdminUser(user): AdminUser,
    Path(session_id): Path<String>,
    Json(req): Json<ExecuteCommandRequest>,
) -> Result<Json<ExecuteCommandResponse>> {
    let session: Option<(String, String)> = sqlx::query_as(
        "SELECT agent_id, id FROM shell_sessions WHERE id = ? AND terminated_at IS NULL AND expires_at > ?"
    )
    .bind(&session_id)
    .bind(chrono::Utc::now().timestamp())
    .fetch_optional(&state.pool)
    .await?;

    let (agent_id, _session_id) = session.ok_or_else(|| {
        AppError::NotFound
    })?;

    let command_id = uuid::Uuid::new_v4().to_string();
    let issued_at = chrono::Utc::now().timestamp() as u64;
    let nonce = hex::encode(rand::thread_rng().gen::<[u8; 16]>());

    let signature = state.signing_service.sign_shell_command(
        &agent_id,
        &session_id,
        &req.command_text,
        &nonce,
        issued_at,
    )?;

    sqlx::query(
        "INSERT INTO shell_commands (id, session_id, command_text, signature, issued_at, nonce) 
         VALUES (?, ?, ?, ?, ?, ?)"
    )
    .bind(&command_id)
    .bind(&session_id)
    .bind(&req.command_text)
    .bind(signature.to_bytes().as_ref())
    .bind(issued_at as i64)
    .bind(&nonce)
    .execute(&state.pool)
    .await?;

    sqlx::query(
        "UPDATE shell_sessions SET last_activity_at = ? WHERE id = ?"
    )
    .bind(chrono::Utc::now().timestamp())
    .bind(&session_id)
    .execute(&state.pool)
    .await?;

    let _ = state.system_events_tx.send(crate::api::SystemEventBroadcast {
        id: uuid::Uuid::new_v4().to_string(),
        agent_id: agent_id.clone(),
        event_type: "shell_command_queued".to_string(),
        timestamp: issued_at as i64,
        data: serde_json::json!({
            "command_id": command_id,
            "session_id": session_id,
            "command_text": req.command_text
        }).to_string(),
        received_at: chrono::Utc::now().timestamp(),
    });

    audit::record_by(
        &state.pool,
        &user,
        "shell.command",
        Some(&agent_id),
        serde_json::json!({ "session_id": session_id, "command_id": command_id, "command_text": req.command_text }),
    )
    .await?;

    Ok(Json(ExecuteCommandResponse { command_id }))
}

pub async fn get_session_commands(
    State(state): State<AppState>,
    AdminUser(_user): AdminUser,
    Path(session_id): Path<String>,
) -> Result<Json<Vec<ShellCommandResult>>> {
    let commands: Vec<ShellCommandResult> = sqlx::query_as(
        "SELECT id, command_text, issued_at, executed_at, exit_code, stdout, stderr
         FROM shell_commands 
         WHERE session_id = ? 
         ORDER BY issued_at ASC"
    )
    .bind(&session_id)
    .fetch_all(&state.pool)
    .await?;

    Ok(Json(commands))
}

