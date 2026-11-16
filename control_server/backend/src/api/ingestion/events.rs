use axum::{body::Bytes, extract::State, http::HeaderMap, Json};
use chrono::Utc;
use serde::Serialize;
use utoipa::ToSchema;
use uuid::Uuid;

use crate::detections::Level;
use crate::agent_auth;
use crate::api::{AppState, SystemEventBroadcast};
use crate::error::{AppError, Result};
use crate::incidents;
use crate::liveness;
use zedr_protocol::{SystemEvent, EventBatch, StopReason, UpgradeCommand, ShellCommand};

const HAND_OUT_AGAIN_AFTER_SECS: i64 = 120;

fn waits_for_an_answer(handed_out_at: Option<i64>, now: i64) -> bool {
    handed_out_at.is_some_and(|handed_out_at| now - handed_out_at < HAND_OUT_AGAIN_AFTER_SECS)
}

#[derive(Serialize, ToSchema)]
pub struct HeartbeatResponse {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub upgrade: Option<UpgradeCommand>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub shell_command: Option<ShellCommand>,
}

#[utoipa::path(
    post,
    path = "/api/events",
    tag = "agents",
    request_body = EventBatch,
    responses(
        (status = 200, description = "Events ingested successfully", body = HeartbeatResponse),
        (status = 400, description = "Batch that cannot be read, nothing is stored"),
        (status = 401, description = "Missing or invalid signature, or unknown agent"),
        (status = 409, description = "Replayed or stale request"),
        (status = 413, description = "Batch larger than MAX_EVENT_BATCH_BYTES, nothing is stored")
    )
)]
pub async fn ingest_events(
    State(state): State<AppState>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Json<HeartbeatResponse>> {
    let batch: EventBatch = serde_json::from_slice(&body)
        .map_err(|e| AppError::BadRequest(format!("Invalid event batch: {}", e)))?;

    authenticate_batch(&state, &batch, &headers, &body).await?;

    let mut has_heartbeat = false;
    let received_at = Utc::now().timestamp();
    
    for event in batch.events {
        let event_id = Uuid::new_v4().to_string();
        let (event_type, timestamp, data) = match &event {
            SystemEvent::Process(e) => {
                ("process", e.timestamp as i64, serde_json::to_string(e).unwrap())
            }
            SystemEvent::File(e) => {
                ("file", e.timestamp as i64, serde_json::to_string(e).unwrap())
            }
            SystemEvent::Network(e) => {
                ("network", e.timestamp as i64, serde_json::to_string(e).unwrap())
            }
            SystemEvent::Heartbeat(e) => {
                has_heartbeat = true;
                ("heartbeat", e.timestamp as i64, serde_json::to_string(e).unwrap())
            }
            SystemEvent::Upgrade(e) => {
                ("upgrade", e.timestamp as i64, serde_json::to_string(e).unwrap())
            }
            SystemEvent::Install(e) => {
                ("install", e.timestamp as i64, serde_json::to_string(e).unwrap())
            }
            SystemEvent::ShellSessionCreated(e) => {
                ("shell_session_created", e.timestamp as i64, serde_json::to_string(e).unwrap())
            }
            SystemEvent::ShellCommandExecuted(e) => {
                ("shell_command_executed", e.timestamp as i64, serde_json::to_string(e).unwrap())
            }
            SystemEvent::ShellSessionTerminated(e) => {
                ("shell_session_terminated", e.timestamp as i64, serde_json::to_string(e).unwrap())
            }
            SystemEvent::AgentStopping(e) => {
                ("agent_stopping", e.timestamp as i64, serde_json::to_string(e).unwrap())
            }
            SystemEvent::Persistence(e) => {
                ("persistence", e.timestamp as i64, serde_json::to_string(e).unwrap())
            }
            SystemEvent::Package(e) => {
                ("package", e.timestamp as i64, serde_json::to_string(e).unwrap())
            }
        };

        sqlx::query(
            "INSERT INTO events (id, agent_id, event_type, timestamp, data, received_at)
             VALUES (?, ?, ?, ?, ?, ?)"
        )
        .bind(&event_id)
        .bind(&batch.agent_id)
        .bind(event_type)
        .bind(timestamp)
        .bind(&data)
        .bind(received_at)
        .execute(&state.pool)
        .await?;

        let _ = state.system_events_tx.send(crate::api::SystemEventBroadcast {
            id: event_id.clone(),
            agent_id: batch.agent_id.clone(),
            event_type: event_type.to_string(),
            timestamp,
            data: data.clone(),
            received_at,
        });

        let (detections, described) = {
            let mut tracker = state.detections.lock().await;
            let detections = tracker.observe(&batch.agent_id, &event);
            let pid = match &event {
                SystemEvent::Process(process) => Some(process.pid),
                SystemEvent::Network(connection) => Some(connection.pid),
                SystemEvent::File(file) => Some(file.pid),
                _ => None,
            };
            (detections, pid.and_then(|pid| tracker.describe(&batch.agent_id, pid)))
        };
        crate::hunt::index(&state.pool, &batch.agent_id, &event, described.as_ref()).await?;
        for detection in detections {
            let evidence = detection.evidence();
            incidents::record_event(&state.pool, &state.system_events_tx, Some(&batch.agent_id), "detection", evidence.clone()).await?;
            if detection.rule.level == Level::High {
                incidents::open(&state.pool, &state.system_events_tx, &batch.agent_id, &detection.incident_type(), evidence).await?;
            }
        }

        // Update upgrade_commands status if this is an upgrade event
        if event_type == "upgrade" {
            if let SystemEvent::Upgrade(upgrade_evt) = &event {
                let status = match upgrade_evt.status {
                    zedr_protocol::UpgradeStatus::Handoff => "handoff",
                    zedr_protocol::UpgradeStatus::Completed => "completed",
                    zedr_protocol::UpgradeStatus::Failed => "failed",
                    _ => continue,
                };
                
                sqlx::query(
                    "UPDATE upgrade_commands 
                     SET status = ?, executed_at = ?, error = ?
                     WHERE agent_id = ? AND target_version = ? AND status IN ('pending', 'downloaded', 'handoff')"
                )
                .bind(status)
                .bind(timestamp)
                .bind(&upgrade_evt.error)
                .bind(&batch.agent_id)
                .bind(&upgrade_evt.to_version)
                .execute(&state.pool)
                .await?;
            }
        }

        // Update shell_commands status if this is a shell command executed event
        if event_type == "shell_command_executed" {
            if let SystemEvent::ShellCommandExecuted(shell_evt) = &event {
                let stored = sqlx::query(
                    "UPDATE shell_commands 
                     SET executed_at = ?, exit_code = ?, stdout = ?, stderr = ?
                     WHERE nonce = ?
                       AND executed_at IS NULL
                       AND session_id IN (SELECT id FROM shell_sessions WHERE agent_id = ?)"
                )
                .bind(timestamp)
                .bind(shell_evt.exit_code)
                .bind(&shell_evt.stdout)
                .bind(&shell_evt.stderr)
                .bind(&shell_evt.command_id)
                .bind(&batch.agent_id)
                .execute(&state.pool)
                .await?;

                if stored.rows_affected() == 0 {
                    tracing::warn!(
                        "Result for shell command {:?} from agent {} was left out, the command has a result already or is not this agent's",
                        shell_evt.command_id,
                        batch.agent_id
                    );
                }

                tracing::info!("Broadcasting shell_command_executed for session {}", shell_evt.session_id);
                let _ = state.system_events_tx.send(SystemEventBroadcast {
                    id: event_id.clone(),
                    agent_id: batch.agent_id.clone(),
                    event_type: "shell_command_executed".to_string(),
                    timestamp,
                    data: data.clone(),
                    received_at,
                });            }
        }

        // Update shell_sessions termination data if this is a shell session terminated event
        if event_type == "shell_session_terminated" {
            if let SystemEvent::ShellSessionTerminated(term_evt) = &event {
                let executed_commands: Vec<String> = sqlx::query_scalar(
                    "SELECT command_text FROM shell_commands WHERE session_id = ? ORDER BY issued_at ASC"
                )
                .bind(&term_evt.session_id)
                .fetch_all(&state.pool)
                .await?;

                let commands_json = serde_json::to_string(&executed_commands).unwrap_or_else(|_| "[]".to_string());

                sqlx::query(
                    "UPDATE shell_sessions 
                     SET terminated_at = ?, termination_reason = ?, executed_commands = ?
                     WHERE id = ? AND agent_id = ?"
                )
                .bind(timestamp)
                .bind(&term_evt.reason)
                .bind(&commands_json)
                .bind(&term_evt.session_id)
                .bind(&batch.agent_id)
                .execute(&state.pool)
                .await?;
            }
        }

        if let SystemEvent::AgentStopping(stopping) = &event {
            record_stop(&state, &batch.agent_id, &stopping.reason).await?;
        }
    }

    // Update agent last_heartbeat and status if batch contains heartbeat event
    if has_heartbeat {
        let now = Utc::now().timestamp();
        sqlx::query(
            "UPDATE agents SET last_heartbeat = ?, status = 'online', liveness_state = 'active', stop_reason = NULL WHERE id = ?"
        )
            .bind(now)
            .bind(&batch.agent_id)
            .execute(&state.pool)
            .await?;

        incidents::close(
            &state.pool,
            &state.system_events_tx,
            &batch.agent_id,
            &[incidents::SILENCE, incidents::SERVICE_STOPPED],
        )
        .await?;
        
        // Broadcast heartbeat event via SSE
        let agent_event = crate::api::AgentEvent {
            agent_id: batch.agent_id.clone(),
            event_type: crate::api::AgentEventType::Heartbeat,
            timestamp: now,
        };
        
        if let Err(e) = state.agent_events_tx.send(agent_event) {
            tracing::warn!("Failed to broadcast heartbeat event: {}", e);
        }
        
        // Reset timeout for this agent (heartbeat-based detection)
        if let Some(ref timeout_manager) = state.timeout_manager {
            timeout_manager.reset_timeout(batch.agent_id.clone()).await;
        }
        
        // Check for pending upgrade commands
        let upgrade_cmd = sqlx::query_as::<_, (String, String, Option<Vec<u8>>, Option<i64>, Option<String>, Option<i64>)>(
            "SELECT uc.id, uc.target_version, uc.signature, uc.issued_at, uc.nonce, uc.handed_out_at
             FROM upgrade_commands uc
             LEFT JOIN install_keys ik ON uc.install_key_id = ik.id
             WHERE uc.agent_id = ? 
               AND uc.status = 'pending'
               AND (uc.install_key_id IS NULL OR (ik.revoked_at IS NULL AND ik.expires_at > ?))
             ORDER BY uc.created_at ASC
             LIMIT 1"
        )
        .bind(&batch.agent_id)
        .bind(now)
        .fetch_optional(&state.pool)
        .await?;

        if let Some((cmd_id, target_version, signature_opt, issued_at_opt, nonce_opt, handed_out_at)) = upgrade_cmd {
            if let (Some(signature), Some(issued_at), Some(nonce)) = (signature_opt, issued_at_opt, nonce_opt) {
                if waits_for_an_answer(handed_out_at, now) {
                    return Ok(Json(HeartbeatResponse { upgrade: None, shell_command: None }));
                }

                sqlx::query("UPDATE upgrade_commands SET handed_out_at = ? WHERE id = ?")
                    .bind(now)
                    .bind(&cmd_id)
                    .execute(&state.pool)
                    .await?;

                return Ok(Json(HeartbeatResponse {
                    upgrade: Some(UpgradeCommand {
                        agent_id: batch.agent_id.clone(),
                        target_version,
                        signature,
                        issued_at: issued_at as u64,
                        nonce,
                    }),
                    shell_command: None,
                }));
            }
        }

        let shell_cmd = sqlx::query_as::<_, (String, String, String, Vec<u8>, i64, String, Option<i64>)>(
            "SELECT sc.id, sc.session_id, sc.command_text, sc.signature, sc.issued_at, sc.nonce, sc.handed_out_at
             FROM shell_commands sc
             JOIN shell_sessions ss ON sc.session_id = ss.id
             WHERE ss.agent_id = ?
               AND ss.terminated_at IS NULL
               AND ss.expires_at > ?
               AND sc.executed_at IS NULL
             ORDER BY sc.issued_at ASC
             LIMIT 1"
        )
        .bind(&batch.agent_id)
        .bind(now)
        .fetch_optional(&state.pool)
        .await?;

        if let Some((cmd_id, session_id, command_text, signature, issued_at, nonce, handed_out_at)) = shell_cmd {
            if waits_for_an_answer(handed_out_at, now) {
                return Ok(Json(HeartbeatResponse { upgrade: None, shell_command: None }));
            }

            sqlx::query("UPDATE shell_commands SET handed_out_at = ? WHERE id = ?")
                .bind(now)
                .bind(&cmd_id)
                .execute(&state.pool)
                .await?;

            return Ok(Json(HeartbeatResponse {
                upgrade: None,
                shell_command: Some(ShellCommand {
                    session_id,
                    agent_id: batch.agent_id.clone(),
                    command_text,
                    signature,
                    issued_at: issued_at as u64,
                    nonce,
                }),
            }));
        }
    }

    Ok(Json(HeartbeatResponse { upgrade: None, shell_command: None }))
}

async fn authenticate_batch(
    state: &AppState,
    batch: &EventBatch,
    headers: &HeaderMap,
    body: &[u8],
) -> Result<()> {
    let signature = agent_auth::signature_header(headers).ok_or(AppError::Unauthorized)?;

    let pinned_key: Option<String> = sqlx::query_scalar("SELECT public_key FROM agents WHERE id = ?")
        .bind(&batch.agent_id)
        .fetch_optional(&state.pool)
        .await?
        .flatten();
    let pinned_key = pinned_key.ok_or(AppError::Unauthorized)?;

    if !agent_auth::signature_is_valid(&pinned_key, body, signature) {
        return Err(AppError::Unauthorized);
    }

    let mut conn = state.pool.acquire().await?;
    let accepted = agent_auth::accept_sequence(&mut conn, &batch.agent_id, batch.session, batch.seq).await?;
    drop(conn);

    if accepted.is_none() {
        incidents::open(
            &state.pool,
            &state.system_events_tx,
            &batch.agent_id,
            incidents::REPLAY,
            serde_json::json!({
                "request": "events",
                "session": batch.session,
                "seq": batch.seq,
            }),
        )
        .await?;
        return Err(AppError::Conflict("Replayed or stale request".to_string()));
    }

    Ok(())
}

async fn record_stop(state: &AppState, agent_id: &str, reason: &StopReason) -> Result<()> {
    let liveness_state = match reason {
        StopReason::ServiceStop => liveness::State::Incident,
        StopReason::SystemShutdown => liveness::State::Stopped,
        StopReason::Upgrade => liveness::State::Active,
    };

    sqlx::query("UPDATE agents SET stop_reason = ?, liveness_state = ? WHERE id = ?")
        .bind(liveness::stop_reason_label(reason))
        .bind(liveness_state.as_str())
        .bind(agent_id)
        .execute(&state.pool)
        .await?;

    if *reason == StopReason::ServiceStop {
        incidents::open(
            &state.pool,
            &state.system_events_tx,
            agent_id,
            incidents::SERVICE_STOPPED,
            serde_json::json!({ "reason": "the agent service was stopped while the system kept running" }),
        )
        .await?;
    }

    Ok(())
}
