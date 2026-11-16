use axum::{body::Bytes, extract::State, http::HeaderMap, Json};
use chrono::Utc;
use serde::Serialize;
use sqlx::SqliteExecutor;
use utoipa::ToSchema;
use uuid::Uuid;

use crate::agent_auth;
use crate::api::{AppState, SystemEventBroadcast};
use crate::error::{AppError, Result};
use crate::incidents;
use crate::liveness;
use zedr_protocol::{SystemEvent, EventBatch, StopReason, UpgradeCommand};

const HAND_OUT_AGAIN_AFTER_SECS: i64 = 120;

fn waits_for_an_answer(handed_out_at: Option<i64>, now: i64) -> bool {
    handed_out_at.is_some_and(|handed_out_at| now - handed_out_at < HAND_OUT_AGAIN_AFTER_SECS)
}

#[derive(Serialize, ToSchema)]
pub struct HeartbeatResponse {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub upgrade: Option<UpgradeCommand>,
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
        (status = 413, description = "Batch larger than MAX_EVENT_BATCH_BYTES, nothing is stored"),
        (status = 422, description = "Batch with a sensor event, which only travels in a sealed window, nothing is stored")
    )
)]
pub async fn ingest_events(
    State(state): State<AppState>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Json<HeartbeatResponse>> {
    let batch: EventBatch = serde_json::from_slice(&body)
        .map_err(|e| AppError::BadRequest(format!("Invalid event batch: {}", e)))?;

    agent_auth::authenticate(&state, "events", &batch.agent_id, batch.session, batch.seq, &headers, &body).await?;

    if batch.events.iter().any(is_sensor_event) {
        return Err(AppError::Unprocessable("Sensor events are sent in sealed windows".to_string()));
    }

    let mut has_heartbeat = false;
    let received_at = Utc::now().timestamp();

    for event in batch.events {
        has_heartbeat |= matches!(event, SystemEvent::Heartbeat(_));
        let stored = store_event(&state.pool, &batch.agent_id, &event, received_at).await?;
        let timestamp = stored.timestamp;
        let _ = state.system_events_tx.send(stored);

        // Update upgrade_commands status if this is an upgrade event
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
                    return Ok(Json(HeartbeatResponse { upgrade: None }));
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
                }));
            }
        }
    }

    Ok(Json(HeartbeatResponse { upgrade: None }))
}

fn is_sensor_event(event: &SystemEvent) -> bool {
    matches!(event, SystemEvent::Process(_) | SystemEvent::File(_) | SystemEvent::Network(_) | SystemEvent::Persistence(_) | SystemEvent::Package(_))
}

/// Stores one event in the form the console reads and returns what to tell the listeners once it is committed
pub async fn store_event<'e>(executor: impl SqliteExecutor<'e>, agent_id: &str, event: &SystemEvent, received_at: i64) -> Result<SystemEventBroadcast> {
    let (event_type, timestamp, data) = match event {
        SystemEvent::Process(e) => ("process", e.timestamp as i64, serde_json::to_string(e).unwrap()),
        SystemEvent::File(e) => ("file", e.timestamp as i64, serde_json::to_string(e).unwrap()),
        SystemEvent::Network(e) => ("network", e.timestamp as i64, serde_json::to_string(e).unwrap()),
        SystemEvent::Heartbeat(e) => ("heartbeat", e.timestamp as i64, serde_json::to_string(e).unwrap()),
        SystemEvent::Upgrade(e) => ("upgrade", e.timestamp as i64, serde_json::to_string(e).unwrap()),
        SystemEvent::Install(e) => ("install", e.timestamp as i64, serde_json::to_string(e).unwrap()),
        SystemEvent::AgentStopping(e) => ("agent_stopping", e.timestamp as i64, serde_json::to_string(e).unwrap()),
        SystemEvent::Persistence(e) => ("persistence", e.timestamp as i64, serde_json::to_string(e).unwrap()),
        SystemEvent::Package(e) => ("package", e.timestamp as i64, serde_json::to_string(e).unwrap()),
    };
    let id = Uuid::new_v4().to_string();

    sqlx::query(
        "INSERT INTO events (id, agent_id, event_type, timestamp, data, received_at)
         VALUES (?, ?, ?, ?, ?, ?)"
    )
    .bind(&id)
    .bind(agent_id)
    .bind(event_type)
    .bind(timestamp)
    .bind(&data)
    .bind(received_at)
    .execute(executor)
    .await?;

    Ok(SystemEventBroadcast { id, agent_id: agent_id.to_string(), event_type: event_type.to_string(), timestamp, data, received_at })
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
