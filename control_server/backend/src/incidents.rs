use chrono::Utc;
use serde::Serialize;
use sqlx::SqlitePool;
use tokio::sync::broadcast;
use utoipa::ToSchema;
use uuid::Uuid;

use crate::api::SystemEventBroadcast;
use crate::error::Result;

pub const SILENCE: &str = "silence";
pub const SERVICE_STOPPED: &str = "service_stopped";
pub const REPLAY: &str = "replay";
pub const IDENTITY_CONFLICT: &str = "identity_conflict";

#[derive(Debug, Clone, Serialize, sqlx::FromRow, ToSchema)]
pub struct Incident {
    pub id: String,
    pub agent_id: String,
    pub incident_type: String,
    pub evidence: String,
    pub opened_at: i64,
    pub closed_at: Option<i64>,
}

pub async fn record_event(
    pool: &SqlitePool,
    events_tx: &broadcast::Sender<SystemEventBroadcast>,
    agent_id: Option<&str>,
    event_type: &str,
    data: serde_json::Value,
) -> Result<()> {
    let id = Uuid::new_v4().to_string();
    let now = Utc::now().timestamp();
    let mut data = data;
    if let Some(fields) = data.as_object_mut() {
        fields.insert("source".to_string(), serde_json::Value::String("server".to_string()));
    }
    let data = data.to_string();

    sqlx::query(
        "INSERT INTO events (id, agent_id, event_type, timestamp, data, received_at)
         VALUES (?, ?, ?, ?, ?, ?)",
    )
    .bind(&id)
    .bind(agent_id)
    .bind(event_type)
    .bind(now)
    .bind(&data)
    .bind(now)
    .execute(pool)
    .await?;

    let _ = events_tx.send(SystemEventBroadcast {
        id,
        agent_id: agent_id.map(str::to_string).unwrap_or_default(),
        event_type: event_type.to_string(),
        timestamp: now,
        data,
        received_at: now,
    });

    Ok(())
}

pub async fn open(
    pool: &SqlitePool,
    events_tx: &broadcast::Sender<SystemEventBroadcast>,
    agent_id: &str,
    incident_type: &str,
    evidence: serde_json::Value,
) -> Result<bool> {
    let id = Uuid::new_v4().to_string();

    let opened = sqlx::query(
        "INSERT INTO incidents (id, agent_id, incident_type, evidence, opened_at)
         VALUES (?, ?, ?, ?, ?)
         ON CONFLICT DO NOTHING",
    )
    .bind(&id)
    .bind(agent_id)
    .bind(incident_type)
    .bind(evidence.to_string())
    .bind(Utc::now().timestamp())
    .execute(pool)
    .await?
    .rows_affected()
        > 0;

    if opened {
        record_event(
            pool,
            events_tx,
            Some(agent_id),
            "incident_opened",
            serde_json::json!({
                "incident_id": id,
                "incident_type": incident_type,
                "evidence": evidence,
            }),
        )
        .await?;
    }

    Ok(opened)
}

pub async fn close(
    pool: &SqlitePool,
    events_tx: &broadcast::Sender<SystemEventBroadcast>,
    agent_id: &str,
    incident_types: &[&str],
) -> Result<()> {
    for incident_type in incident_types {
        let closed: Option<String> = sqlx::query_scalar(
            "UPDATE incidents SET closed_at = ?
             WHERE agent_id = ? AND incident_type = ? AND closed_at IS NULL
             RETURNING id",
        )
        .bind(Utc::now().timestamp())
        .bind(agent_id)
        .bind(incident_type)
        .fetch_optional(pool)
        .await?;

        if let Some(incident_id) = closed {
            record_event(
                pool,
                events_tx,
                Some(agent_id),
                "incident_closed",
                serde_json::json!({
                    "incident_id": incident_id,
                    "incident_type": incident_type,
                }),
            )
            .await?;
        }
    }

    Ok(())
}

pub async fn close_by_id(
    pool: &SqlitePool,
    events_tx: &broadcast::Sender<SystemEventBroadcast>,
    incident_id: &str,
    closed_by: &str,
) -> Result<Option<Incident>> {
    let closed = sqlx::query_as::<_, Incident>(
        "UPDATE incidents SET closed_at = ?
         WHERE id = ? AND closed_at IS NULL
         RETURNING id, agent_id, incident_type, evidence, opened_at, closed_at",
    )
    .bind(Utc::now().timestamp())
    .bind(incident_id)
    .fetch_optional(pool)
    .await?;

    if let Some(incident) = &closed {
        record_event(
            pool,
            events_tx,
            Some(&incident.agent_id),
            "incident_closed",
            serde_json::json!({
                "incident_id": incident.id,
                "incident_type": incident.incident_type,
                "closed_by": closed_by,
            }),
        )
        .await?;
    }

    Ok(closed)
}

pub async fn list(pool: &SqlitePool, open_only: bool, limit: i64) -> Result<Vec<Incident>> {
    let incidents = sqlx::query_as::<_, Incident>(
        "SELECT id, agent_id, incident_type, evidence, opened_at, closed_at
         FROM incidents
         WHERE (? = 0 OR closed_at IS NULL)
         ORDER BY opened_at DESC
         LIMIT ?",
    )
    .bind(open_only)
    .bind(limit)
    .fetch_all(pool)
    .await?;

    Ok(incidents)
}
