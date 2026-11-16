use sqlx::{QueryBuilder, Sqlite, SqlitePool};

use crate::db::models::{Agent, Event};
use crate::error::Result;
use crate::api::admin::events::EventStats;

pub async fn list_agents(pool: &SqlitePool, limit: i64, offset: i64) -> Result<Vec<Agent>> {
    let agents = sqlx::query_as::<_, Agent>(
        "SELECT a.id, a.hostname, a.platform, a.os_version, a.architecture, a.version, a.ip_address, a.last_heartbeat, a.status, a.created_at, a.user_id, a.liveness_state, a.enrollment_token_id, t.label AS enrollment_group
         FROM agents a
         LEFT JOIN enrollment_tokens t ON t.id = a.enrollment_token_id
         ORDER BY a.last_heartbeat DESC
         LIMIT ? OFFSET ?",
    )
    .bind(limit)
    .bind(offset)
    .fetch_all(pool)
    .await?;

    Ok(agents)
}

pub async fn get_agent_by_id(pool: &SqlitePool, agent_id: &str) -> Result<Agent> {
    let agent = sqlx::query_as::<_, Agent>(
        "SELECT a.id, a.hostname, a.platform, a.os_version, a.architecture, a.version, a.ip_address, a.last_heartbeat, a.status, a.created_at, a.user_id, a.liveness_state, a.enrollment_token_id, t.label AS enrollment_group
         FROM agents a
         LEFT JOIN enrollment_tokens t ON t.id = a.enrollment_token_id
         WHERE a.id = ?",
    )
    .bind(agent_id)
    .fetch_optional(pool)
    .await?
    .ok_or(crate::error::AppError::NotFound)?;

    Ok(agent)
}

pub async fn get_event_stats(pool: &SqlitePool) -> Result<EventStats> {
        let shell_session_created: (i64,) = sqlx::query_as(
            "SELECT COUNT(*) FROM events WHERE event_type = 'shell_session_created'"
        )
        .fetch_one(pool)
        .await?;

        let shell_session_terminated: (i64,) = sqlx::query_as(
            "SELECT COUNT(*) FROM events WHERE event_type = 'shell_session_terminated'"
        )
        .fetch_one(pool)
        .await?;
    let process: (i64,) = sqlx::query_as(
        "SELECT COUNT(*) FROM events WHERE event_type = 'process'"
    )
    .fetch_one(pool)
    .await?;

    let file: (i64,) = sqlx::query_as(
        "SELECT COUNT(*) FROM events WHERE event_type = 'file'"
    )
    .fetch_one(pool)
    .await?;

    let network: (i64,) = sqlx::query_as(
        "SELECT COUNT(*) FROM events WHERE event_type = 'network'"
    )
    .fetch_one(pool)
    .await?;

    let heartbeat: (i64,) = sqlx::query_as(
        "SELECT COUNT(*) FROM events WHERE event_type = 'heartbeat'"
    )
    .fetch_one(pool)
    .await?;

    let upgrade: (i64,) = sqlx::query_as(
        "SELECT COUNT(*) FROM events WHERE event_type = 'upgrade'"
    )
    .fetch_one(pool)
    .await?;

    let install: (i64,) = sqlx::query_as(
        "SELECT COUNT(*) FROM events WHERE event_type = 'install'"
    )
    .fetch_one(pool)
    .await?;

    let incident: (i64,) = sqlx::query_as(
        "SELECT COUNT(*) FROM events WHERE event_type = 'incident_opened'"
    )
    .fetch_one(pool)
    .await?;

    Ok(EventStats {
        incident: incident.0,
        process: process.0,
        file: file.0,
        network: network.0,
        heartbeat: heartbeat.0,
        upgrade: upgrade.0,
        install: install.0,
        shell_session_created: shell_session_created.0,
        shell_session_terminated: shell_session_terminated.0,
    })
}

pub struct EventFilter<'a> {
    pub agent_id: Option<&'a str>,
    pub event_types: Option<&'a [String]>,
    pub from: Option<i64>,
    pub to: Option<i64>,
}

pub async fn list_events(pool: &SqlitePool, filter: &EventFilter<'_>, limit: i64, offset: i64) -> Result<Vec<Event>> {
    let mut query = QueryBuilder::<Sqlite>::new("SELECT id, agent_id, event_type, timestamp, data, received_at FROM events WHERE 1 = 1");
    if let Some(agent_id) = filter.agent_id {
        query.push(" AND agent_id = ").push_bind(agent_id);
    }
    if let Some(types) = filter.event_types.filter(|types| !types.is_empty()) {
        query.push(" AND event_type IN (");
        let mut listed = query.separated(", ");
        for event_type in types {
            listed.push_bind(event_type);
        }
        query.push(")");
    }
    if let Some(from) = filter.from {
        query.push(" AND timestamp >= ").push_bind(from);
    }
    if let Some(to) = filter.to {
        query.push(" AND timestamp <= ").push_bind(to);
    }
    query.push(" ORDER BY received_at DESC LIMIT ").push_bind(limit).push(" OFFSET ").push_bind(offset);

    Ok(query.build_query_as::<Event>().fetch_all(pool).await?)
}

pub async fn event_histogram(
    pool: &SqlitePool,
    from: i64,
    to: i64,
    bucket_seconds: i64,
    agent_id: Option<&str>,
) -> Result<Vec<(String, i64, i64)>> {
    let mut query = QueryBuilder::<Sqlite>::new("SELECT event_type, (timestamp - ");
    query
        .push_bind(from)
        .push(") / ")
        .push_bind(bucket_seconds)
        .push(" AS bucket, COUNT(*) FROM events WHERE timestamp >= ")
        .push_bind(from)
        .push(" AND timestamp < ")
        .push_bind(to);
    if let Some(agent_id) = agent_id {
        query.push(" AND agent_id = ").push_bind(agent_id);
    }
    query.push(" GROUP BY event_type, bucket");

    Ok(query.build_query_as::<(String, i64, i64)>().fetch_all(pool).await?)
}
