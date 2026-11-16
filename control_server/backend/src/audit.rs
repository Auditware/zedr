use chrono::Utc;
use serde::Serialize;
use sha2::{Digest, Sha256};
use sqlx::SqlitePool;
use tokio::sync::Mutex;
use utoipa::ToSchema;

use crate::auth::User;
use crate::error::Result;

const GENESIS_HASH: &str = "0000000000000000000000000000000000000000000000000000000000000000";

static APPEND_LOCK: Mutex<()> = Mutex::const_new(());

#[derive(Debug, Clone, Serialize, sqlx::FromRow, ToSchema)]
pub struct AuditEntry {
    pub seq: i64,
    pub timestamp: i64,
    pub actor_id: Option<String>,
    pub actor: String,
    pub action: String,
    pub target: Option<String>,
    pub detail: String,
    pub prev_hash: String,
    pub hash: String,
}

#[derive(Serialize)]
struct HashedFields<'a> {
    prev_hash: &'a str,
    timestamp: i64,
    actor_id: Option<&'a str>,
    actor: &'a str,
    action: &'a str,
    target: Option<&'a str>,
    detail: &'a str,
}

fn entry_hash(fields: &HashedFields) -> String {
    let encoded = serde_json::to_vec(fields).unwrap_or_default();
    hex::encode(Sha256::digest(&encoded))
}

pub async fn record(
    pool: &SqlitePool,
    actor_id: Option<&str>,
    actor_name: &str,
    action: &str,
    target: Option<&str>,
    detail: serde_json::Value,
) -> Result<()> {
    let _guard = APPEND_LOCK.lock().await;

    let prev_hash: String = sqlx::query_scalar("SELECT hash FROM audit_log ORDER BY seq DESC LIMIT 1")
        .fetch_optional(pool)
        .await?
        .unwrap_or_else(|| GENESIS_HASH.to_string());

    let timestamp = Utc::now().timestamp();
    let detail = detail.to_string();

    let hash = entry_hash(&HashedFields {
        prev_hash: &prev_hash,
        timestamp,
        actor_id,
        actor: actor_name,
        action,
        target,
        detail: &detail,
    });

    sqlx::query(
        "INSERT INTO audit_log (timestamp, actor_id, actor, action, target, detail, prev_hash, hash)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
    )
    .bind(timestamp)
    .bind(actor_id)
    .bind(actor_name)
    .bind(action)
    .bind(target)
    .bind(&detail)
    .bind(&prev_hash)
    .bind(&hash)
    .execute(pool)
    .await?;

    Ok(())
}

pub async fn record_by(
    pool: &SqlitePool,
    actor: &User,
    action: &str,
    target: Option<&str>,
    mut detail: serde_json::Value,
) -> Result<()> {
    let Some(admin) = &actor.impersonator else {
        return record(pool, Some(&actor.id), &actor.username, action, target, detail).await;
    };
    if let Some(fields) = detail.as_object_mut() {
        fields.insert("as".to_string(), serde_json::Value::String(actor.username.clone()));
    }
    record(pool, Some(&admin.id), &admin.username, action, target, detail).await
}

pub async fn histogram(pool: &SqlitePool, from: i64, to: i64, bucket_seconds: i64) -> Result<Vec<(i64, i64)>> {
    let counts = sqlx::query_as(
        "SELECT (timestamp - ?) / ? AS bucket, COUNT(*) FROM audit_log WHERE timestamp >= ? AND timestamp < ? GROUP BY bucket",
    )
    .bind(from)
    .bind(bucket_seconds)
    .bind(from)
    .bind(to)
    .fetch_all(pool)
    .await?;
    Ok(counts)
}

pub async fn list(pool: &SqlitePool, limit: i64, offset: i64) -> Result<Vec<AuditEntry>> {
    let entries = sqlx::query_as::<_, AuditEntry>(
        "SELECT seq, timestamp, actor_id, actor, action, target, detail, prev_hash, hash
         FROM audit_log ORDER BY seq DESC LIMIT ? OFFSET ?",
    )
    .bind(limit)
    .bind(offset)
    .fetch_all(pool)
    .await?;

    Ok(entries)
}

pub async fn first_broken_entry(pool: &SqlitePool) -> Result<Option<i64>> {
    let entries = sqlx::query_as::<_, AuditEntry>(
        "SELECT seq, timestamp, actor_id, actor, action, target, detail, prev_hash, hash
         FROM audit_log ORDER BY seq ASC",
    )
    .fetch_all(pool)
    .await?;

    let mut expected_prev = GENESIS_HASH.to_string();

    for entry in entries {
        let recomputed = entry_hash(&HashedFields {
            prev_hash: &expected_prev,
            timestamp: entry.timestamp,
            actor_id: entry.actor_id.as_deref(),
            actor: &entry.actor,
            action: &entry.action,
            target: entry.target.as_deref(),
            detail: &entry.detail,
        });

        if entry.prev_hash != expected_prev || entry.hash != recomputed {
            return Ok(Some(entry.seq));
        }

        expected_prev = entry.hash;
    }

    Ok(None)
}
