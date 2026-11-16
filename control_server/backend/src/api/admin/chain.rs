use axum::{
    extract::{Path, Query, State},
    Json,
};
use serde::{Deserialize, Serialize};
use utoipa::{IntoParams, ToSchema};
use zedr_protocol::{hash_to_hex, SealedWindowHeader};
use zedr_rules::RuleId;

use crate::api::AppState;
use crate::chain;
use crate::error::{AppError, Result};

const DEFAULT_WINDOWS: i64 = 60;
const MAX_WINDOWS: i64 = 500;

#[derive(Deserialize, IntoParams, ToSchema)]
pub struct ChainQuery {
    /// How many of the most recent windows to return, at most 500
    #[serde(default = "default_windows")]
    limit: i64,
}

fn default_windows() -> i64 {
    DEFAULT_WINDOWS
}

#[derive(Serialize, ToSchema)]
pub struct ChainTotals {
    pub windows: i64,
    pub events: i64,
    pub opened: i64,
    pub gaps: i64,
}

#[derive(Serialize, sqlx::FromRow, ToSchema)]
pub struct WindowSummary {
    pub window: i64,
    pub epoch: i64,
    pub first_index: i64,
    pub count: i64,
    pub opened: i64,
    pub fresh: bool,
    pub gap: bool,
    pub received_at: i64,
    /// pending, verified, mismatch, or none when the endpoint has no prover
    pub proof: String,
}

#[derive(Serialize, ToSchema)]
pub struct ChainView {
    pub epoch: u64,
    pub next_window: u64,
    pub next_index: u64,
    pub head: String,
    pub proven_window: Option<u64>,
    pub totals: ChainTotals,
    /// The most recent windows, newest first
    pub windows: Vec<WindowSummary>,
}

async fn require_agent(state: &AppState, agent_id: &str) -> Result<()> {
    let known: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM agents WHERE id = ?)").bind(agent_id).fetch_one(&state.pool).await?;
    if known {
        Ok(())
    } else {
        Err(AppError::NotFound)
    }
}

#[utoipa::path(
    get,
    path = "/api/admin/agents/{id}/chain",
    tag = "admin",
    params(("id" = String, Path, description = "Agent ID"), ChainQuery),
    responses(
        (status = 200, description = "Where the stored chain of sealed windows of an agent stands, with its most recent windows", body = ChainView),
        (status = 404, description = "Agent not found")
    )
)]
pub async fn agent_chain(State(state): State<AppState>, Path(agent_id): Path<String>, Query(query): Query<ChainQuery>) -> Result<Json<ChainView>> {
    require_agent(&state, &agent_id).await?;
    let position = chain::position(&state.pool, &agent_id).await?;

    let (opened, gaps): (i64, i64) = sqlx::query_as(
        "SELECT (SELECT COUNT(*) FROM sealed_events WHERE agent_id = ? AND opened_at IS NOT NULL),
                (SELECT COUNT(*) FROM sealed_windows WHERE agent_id = ? AND gap = 1)",
    )
    .bind(&agent_id)
    .bind(&agent_id)
    .fetch_one(&state.pool)
    .await?;

    let windows = sqlx::query_as::<_, WindowSummary>(
        "SELECT w.window, w.epoch, w.first_index, w.count, w.fresh, w.gap, w.received_at, w.proof,
                (SELECT COUNT(*) FROM sealed_events e WHERE e.agent_id = w.agent_id AND e.window = w.window AND e.opened_at IS NOT NULL) AS opened
         FROM sealed_windows w WHERE w.agent_id = ? ORDER BY w.window DESC LIMIT ?",
    )
    .bind(&agent_id)
    .bind(query.limit.clamp(1, MAX_WINDOWS))
    .fetch_all(&state.pool)
    .await?;

    Ok(Json(ChainView {
        epoch: position.epoch,
        next_window: position.next_window,
        next_index: position.next_index,
        head: position.head,
        proven_window: position.proven_window,
        totals: ChainTotals { windows: position.next_window as i64, events: position.next_index as i64, opened, gaps },
        windows,
    }))
}

#[derive(Serialize, sqlx::FromRow, ToSchema)]
pub struct SealedEventView {
    pub index: i64,
    pub leaf: String,
    pub ciphertext_bytes: i64,
    pub opened: bool,
    /// The plaintext event this one was opened as
    #[serde(skip_serializing_if = "Option::is_none")]
    pub event_id: Option<String>,
}

#[derive(Serialize, ToSchema)]
pub struct ReleaseView {
    pub trigger: i64,
    pub rule: String,
    pub title: String,
    pub technique: String,
    pub level: String,
    pub context: Vec<u64>,
    pub proven: bool,
}

#[derive(Serialize, ToSchema)]
pub struct WindowView {
    pub header: SealedWindowHeader,
    pub received_at: i64,
    pub proving: bool,
    pub proof: String,
    pub events: Vec<SealedEventView>,
    pub releases: Vec<ReleaseView>,
}

#[derive(sqlx::FromRow)]
struct StoredWindow {
    epoch: i64,
    first_index: i64,
    count: i64,
    fresh: bool,
    gap: bool,
    prev_head: String,
    root: String,
    head: String,
    received_at: i64,
    proving: bool,
    proof: String,
}

#[utoipa::path(
    get,
    path = "/api/admin/agents/{id}/windows/{window}",
    tag = "admin",
    params(("id" = String, Path, description = "Agent ID"), ("window" = u64, Path, description = "Window number")),
    responses(
        (status = 200, description = "One sealed window: its header, its sealed events and what was released in it", body = WindowView),
        (status = 404, description = "The server holds no such window of this agent")
    )
)]
pub async fn agent_window(State(state): State<AppState>, Path((agent_id, window)): Path<(String, i64)>) -> Result<Json<WindowView>> {
    let stored = sqlx::query_as::<_, StoredWindow>(
        "SELECT epoch, first_index, count, fresh, gap, prev_head, root, head, received_at, proving, proof FROM sealed_windows WHERE agent_id = ? AND window = ?",
    )
    .bind(&agent_id)
    .bind(window)
    .fetch_optional(&state.pool)
    .await?
    .ok_or(AppError::NotFound)?;

    let events = sqlx::query_as::<_, SealedEventView>(
        "SELECT idx AS \"index\", leaf, LENGTH(ciphertext) AS ciphertext_bytes, opened_at IS NOT NULL AS opened, event_id FROM sealed_events WHERE agent_id = ? AND window = ? ORDER BY idx",
    )
    .bind(&agent_id)
    .bind(window)
    .fetch_all(&state.pool)
    .await?;

    let released: Vec<(i64, String, String, bool)> = sqlx::query_as("SELECT trigger_idx, rule, context, proven FROM releases WHERE agent_id = ? AND window = ? ORDER BY trigger_idx, rule")
        .bind(&agent_id)
        .bind(window)
        .fetch_all(&state.pool)
        .await?;
    let releases = released
        .into_iter()
        .map(|(trigger, rule, context, proven)| {
            let context = serde_json::from_str(&context).map_err(|e| AppError::InternalError(format!("Stored release context is damaged: {}", e)))?;
            let known = RuleId::from_id(&rule);
            Ok(ReleaseView {
                trigger,
                title: known.map(RuleId::title).unwrap_or_default().to_string(),
                technique: known.map(RuleId::technique).unwrap_or_default().to_string(),
                level: known.map(|rule| rule.level().as_str()).unwrap_or_default().to_string(),
                rule,
                context,
                proven,
            })
        })
        .collect::<Result<Vec<_>>>()?;

    Ok(Json(WindowView {
        header: SealedWindowHeader {
            epoch: stored.epoch as u64,
            window: window as u64,
            first_index: stored.first_index as u64,
            count: stored.count as u32,
            fresh: stored.fresh,
            gap: stored.gap,
            prev_head: stored.prev_head,
            root: stored.root,
            head: stored.head,
        },
        received_at: stored.received_at,
        proving: stored.proving,
        proof: stored.proof,
        events,
        releases,
    }))
}

#[derive(Serialize, ToSchema)]
pub struct RuleView {
    pub id: String,
    pub title: String,
    pub technique: String,
    pub level: String,
    /// What a match of this rule lets the server open
    pub opens: String,
    pub releases: i64,
}

#[derive(Serialize, ToSchema)]
pub struct RulesetView {
    /// The proof programs this server accepts receipts of, none means no proof can be accepted
    pub image_ids: Vec<String>,
    pub rules: Vec<RuleView>,
}

#[utoipa::path(
    get,
    path = "/api/admin/ruleset",
    tag = "admin",
    responses((status = 200, description = "The rules endpoints run and the proof programs this server accepts", body = RulesetView))
)]
pub async fn ruleset(State(state): State<AppState>) -> Result<Json<RulesetView>> {
    let released: Vec<(String, i64)> = sqlx::query_as("SELECT rule, COUNT(*) FROM releases GROUP BY rule").fetch_all(&state.pool).await?;

    let rules = RuleId::ALL
        .into_iter()
        .map(|rule| RuleView {
            id: rule.id().to_string(),
            title: rule.title().to_string(),
            technique: rule.technique().to_string(),
            level: rule.level().as_str().to_string(),
            opens: rule.opens().as_str().to_string(),
            releases: released.iter().find(|(id, _)| id == rule.id()).map(|(_, count)| *count).unwrap_or(0),
        })
        .collect();

    Ok(Json(RulesetView { image_ids: state.receipt_verifier.image_ids().iter().map(hash_to_hex).collect(), rules }))
}
