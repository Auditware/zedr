use axum::{
    extract::{Query, State},
    http::StatusCode,
    response::sse::{Event as SseEvent, KeepAlive, Sse},
    Extension, Json,
};
use futures::stream::{Stream, StreamExt};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::convert::Infallible;
use utoipa::{IntoParams, ToSchema};

use crate::api::AppState;
use crate::audit;
use crate::auth::{authenticate, session_ended, JwtSecret, User, ROLE_ADMIN};
use crate::db::{models::Event, queries};
use crate::error::{AppError, Result};

const DEFAULT_BUCKETS: i64 = 60;
const MAX_BUCKETS: i64 = 240;
const MAX_HISTOGRAM_SECONDS: i64 = 366 * 24 * 60 * 60;
const AUDIT_SERIES: &str = "audit";

#[derive(Deserialize, IntoParams, ToSchema)]
pub struct EventsQuery {
    agent_id: Option<String>,
    #[serde(default)]
    event_types: Option<String>,
    /// Earliest event time to return, in Unix seconds
    from: Option<i64>,
    /// Latest event time to return, in Unix seconds
    to: Option<i64>,
    #[serde(default = "default_limit")]
    limit: i64,
    #[serde(default)]
    offset: i64,
}

fn default_limit() -> i64 {
    100
}

#[derive(Serialize, ToSchema)]
pub struct EventStats {
    pub process: i64,
    pub file: i64,
    pub network: i64,
    pub heartbeat: i64,
    pub upgrade: i64,
    pub install: i64,
    pub shell_session_created: i64,
    pub shell_session_terminated: i64,
    pub incident: i64,
}

#[utoipa::path(
    get,
    path = "/api/admin/events/stats",
    tag = "admin",
    responses(
        (status = 200, description = "Event statistics", body = EventStats)
    )
)]
pub async fn event_stats(
    State(state): State<AppState>,
) -> Result<Json<EventStats>> {
    let stats = queries::get_event_stats(&state.pool).await?;
    Ok(Json(stats))
}

#[utoipa::path(
    get,
    path = "/api/admin/events",
    tag = "admin",
    params(EventsQuery),
    responses(
        (status = 200, description = "List of events", body = Vec<Event>)
    )
)]
pub async fn list_events(
    State(state): State<AppState>,
    Query(query): Query<EventsQuery>,
) -> Result<Json<Vec<Event>>> {
    let event_types = query.event_types
        .map(|s| s.split(',').map(|t| t.trim().to_string()).collect::<Vec<_>>());
    let filter = queries::EventFilter {
        agent_id: query.agent_id.as_deref(),
        event_types: event_types.as_deref(),
        from: query.from,
        to: query.to,
    };

    let events = queries::list_events(&state.pool, &filter, query.limit, query.offset).await?;
    Ok(Json(events))
}

fn default_buckets() -> i64 {
    DEFAULT_BUCKETS
}

#[derive(Deserialize, IntoParams, ToSchema)]
pub struct HistogramQuery {
    /// Start of the period, in Unix seconds
    from: i64,
    /// End of the period, in Unix seconds, not included
    to: i64,
    #[serde(default = "default_buckets")]
    buckets: i64,
    agent_id: Option<String>,
}

#[derive(Serialize, ToSchema)]
pub struct EventSeries {
    pub event_type: String,
    pub counts: Vec<i64>,
}

#[derive(Serialize, ToSchema)]
pub struct EventHistogram {
    pub from: i64,
    pub bucket_seconds: i64,
    pub buckets: i64,
    pub series: Vec<EventSeries>,
}

#[utoipa::path(
    get,
    path = "/api/admin/events/histogram",
    tag = "admin",
    params(HistogramQuery),
    responses(
        (status = 200, description = "Events per type in equal time buckets. Admins also get console activity as the audit series when no endpoint is named", body = EventHistogram),
        (status = 400, description = "The period is empty or longer than a year")
    )
)]
pub async fn event_histogram(
    State(state): State<AppState>,
    Extension(user): Extension<User>,
    Query(query): Query<HistogramQuery>,
) -> Result<Json<EventHistogram>> {
    let span = query
        .to
        .checked_sub(query.from)
        .filter(|span| (1..=MAX_HISTOGRAM_SECONDS).contains(span))
        .ok_or_else(|| AppError::BadRequest("the period must end after it starts and span at most a year".to_string()))?;
    let wanted = query.buckets.clamp(1, MAX_BUCKETS);
    let bucket_seconds = (span + wanted - 1) / wanted;
    let buckets = (span + bucket_seconds - 1) / bucket_seconds;

    let mut counted = queries::event_histogram(&state.pool, query.from, query.to, bucket_seconds, query.agent_id.as_deref()).await?;
    if user.role == ROLE_ADMIN && query.agent_id.is_none() {
        let console = audit::histogram(&state.pool, query.from, query.to, bucket_seconds).await?;
        counted.extend(console.into_iter().map(|(bucket, count)| (AUDIT_SERIES.to_string(), bucket, count)));
    }

    let mut series: BTreeMap<String, Vec<i64>> = BTreeMap::new();
    for (event_type, bucket, count) in counted {
        series.entry(event_type).or_insert_with(|| vec![0; buckets as usize])[bucket as usize] = count;
    }

    Ok(Json(EventHistogram {
        from: query.from,
        bucket_seconds,
        buckets,
        series: series.into_iter().map(|(event_type, counts)| EventSeries { event_type, counts }).collect(),
    }))
}

#[derive(Deserialize)]
pub struct StreamQuery {
    token: String,
}

pub async fn stream_events(
    State(state): State<AppState>,
    Query(query): Query<StreamQuery>,
) -> std::result::Result<Sse<impl Stream<Item = std::result::Result<SseEvent, Infallible>>>, (StatusCode, String)> {
    let secret = JwtSecret::from_env()
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e))?;
    authenticate(&state.pool, &query.token, &secret.0)
        .await
        .map_err(|_| (StatusCode::UNAUTHORIZED, "Invalid token".to_string()))?;
    let ended = session_ended(state.pool.clone(), query.token, secret.0);
    
    let rx = state.system_events_tx.subscribe();
    
    let stream = tokio_stream::wrappers::BroadcastStream::new(rx)
        .filter_map(|result| async move {
            match result {
                Ok(event) => {
                    let json = serde_json::to_string(&event).ok()?;
                    Some(Ok(SseEvent::default().data(json)))
                }
                Err(_) => None,
            }
        })
        .take_until(ended);

    Ok(Sse::new(stream).keep_alive(KeepAlive::default()))
}
