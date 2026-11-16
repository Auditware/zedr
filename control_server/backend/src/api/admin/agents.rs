use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    response::sse::{Event, Sse},
    Json,
};
use futures::stream::{Stream, StreamExt};
use serde::{Deserialize, Serialize};
use std::convert::Infallible;
use tokio_stream::wrappers::BroadcastStream;
use utoipa::{IntoParams, ToSchema};

use crate::api::AppState;
use crate::auth::{authenticate, session_ended, JwtSecret};
use crate::db::{models::Agent, queries};
use crate::error::Result;

#[derive(Deserialize, IntoParams, ToSchema)]
pub struct ListQuery {
    #[serde(default = "default_limit")]
    limit: i64,
    #[serde(default)]
    offset: i64,
}

fn default_limit() -> i64 {
    50
}

#[derive(Serialize, ToSchema)]
pub struct AgentsResponse {
    agents: Vec<Agent>,
}

#[utoipa::path(
    get,
    path = "/api/admin/agents",
    tag = "admin",
    params(ListQuery),
    responses(
        (status = 200, description = "List of agents", body = AgentsResponse)
    )
)]
pub async fn list_agents(
    State(state): State<AppState>,
    Query(query): Query<ListQuery>,
) -> Result<Json<AgentsResponse>> {
    let agents = queries::list_agents(&state.pool, query.limit, query.offset).await?;
    Ok(Json(AgentsResponse { agents }))
}

#[utoipa::path(
    get,
    path = "/api/admin/agents/{agent_id}",
    tag = "admin",
    params(
        ("agent_id" = String, Path, description = "Agent ID")
    ),
    responses(
        (status = 200, description = "Agent details", body = Agent),
        (status = 404, description = "Agent not found")
    )
)]
pub async fn get_agent(
    State(state): State<AppState>,
    Path(agent_id): Path<String>,
) -> Result<Json<Agent>> {
    let agent = queries::get_agent_by_id(&state.pool, &agent_id).await?;
    Ok(Json(agent))
}

#[derive(Deserialize)]
pub struct StreamQuery {
    token: String,
}

#[utoipa::path(
    get,
    path = "/api/admin/agents/stream",
    tag = "admin",
    params(
        ("token" = String, Query, description = "Auth token for SSE")
    ),
    responses(
        (status = 200, description = "Real-time agent event stream", content_type = "text/event-stream"),
        (status = 401, description = "Unauthorized")
    )
)]
pub async fn stream_agents(
    State(state): State<AppState>,
    Query(query): Query<StreamQuery>,
) -> std::result::Result<Sse<impl Stream<Item = Result<Event, Infallible>>>, (StatusCode, String)> {
    let secret = JwtSecret::from_env()
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e))?;
    authenticate(&state.pool, &query.token, &secret.0)
        .await
        .map_err(|_| (StatusCode::UNAUTHORIZED, "Invalid token".to_string()))?;
    let ended = session_ended(state.pool.clone(), query.token, secret.0);
    
    let rx = state.agent_events_tx.subscribe();
    let stream = BroadcastStream::new(rx).filter_map(|result| async move {
        match result {
            Ok(agent_event) => {
                let json = serde_json::to_string(&agent_event).ok()?;
                Some(Ok(Event::default().data(json)))
            }
            Err(_) => None,
        }
    })
    .take_until(ended);

    Ok(Sse::new(stream))
}
