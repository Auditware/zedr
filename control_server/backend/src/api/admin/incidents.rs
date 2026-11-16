use axum::{
    extract::{Path, Query, State},
    Json,
};
use serde::Deserialize;
use utoipa::{IntoParams, ToSchema};

use crate::api::AppState;
use crate::audit;
use crate::auth::AdminUser;
use crate::error::{AppError, Result};
use crate::incidents::{self, Incident};

#[derive(Deserialize, IntoParams, ToSchema)]
pub struct IncidentsQuery {
    #[serde(default)]
    open: bool,
    #[serde(default = "default_limit")]
    limit: i64,
}

fn default_limit() -> i64 {
    100
}

#[utoipa::path(
    get,
    path = "/api/admin/incidents",
    tag = "admin",
    params(IncidentsQuery),
    responses(
        (status = 200, description = "Tamper, silence and detection incidents, newest first", body = Vec<Incident>)
    )
)]
pub async fn list_incidents(
    State(state): State<AppState>,
    Query(query): Query<IncidentsQuery>,
) -> Result<Json<Vec<Incident>>> {
    let incidents = incidents::list(&state.pool, query.open, query.limit.clamp(1, 500)).await?;
    Ok(Json(incidents))
}

#[utoipa::path(
    post,
    path = "/api/admin/incidents/{id}/close",
    tag = "admin",
    params(("id" = String, Path, description = "Incident ID")),
    responses(
        (status = 200, description = "The incident, now closed", body = Incident),
        (status = 403, description = "Admin role required"),
        (status = 404, description = "No open incident with this ID")
    )
)]
pub async fn close_incident(
    State(state): State<AppState>,
    AdminUser(admin): AdminUser,
    Path(id): Path<String>,
) -> Result<Json<Incident>> {
    let closed = incidents::close_by_id(&state.pool, &state.system_events_tx, &id, &admin.username)
        .await?
        .ok_or(AppError::NotFound)?;

    audit::record_by(
        &state.pool,
        &admin,
        "incident.close",
        Some(&closed.id),
        serde_json::json!({ "agent_id": closed.agent_id, "incident_type": closed.incident_type }),
    )
    .await?;

    Ok(Json(closed))
}
