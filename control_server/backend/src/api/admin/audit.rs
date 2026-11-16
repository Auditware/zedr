use axum::{
    extract::{Query, State},
    Json,
};
use serde::{Deserialize, Serialize};
use utoipa::{IntoParams, ToSchema};

use crate::api::AppState;
use crate::audit::{self, AuditEntry};
use crate::auth::AdminUser;
use crate::error::Result;

#[derive(Deserialize, IntoParams, ToSchema)]
pub struct AuditQuery {
    #[serde(default = "default_limit")]
    limit: i64,
    #[serde(default)]
    offset: i64,
}

fn default_limit() -> i64 {
    100
}

#[derive(Serialize, ToSchema)]
pub struct AuditResponse {
    pub entries: Vec<AuditEntry>,
    pub chain_intact: bool,
    pub first_broken_seq: Option<i64>,
}

#[utoipa::path(
    get,
    path = "/api/admin/audit",
    tag = "admin",
    params(AuditQuery),
    responses(
        (status = 200, description = "Console activity, newest first, with hash-chain verification", body = AuditResponse),
        (status = 403, description = "Admin role required")
    )
)]
pub async fn list_audit(
    State(state): State<AppState>,
    AdminUser(_admin): AdminUser,
    Query(query): Query<AuditQuery>,
) -> Result<Json<AuditResponse>> {
    let entries = audit::list(&state.pool, query.limit.clamp(1, 500), query.offset.max(0)).await?;
    let first_broken_seq = audit::first_broken_entry(&state.pool).await?;

    Ok(Json(AuditResponse {
        entries,
        chain_intact: first_broken_seq.is_none(),
        first_broken_seq,
    }))
}
