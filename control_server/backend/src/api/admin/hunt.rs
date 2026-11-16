use axum::{
    extract::State,
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

use crate::api::AppState;
use crate::error::Result;
use crate::hunt::{self, HuntEntity, HuntResult};

#[derive(Debug, Deserialize, ToSchema)]
pub struct HuntRequest {
    pub query: String,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct HuntQueryError {
    pub error: String,
    pub column: usize,
}

#[utoipa::path(
    get,
    path = "/api/admin/hunt/fields",
    tag = "admin",
    responses((status = 200, description = "The kinds of record a hunt can ask for and the fields of each", body = Vec<HuntEntity>))
)]
pub async fn hunt_fields() -> Json<Vec<HuntEntity>> {
    Json(hunt::entities())
}

#[utoipa::path(
    post,
    path = "/api/admin/hunt",
    tag = "admin",
    request_body = HuntRequest,
    responses(
        (status = 200, description = "Matching records across every endpoint, newest first, with a count per endpoint", body = HuntResult),
        (status = 400, description = "The query could not be read", body = HuntQueryError)
    )
)]
pub async fn hunt(State(state): State<AppState>, Json(request): Json<HuntRequest>) -> Result<Response> {
    let refused = |error: hunt::QueryError| {
        (StatusCode::BAD_REQUEST, Json(HuntQueryError { error: error.message, column: error.column })).into_response()
    };

    let query = match hunt::parse(&request.query) {
        Ok(query) => query,
        Err(error) => return Ok(refused(error)),
    };
    Ok(match hunt::run(&state.pool, &query).await? {
        Ok(result) => Json(result).into_response(),
        Err(error) => refused(error),
    })
}
