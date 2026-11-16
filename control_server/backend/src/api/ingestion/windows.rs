use axum::{
    body::Bytes,
    extract::State,
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    Json,
};
use zedr_protocol::{ChainPosition, SealedWindow, SealedWindowAck};

use crate::agent_auth;
use crate::api::AppState;
use crate::chain::{self, Admission};
use crate::error::{AppError, Result};

/// Largest request body the control server reads on the window endpoint
pub const MAX_WINDOW_BYTES: usize = 16 * 1024 * 1024;

#[utoipa::path(
    post,
    path = "/api/windows",
    tag = "agents",
    request_body = SealedWindow,
    responses(
        (status = 200, description = "The server holds the window, the acknowledgement is signed with the deployment key", body = SealedWindowAck),
        (status = 400, description = "Request that cannot be read, nothing is stored"),
        (status = 401, description = "Missing or invalid signature, or unknown agent"),
        (status = 409, description = "The window does not continue the stored chain, answered with where that chain stands, signed for this request. Also a replayed or stale request", body = ChainPosition),
        (status = 413, description = "Window larger than MAX_WINDOW_BYTES, nothing is stored"),
        (status = 422, description = "Window that is malformed or does not match its own header, nothing is stored")
    )
)]
pub async fn ingest_window(
    State(state): State<AppState>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Response> {
    let window: SealedWindow = serde_json::from_slice(&body)
        .map_err(|e| AppError::BadRequest(format!("Invalid sealed window: {}", e)))?;

    let agent = agent_auth::authenticate(&state, "windows", &window.agent_id, window.session, window.seq, &headers, &body).await?;

    match chain::admit(&state, &agent, &window).await? {
        Admission::Malformed(reason) => Err(AppError::Unprocessable(reason)),
        Admission::Refused(position) => {
            let signature = state.signing_service.sign_chain_position(
                &window.agent_id,
                window.session,
                window.seq,
                position.next_window,
                position.next_index,
                &position.head,
            )?;
            let position = ChainPosition {
                next_window: position.next_window,
                next_index: position.next_index,
                head: position.head,
                signature: signature.to_bytes().to_vec(),
            };
            Ok((StatusCode::CONFLICT, Json(position)).into_response())
        }
        Admission::Held { next_index, head } => {
            let signature = state.signing_service.sign_window_ack(&window.agent_id, window.header.window, next_index, &head)?;
            Ok(Json(SealedWindowAck { window: window.header.window, next_index, head, signature: signature.to_bytes().to_vec() }).into_response())
        }
    }
}
