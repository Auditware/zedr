use axum::{body::Bytes, extract::State, http::HeaderMap, Json};
use zedr_protocol::{ProofAck, ProofSubmission};

use crate::agent_auth;
use crate::api::AppState;
use crate::error::{AppError, Result};
use crate::proofs;

#[utoipa::path(
    post,
    path = "/api/proofs",
    tag = "agents",
    request_body = ProofSubmission,
    responses(
        (status = 200, description = "The proof is accepted for these windows. They are verified when the proof says what the agent released, and marked as a mismatch when it does not", body = ProofAck),
        (status = 400, description = "Request that cannot be read"),
        (status = 401, description = "Missing or invalid signature, or unknown agent"),
        (status = 409, description = "Replayed or stale request"),
        (status = 422, description = "Receipt that does not verify, or a journal that contradicts the stored windows")
    )
)]
pub async fn submit_proof(
    State(state): State<AppState>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Json<ProofAck>> {
    let submission: ProofSubmission = serde_json::from_slice(&body)
        .map_err(|e| AppError::BadRequest(format!("Invalid proof submission: {}", e)))?;

    let agent = agent_auth::authenticate(&state, "proofs", &submission.agent_id, submission.session, submission.seq, &headers, &body).await?;

    proofs::accept(&state, &submission.agent_id, &agent, &submission.receipt)
        .await?
        .map(Json)
        .map_err(AppError::Unprocessable)
}
