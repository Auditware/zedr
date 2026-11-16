use axum::{body::Bytes, extract::State, http::HeaderMap, Json};
use chrono::Utc;
use sha2::{Digest, Sha256};
use sqlx::SqliteConnection;
use uuid::Uuid;

use crate::agent_auth;
use crate::api::{AgentEvent, AgentEventType, AppState};
use crate::enrollment::{self, FleetClaim, FleetToken};
use crate::error::{AppError, Result};
use crate::incidents;
use zedr_protocol::{AgentRegistration, AgentRegistrationResponse, InstallEvent};

enum Enrollment {
    None,
    InstallKey(String),
    FleetToken(FleetToken),
}

struct Refusal {
    reason: &'static str,
    token: Option<FleetToken>,
}

const REFUSED_NO_KEY: &str = "no enrollment key was presented";
const REFUSED_UNKNOWN_KEY: &str = "enrollment key is unknown, expired, revoked or already used";
const REFUSED_UNKNOWN_TOKEN: &str = "unknown";
const REFUSED_KEY_REPLACEMENT: &str = "a fleet enrollment token cannot replace the key of an enrolled agent";

#[utoipa::path(
    post,
    path = "/api/agents/register",
    tag = "agents",
    request_body = AgentRegistration,
    responses(
        (status = 200, description = "Agent registered successfully", body = AgentRegistrationResponse),
        (status = 401, description = "Missing or invalid signature, or enrollment not authorized"),
        (status = 409, description = "Replayed or stale request")
    )
)]
pub async fn register_agent(
    State(state): State<AppState>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Json<AgentRegistrationResponse>> {
    let registration: AgentRegistration = serde_json::from_slice(&body)
        .map_err(|e| AppError::BadRequest(format!("Invalid registration: {}", e)))?;

    let signature = agent_auth::signature_header(&headers).ok_or(AppError::Unauthorized)?;
    if !agent_auth::signature_is_valid(&registration.public_key, &body, signature) {
        return Err(AppError::Unauthorized);
    }

    let agent_id = registration.agent_id.clone();
    let now = Utc::now().timestamp();

    let existing: Option<(Option<String>,)> = sqlx::query_as("SELECT public_key FROM agents WHERE id = ?")
        .bind(&agent_id)
        .fetch_optional(&state.pool)
        .await?;
    let is_new_agent = existing.is_none();
    let pinned_key = existing.and_then(|(key,)| key);
    let key_matches = pinned_key.as_deref() == Some(registration.public_key.as_str());

    let mut tx = state.pool.begin().await?;

    let enrollment = match registration.enrollment_key.as_deref() {
        Some(token) if enrollment::is_fleet_token(token) => {
            if key_matches {
                Ok(Enrollment::None)
            } else if pinned_key.is_some() {
                Err(Refusal {
                    reason: REFUSED_KEY_REPLACEMENT,
                    token: enrollment::find_fleet_token(&mut tx, token).await?,
                })
            } else {
                match enrollment::claim_fleet_token(&mut tx, token, now).await? {
                    FleetClaim::Claimed(token) => Ok(Enrollment::FleetToken(token)),
                    FleetClaim::Refused { token, reason } => Err(Refusal { reason, token: Some(token) }),
                    FleetClaim::Unknown => Err(Refusal { reason: REFUSED_UNKNOWN_TOKEN, token: None }),
                }
            }
        }
        Some(key) => match claim_enrollment_key(&mut tx, key, &agent_id, now).await? {
            Some(install_key_id) => Ok(Enrollment::InstallKey(install_key_id)),
            None if key_matches => Ok(Enrollment::None),
            None => Err(Refusal { reason: REFUSED_UNKNOWN_KEY, token: None }),
        },
        None if key_matches => Ok(Enrollment::None),
        None => Err(Refusal { reason: REFUSED_NO_KEY, token: None }),
    };

    let enrollment = match enrollment {
        Ok(enrollment) => enrollment,
        Err(refusal) => {
            drop(tx);
            reject_enrollment(&state, &registration, pinned_key.is_some(), &refusal).await?;
            return Err(AppError::Unauthorized);
        }
    };

    let pinned = sqlx::query(
        "INSERT INTO agents (id, hostname, platform, os_version, architecture, version, ip_address, last_heartbeat, status, created_at, public_key)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
         ON CONFLICT(id) DO UPDATE SET
            hostname = excluded.hostname,
            platform = excluded.platform,
            os_version = excluded.os_version,
            architecture = excluded.architecture,
            version = excluded.version,
            ip_address = excluded.ip_address,
            last_heartbeat = excluded.last_heartbeat,
            status = excluded.status,
            public_key = excluded.public_key,
            liveness_state = 'active',
            stop_reason = NULL
         WHERE agents.public_key IS NULL OR agents.public_key = excluded.public_key OR ?"
    )
    .bind(&agent_id)
    .bind(&registration.hostname)
    .bind(&registration.platform)
    .bind(&registration.os_version)
    .bind(&registration.architecture)
    .bind(&registration.version)
    .bind(&registration.ip_address)
    .bind(now)
    .bind("online")
    .bind(now)
    .bind(&registration.public_key)
    .bind(matches!(enrollment, Enrollment::InstallKey(_)))
    .execute(&mut *tx)
    .await?
    .rows_affected()
        > 0;

    if !pinned {
        drop(tx);
        let refusal = Refusal { reason: REFUSED_KEY_REPLACEMENT, token: None };
        reject_enrollment(&state, &registration, true, &refusal).await?;
        return Err(AppError::Unauthorized);
    }

    match &enrollment {
        Enrollment::FleetToken(token) => {
            sqlx::query("UPDATE agents SET enrollment_token_id = ? WHERE id = ?")
                .bind(&token.id)
                .bind(&agent_id)
                .execute(&mut *tx)
                .await?;
        }
        Enrollment::InstallKey(_) => {
            sqlx::query("UPDATE agents SET enrollment_token_id = NULL WHERE id = ?")
                .bind(&agent_id)
                .execute(&mut *tx)
                .await?;
        }
        Enrollment::None => {}
    }

    if !key_matches {
        sqlx::query("DELETE FROM agent_sessions WHERE agent_id = ?")
            .bind(&agent_id)
            .execute(&mut *tx)
            .await?;
    }

    if agent_auth::accept_sequence(&mut tx, &agent_id, registration.session, registration.seq)
        .await?
        .is_none()
    {
        drop(tx);
        if !is_new_agent {
            incidents::open(
                &state.pool,
                &state.system_events_tx,
                &agent_id,
                incidents::REPLAY,
                serde_json::json!({
                    "request": "register",
                    "session": registration.session,
                    "seq": registration.seq,
                }),
            )
            .await?;
        }
        return Err(AppError::Conflict("Replayed or stale request".to_string()));
    }

    if let Enrollment::InstallKey(install_key_id) = &enrollment {
        sqlx::query(
            "INSERT INTO agent_installations (id, install_key_id, agent_id, installed_at, hostname, platform, ip_address)
             VALUES (?, ?, ?, ?, ?, ?, ?)"
        )
        .bind(Uuid::new_v4().to_string())
        .bind(install_key_id)
        .bind(&agent_id)
        .bind(now)
        .bind(&registration.hostname)
        .bind(&registration.platform)
        .bind(&registration.ip_address)
        .execute(&mut *tx)
        .await?;
    }

    if is_new_agent {
        let install_event = InstallEvent {
            timestamp: now as u64,
            version: registration.version.clone(),
            hostname: registration.hostname.clone(),
            platform: registration.platform.clone(),
            os_version: registration.os_version.clone(),
            architecture: registration.architecture.clone(),
        };
        let event_data = serde_json::to_string(&install_event)
            .map_err(|e| AppError::InternalError(format!("Failed to serialize install event: {}", e)))?;

        sqlx::query(
            "INSERT INTO events (id, agent_id, event_type, timestamp, data, received_at)
             VALUES (?, ?, 'install', ?, ?, ?)"
        )
        .bind(Uuid::new_v4().to_string())
        .bind(&agent_id)
        .bind(now)
        .bind(&event_data)
        .bind(now)
        .execute(&mut *tx)
        .await?;
    }

    tx.commit().await?;

    if !key_matches && !is_new_agent {
        incidents::record_event(
            &state.pool,
            &state.system_events_tx,
            Some(&agent_id),
            "identity_rotated",
            serde_json::json!({
                "hostname": registration.hostname,
                "ip_address": registration.ip_address,
                "install_key_id": match &enrollment {
                    Enrollment::InstallKey(id) => Some(id),
                    _ => None,
                },
                "enrollment_token_id": match &enrollment {
                    Enrollment::FleetToken(token) => Some(&token.id),
                    _ => None,
                },
            }),
        )
        .await?;
    }

    incidents::close(
        &state.pool,
        &state.system_events_tx,
        &agent_id,
        &[incidents::SILENCE, incidents::SERVICE_STOPPED, incidents::IDENTITY_CONFLICT],
    )
    .await?;

    let _ = state.agent_events_tx.send(AgentEvent {
        agent_id: agent_id.clone(),
        event_type: AgentEventType::Registered,
        timestamp: now,
    });

    if let Some(ref timeout_manager) = state.timeout_manager {
        timeout_manager.reset_timeout(agent_id.clone()).await;
    }

    Ok(Json(AgentRegistrationResponse {
        agent_id,
        registered_at: now,
    }))
}

async fn claim_enrollment_key(
    conn: &mut SqliteConnection,
    enrollment_key: &str,
    agent_id: &str,
    now: i64,
) -> Result<Option<String>> {
    let key_hash = format!("{:x}", Sha256::digest(enrollment_key.as_bytes()));

    let claimed: Option<String> = sqlx::query_scalar(
        "UPDATE install_keys SET enrolled_at = ?, enrolled_agent_id = ?
         WHERE key_hash = ? AND enrolled_at IS NULL AND revoked_at IS NULL AND expires_at > ?
         RETURNING id"
    )
    .bind(now)
    .bind(agent_id)
    .bind(key_hash)
    .bind(now)
    .fetch_optional(&mut *conn)
    .await?;

    Ok(claimed)
}

async fn reject_enrollment(
    state: &AppState,
    registration: &AgentRegistration,
    agent_has_pinned_key: bool,
    refusal: &Refusal,
) -> Result<()> {
    let token_id = refusal.token.as_ref().map(|token| token.id.as_str());
    let token_label = refusal.token.as_ref().map(|token| token.label.as_str());

    if agent_has_pinned_key {
        incidents::open(
            &state.pool,
            &state.system_events_tx,
            &registration.agent_id,
            incidents::IDENTITY_CONFLICT,
            serde_json::json!({
                "hostname": registration.hostname,
                "ip_address": registration.ip_address,
                "enrollment_key_presented": registration.enrollment_key.is_some(),
                "enrollment_token_id": token_id,
                "enrollment_group": token_label,
                "reason": refusal.reason,
            }),
        )
        .await?;
        return Ok(());
    }

    if registration.enrollment_key.is_some() {
        incidents::record_event(
            &state.pool,
            &state.system_events_tx,
            None,
            "enrollment_rejected",
            serde_json::json!({
                "claimed_agent_id": registration.agent_id,
                "hostname": registration.hostname,
                "ip_address": registration.ip_address,
                "enrollment_token_id": token_id,
                "enrollment_group": token_label,
                "reason": refusal.reason,
            }),
        )
        .await?;
    }

    Ok(())
}
