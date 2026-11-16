use axum::http::HeaderMap;
use ed25519_dalek::{Signature, VerifyingKey};
use sha2::{Digest, Sha256};
use sqlx::SqliteConnection;
use zedr_ledger::Hash;
use zedr_protocol::SIGNATURE_HEADER;

use crate::api::AppState;
use crate::error::{AppError, Result};
use crate::incidents;

const RETAINED_SESSIONS: i64 = 4;

pub struct AcceptedSequence {
    pub new_session: bool,
}

pub fn signature_header(headers: &HeaderMap) -> Option<&str> {
    headers.get(SIGNATURE_HEADER).and_then(|value| value.to_str().ok())
}

fn key_bytes(public_key_hex: &str) -> Option<[u8; 32]> {
    let mut key = [0u8; 32];
    hex::decode_to_slice(public_key_hex, &mut key).ok()?;
    Some(key)
}

/// Identifier of an agent inside its leaves and heads: the hash of its pinned public key
pub fn agent_hash(public_key_hex: &str) -> Option<Hash> {
    key_bytes(public_key_hex).map(|key| Sha256::digest(key).into())
}

pub fn signature_is_valid(public_key_hex: &str, body: &[u8], signature_hex: &str) -> bool {
    let Some(key_bytes) = key_bytes(public_key_hex) else {
        return false;
    };
    let Ok(public_key) = VerifyingKey::from_bytes(&key_bytes) else {
        return false;
    };
    let Ok(signature_bytes) = hex::decode(signature_hex) else {
        return false;
    };
    let Ok(signature) = Signature::from_slice(&signature_bytes) else {
        return false;
    };

    public_key.verify_strict(body, &signature).is_ok()
}

pub async fn accept_sequence(
    conn: &mut SqliteConnection,
    agent_id: &str,
    session: u64,
    seq: u64,
) -> Result<Option<AcceptedSequence>> {
    let (Ok(session), Ok(seq)) = (i64::try_from(session), i64::try_from(seq)) else {
        return Ok(None);
    };

    let newest: Option<i64> =
        sqlx::query_scalar("SELECT MAX(session) FROM agent_sessions WHERE agent_id = ?")
            .bind(agent_id)
            .fetch_one(&mut *conn)
            .await?;

    if let Some(newest) = newest {
        if session <= newest - RETAINED_SESSIONS {
            return Ok(None);
        }
    }

    let advanced = sqlx::query(
        "INSERT INTO agent_sessions (agent_id, session, last_seq) VALUES (?, ?, ?)
         ON CONFLICT(agent_id, session) DO UPDATE SET last_seq = excluded.last_seq
         WHERE excluded.last_seq > agent_sessions.last_seq",
    )
    .bind(agent_id)
    .bind(session)
    .bind(seq)
    .execute(&mut *conn)
    .await?
    .rows_affected()
        > 0;

    if !advanced {
        return Ok(None);
    }

    let new_session = newest.is_none_or(|newest| session > newest);

    if new_session {
        sqlx::query("DELETE FROM agent_sessions WHERE agent_id = ? AND session <= ?")
            .bind(agent_id)
            .bind(session - RETAINED_SESSIONS)
            .execute(&mut *conn)
            .await?;
    }

    Ok(Some(AcceptedSequence { new_session }))
}

/// Checks that a request was signed by the enrolled agent it names and was not seen before, and returns that agent's identifier inside its leaves and heads
pub async fn authenticate(state: &AppState, request: &str, agent_id: &str, session: u64, seq: u64, headers: &HeaderMap, body: &[u8]) -> Result<Hash> {
    let signature = signature_header(headers).ok_or(AppError::Unauthorized)?;

    let pinned_key: Option<String> = sqlx::query_scalar("SELECT public_key FROM agents WHERE id = ?")
        .bind(agent_id)
        .fetch_optional(&state.pool)
        .await?
        .flatten();
    let pinned_key = pinned_key.ok_or(AppError::Unauthorized)?;

    if !signature_is_valid(&pinned_key, body, signature) {
        return Err(AppError::Unauthorized);
    }
    let agent = agent_hash(&pinned_key).ok_or(AppError::Unauthorized)?;

    let mut conn = state.pool.acquire().await?;
    let accepted = accept_sequence(&mut conn, agent_id, session, seq).await?;
    drop(conn);

    if accepted.is_none() {
        incidents::open(
            &state.pool,
            &state.system_events_tx,
            agent_id,
            incidents::REPLAY,
            serde_json::json!({
                "request": request,
                "session": session,
                "seq": seq,
            }),
        )
        .await?;
        return Err(AppError::Conflict("Replayed or stale request".to_string()));
    }

    Ok(agent)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_the_agent_hash_is_the_sha256_of_the_raw_public_key() {
        let key = [7u8; 32];
        assert_eq!(agent_hash(&hex::encode(key)).map(hex::encode).as_deref(), Some("4bb06f8e4e3a7715d201d573d0aa423762e55dabd61a2c02278fa56cc6d294e0"));
        assert_ne!(agent_hash(&hex::encode(key)), agent_hash(&hex::encode([8u8; 32])));
        assert_eq!(agent_hash("abcd"), None);
        assert_eq!(agent_hash(&"zz".repeat(32)), None);
    }
}
