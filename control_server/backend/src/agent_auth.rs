use axum::http::HeaderMap;
use ed25519_dalek::{Signature, VerifyingKey};
use sqlx::SqliteConnection;
use zedr_protocol::SIGNATURE_HEADER;

use crate::error::Result;

const RETAINED_SESSIONS: i64 = 4;

pub struct AcceptedSequence {
    pub new_session: bool,
}

pub fn signature_header(headers: &HeaderMap) -> Option<&str> {
    headers.get(SIGNATURE_HEADER).and_then(|value| value.to_str().ok())
}

pub fn signature_is_valid(public_key_hex: &str, body: &[u8], signature_hex: &str) -> bool {
    let Ok(key_bytes) = hex::decode(public_key_hex) else {
        return false;
    };
    let Ok(key_bytes) = <[u8; 32]>::try_from(key_bytes.as_slice()) else {
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
