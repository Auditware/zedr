use axum::http::HeaderMap;
use rand::RngCore;
use sha2::{Digest, Sha256};
use sqlx::{SqliteConnection, SqlitePool};

use crate::error::Result;

pub const KEY_HEADER: &str = "x-zedr-enrollment-key";
pub const FLEET_TOKEN_PREFIX: &str = "zedr_fleet_";

pub const REFUSED_EXPIRED: &str = "expired";
pub const REFUSED_REVOKED: &str = "revoked";
pub const REFUSED_EXHAUSTED: &str = "exhausted";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FleetToken {
    pub id: String,
    pub label: String,
}

pub enum Credential {
    InstallKey {
        id: String,
        agent_version: String,
        created_by: String,
        downloaded: bool,
    },
    FleetToken(FleetToken),
}

pub enum FleetClaim {
    Claimed(FleetToken),
    Refused { token: FleetToken, reason: &'static str },
    Unknown,
}

pub fn is_fleet_token(presented: &str) -> bool {
    presented.starts_with(FLEET_TOKEN_PREFIX)
}

pub fn hash(presented: &str) -> String {
    hex::encode(Sha256::digest(presented.as_bytes()))
}

pub fn generate_fleet_token() -> String {
    let mut secret = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut secret);
    format!("{}{}", FLEET_TOKEN_PREFIX, hex::encode(secret))
}

pub fn presented_key(headers: &HeaderMap, query_key: Option<&str>) -> Option<String> {
    headers
        .get(KEY_HEADER)
        .and_then(|value| value.to_str().ok())
        .or(query_key)
        .map(str::trim)
        .filter(|key| !key.is_empty())
        .map(str::to_string)
}

pub async fn usable_credential(pool: &SqlitePool, presented: &str, now: i64) -> Result<Option<Credential>> {
    if is_fleet_token(presented) {
        let token = sqlx::query_as::<_, (String, String)>(
            "SELECT id, label FROM enrollment_tokens
             WHERE token_hash = ? AND revoked_at IS NULL AND expires_at > ?
               AND (max_uses IS NULL OR use_count < max_uses)",
        )
        .bind(hash(presented))
        .bind(now)
        .fetch_optional(pool)
        .await?;

        return Ok(token.map(|(id, label)| Credential::FleetToken(FleetToken { id, label })));
    }

    let key = sqlx::query_as::<_, (String, String, String, Option<i64>)>(
        "SELECT id, agent_version, created_by, used_at FROM install_keys
         WHERE key_hash = ? AND revoked_at IS NULL AND expires_at > ?",
    )
    .bind(hash(presented))
    .bind(now)
    .fetch_optional(pool)
    .await?;

    Ok(key.map(|(id, agent_version, created_by, used_at)| Credential::InstallKey {
        id,
        agent_version,
        created_by,
        downloaded: used_at.is_some(),
    }))
}

pub async fn claim_fleet_token(conn: &mut SqliteConnection, presented: &str, now: i64) -> Result<FleetClaim> {
    let token_hash = hash(presented);

    let claimed = sqlx::query_as::<_, (String, String)>(
        "UPDATE enrollment_tokens SET use_count = use_count + 1, last_used_at = ?
         WHERE token_hash = ? AND revoked_at IS NULL AND expires_at > ?
           AND (max_uses IS NULL OR use_count < max_uses)
         RETURNING id, label",
    )
    .bind(now)
    .bind(&token_hash)
    .bind(now)
    .fetch_optional(&mut *conn)
    .await?;

    if let Some((id, label)) = claimed {
        return Ok(FleetClaim::Claimed(FleetToken { id, label }));
    }

    Ok(match refused_fleet_token(&mut *conn, presented, now).await? {
        Some((token, reason)) => FleetClaim::Refused { token, reason },
        None => FleetClaim::Unknown,
    })
}

pub async fn refused_fleet_token(
    conn: &mut SqliteConnection,
    presented: &str,
    now: i64,
) -> Result<Option<(FleetToken, &'static str)>> {
    let known = sqlx::query_as::<_, (String, String, i64, Option<i64>, Option<i64>, i64)>(
        "SELECT id, label, expires_at, revoked_at, max_uses, use_count FROM enrollment_tokens WHERE token_hash = ?",
    )
    .bind(hash(presented))
    .fetch_optional(&mut *conn)
    .await?;

    Ok(known.and_then(|(id, label, expires_at, revoked_at, max_uses, use_count)| {
        let reason = if revoked_at.is_some() {
            REFUSED_REVOKED
        } else if expires_at <= now {
            REFUSED_EXPIRED
        } else if max_uses.is_some_and(|max_uses| use_count >= max_uses) {
            REFUSED_EXHAUSTED
        } else {
            return None;
        };
        Some((FleetToken { id, label }, reason))
    }))
}

pub async fn find_fleet_token(conn: &mut SqliteConnection, presented: &str) -> Result<Option<FleetToken>> {
    let token = sqlx::query_as::<_, (String, String)>("SELECT id, label FROM enrollment_tokens WHERE token_hash = ?")
        .bind(hash(presented))
        .fetch_optional(&mut *conn)
        .await?;

    Ok(token.map(|(id, label)| FleetToken { id, label }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_fleet_tokens_are_long_random_and_recognisable() {
        let first = generate_fleet_token();
        let second = generate_fleet_token();

        assert!(is_fleet_token(&first));
        assert_eq!(first.len(), FLEET_TOKEN_PREFIX.len() + 64);
        assert_ne!(first, second);
        assert!(!is_fleet_token("zedr_0123456789abcdef"));
    }

    #[test]
    fn test_header_wins_over_query_and_blank_values_are_absent() {
        let mut headers = HeaderMap::new();
        assert_eq!(presented_key(&headers, Some("from-query")).as_deref(), Some("from-query"));
        assert_eq!(presented_key(&headers, None), None);
        assert_eq!(presented_key(&headers, Some("  ")), None);

        headers.insert(KEY_HEADER, " from-header ".parse().unwrap());
        assert_eq!(presented_key(&headers, Some("from-query")).as_deref(), Some("from-header"));
    }
}
