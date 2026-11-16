use chrono::Utc;
use sqlx::SqlitePool;

use crate::audit;
use crate::error::{AppError, Result};
use crate::signing::SigningService;

pub const ACCEPT_CHANGE_ENV: &str = "ZEDR_SIGNING_KEY_CHANGE_ACCEPTED";

#[derive(Debug, PartialEq, Eq)]
pub enum Outcome {
    Recorded,
    Unchanged,
    Changed { enrolled_agents: i64 },
}

pub async fn enforce(
    pool: &SqlitePool,
    signing_service: &SigningService,
    accepted_public_key: Option<&str>,
) -> Result<Outcome> {
    let current = hex::encode(signing_service.public_key());

    let recorded: Option<String> =
        sqlx::query_scalar("SELECT public_key FROM deployment_signing_key WHERE id = 1")
            .fetch_optional(pool)
            .await?;

    let Some(recorded) = recorded else {
        sqlx::query("INSERT INTO deployment_signing_key (id, public_key, recorded_at) VALUES (1, ?, ?)")
            .bind(&current)
            .bind(Utc::now().timestamp())
            .execute(pool)
            .await?;
        return Ok(Outcome::Recorded);
    };

    if recorded == current {
        return Ok(Outcome::Unchanged);
    }

    let enrolled_agents: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM agents WHERE public_key IS NOT NULL")
        .fetch_one(pool)
        .await?;

    let accepted = accepted_public_key.is_some_and(|key| key.trim().eq_ignore_ascii_case(&current));

    if enrolled_agents > 0 && !accepted {
        return Err(AppError::Config(format!(
            "ZEDR_SIGNING_KEY_HEX changed while agents are enrolled ({} enrolled). They trust public key {} and refuse every \
             command and upgrade signed by the new key, whose public key is {}. Restore the previous key, or reinstall \
             those agents and start with {}={}",
            enrolled_agents, recorded, current, ACCEPT_CHANGE_ENV, current
        )));
    }

    sqlx::query("UPDATE deployment_signing_key SET public_key = ?, recorded_at = ? WHERE id = 1")
        .bind(&current)
        .bind(Utc::now().timestamp())
        .execute(pool)
        .await?;

    audit::record(
        pool,
        None,
        "system",
        "signing_key.changed",
        None,
        serde_json::json!({
            "previous_public_key": recorded,
            "public_key": current,
            "enrolled_agents": enrolled_agents,
        }),
    )
    .await?;

    Ok(Outcome::Changed { enrolled_agents })
}
