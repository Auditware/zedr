use std::net::IpAddr;

use ipnet::Ipv6Net;
use sqlx::SqlitePool;
use tokio::sync::Mutex;

use crate::error::{AppError, Result};

pub const LOCKED: &str = "auth.locked";

const WINDOW_SECS: i64 = 3600;
const FIRST_WAIT_SECS: i64 = 60;
const LONGEST_WAIT_SECS: i64 = 900;
const ACCOUNT_FAILURES_BEFORE_WAIT: i64 = 5;
const ADDRESS_FAILURES_BEFORE_WAIT: i64 = 20;
const MAX_ACCOUNT_CHARS: usize = 64;
const IPV6_HOST_PREFIX: u8 = 64;

static RESERVE_LOCK: Mutex<()> = Mutex::const_new(());

/// Whose budget a password or code check spends: the account it was tried for, or the address it came from
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Subject {
    Account(String),
    Address(String),
}

impl Subject {
    pub fn account(username: &str) -> Self {
        Subject::Account(username.chars().take(MAX_ACCOUNT_CHARS).collect())
    }

    pub fn address(peer: Option<IpAddr>) -> Self {
        Subject::Address(match peer.map(|ip| ip.to_canonical()) {
            Some(IpAddr::V4(v4)) => v4.to_string(),
            Some(IpAddr::V6(v6)) => Ipv6Net::new(v6, IPV6_HOST_PREFIX).expect("a /64 is a valid IPv6 prefix").trunc().to_string(),
            None => "unknown".to_string(),
        })
    }

    fn scope(&self) -> &'static str {
        match self {
            Subject::Account(_) => "account",
            Subject::Address(_) => "address",
        }
    }

    fn name(&self) -> &str {
        match self {
            Subject::Account(name) | Subject::Address(name) => name,
        }
    }

    fn failures_before_wait(&self) -> i64 {
        match self {
            Subject::Account(_) => ACCOUNT_FAILURES_BEFORE_WAIT,
            Subject::Address(_) => ADDRESS_FAILURES_BEFORE_WAIT,
        }
    }

    fn wait_after(&self, failures: i64) -> i64 {
        let over = failures - self.failures_before_wait();
        if over < 0 {
            return 0;
        }
        (FIRST_WAIT_SECS << over.min(16)).min(LONGEST_WAIT_SECS)
    }
}

/// A check that was counted as a failure before it ran, so parallel guesses see each other
pub struct Attempt {
    reserved: Vec<Reserved>,
}

struct Reserved {
    subject: Subject,
    row: i64,
    failures: i64,
}

/// A wait that a failure started or made longer
pub struct Lock {
    subject: Subject,
    failures: i64,
    wait_secs: i64,
}

impl Lock {
    pub fn detail(&self) -> serde_json::Value {
        serde_json::json!({
            "scope": self.subject.scope(),
            "subject": self.subject.name(),
            "failures": self.failures,
            "retry_after": self.wait_secs,
        })
    }
}

fn now() -> i64 {
    chrono::Utc::now().timestamp()
}

/// Refuses with the longest wait among the subjects, or counts the attempt as a failure of each of them until it is settled
pub async fn begin(pool: &SqlitePool, subjects: &[Subject]) -> Result<Attempt> {
    let _guard = RESERVE_LOCK.lock().await;
    let now = now();

    sqlx::query("DELETE FROM auth_failures WHERE at <= ?")
        .bind(now - WINDOW_SECS)
        .execute(pool)
        .await?;

    let mut counted = Vec::with_capacity(subjects.len());
    let mut retry_after = 0;
    for subject in subjects {
        let (failures, latest): (i64, Option<i64>) = sqlx::query_as("SELECT COUNT(*), MAX(at) FROM auth_failures WHERE scope = ? AND subject = ?")
            .bind(subject.scope())
            .bind(subject.name())
            .fetch_one(pool)
            .await?;
        if let Some(latest) = latest {
            retry_after = retry_after.max(latest + subject.wait_after(failures) - now);
        }
        counted.push(failures);
    }
    if retry_after > 0 {
        return Err(AppError::TooManyAttempts(retry_after as u64));
    }

    let mut reserved = Vec::with_capacity(subjects.len());
    for (subject, failures) in subjects.iter().zip(counted) {
        let row = sqlx::query_scalar("INSERT INTO auth_failures (scope, subject, at) VALUES (?, ?, ?) RETURNING id")
            .bind(subject.scope())
            .bind(subject.name())
            .bind(now)
            .fetch_one(pool)
            .await?;
        reserved.push(Reserved { subject: subject.clone(), row, failures: failures + 1 });
    }

    Ok(Attempt { reserved })
}

/// Forgets the failures of a subject, as a changed password makes the guesses at the old one moot
pub async fn forget(pool: &SqlitePool, subject: &Subject) -> Result<()> {
    sqlx::query("DELETE FROM auth_failures WHERE scope = ? AND subject = ?")
        .bind(subject.scope())
        .bind(subject.name())
        .execute(pool)
        .await?;
    Ok(())
}

impl Attempt {
    /// Keeps the attempt counted and returns the waits it started or made longer
    pub fn failed(self) -> Vec<Lock> {
        self.reserved
            .into_iter()
            .filter_map(|reserved| {
                let wait_secs = reserved.subject.wait_after(reserved.failures);
                (wait_secs > 0).then_some(Lock { subject: reserved.subject, failures: reserved.failures, wait_secs })
            })
            .collect()
    }

    /// Takes the attempt back and leaves the earlier failures counted, as a right password does while its code is still to come
    pub async fn passed(self, pool: &SqlitePool) -> Result<()> {
        for reserved in &self.reserved {
            sqlx::query("DELETE FROM auth_failures WHERE id = ?")
                .bind(reserved.row)
                .execute(pool)
                .await?;
        }
        Ok(())
    }

    /// Takes the attempt back and forgets the account's failures, an address keeps its own
    pub async fn succeeded(self, pool: &SqlitePool) -> Result<()> {
        for reserved in &self.reserved {
            match reserved.subject {
                Subject::Account(_) => forget(pool, &reserved.subject).await?,
                Subject::Address(_) => {
                    sqlx::query("DELETE FROM auth_failures WHERE id = ?")
                        .bind(reserved.row)
                        .execute(pool)
                        .await?;
                }
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_the_wait_starts_after_the_free_failures_and_doubles_up_to_fifteen_minutes() {
        let account = Subject::account("admin");
        let waits: Vec<i64> = (1..=10).map(|failures| account.wait_after(failures)).collect();
        assert_eq!(waits, vec![0, 0, 0, 0, 60, 120, 240, 480, 900, 900]);
        assert_eq!(account.wait_after(i64::from(u16::MAX)), 900);

        let address = Subject::address(Some("203.0.113.9".parse().unwrap()));
        assert_eq!(address.wait_after(19), 0);
        assert_eq!(address.wait_after(20), 60);
    }

    #[test]
    fn test_an_ipv6_host_is_counted_by_its_slash_64_and_a_mapped_ipv4_as_ipv4() {
        let one = Subject::address(Some("2001:db8:1:2:aaaa::1".parse().unwrap()));
        let same_host = Subject::address(Some("2001:db8:1:2:ffff::9".parse().unwrap()));
        let other_host = Subject::address(Some("2001:db8:1:3::1".parse().unwrap()));
        assert_eq!(one, same_host);
        assert_ne!(one, other_host);
        assert_eq!(one.name(), "2001:db8:1:2::/64");

        assert_eq!(Subject::address(Some("::ffff:203.0.113.9".parse().unwrap())).name(), "203.0.113.9");
        assert_eq!(Subject::address(None).name(), "unknown");
    }

    #[test]
    fn test_an_account_is_counted_by_the_username_as_typed_up_to_the_longest_username() {
        assert_ne!(Subject::account("admin"), Subject::account("Admin"));
        assert_eq!(Subject::account(&"a".repeat(500)).name().chars().count(), MAX_ACCOUNT_CHARS);
    }
}
