use std::collections::BTreeSet;
use std::time::Duration;

use chrono::Utc;
use risc0_zkvm::{Receipt, VerifierContext};
use sqlx::{SqliteConnection, SqlitePool};
use tokio::sync::broadcast;
use zedr_ledger::{Hash, GENESIS};
use zedr_protocol::{bytes_from_base64, hash_from_hex, hash_to_hex, ProofAck};
use zedr_rules::proof::{Journal, JOURNAL_VERSION};

use crate::api::{AppState, SystemEventBroadcast};
use crate::chain::{self, NUMBER_LIMIT, PROOF_MISMATCH, PROOF_PENDING, PROOF_VERIFIED};
use crate::detections::INCIDENT_PREFIX;
use crate::error::{AppError, Refusal, Result};
use crate::incidents;
use crate::liveness;

pub const IMAGE_IDS_ENV: &str = "ZEDR_GUEST_IMAGE_IDS";
pub const DEADLINE_ENV: &str = "ZEDR_PROOF_DEADLINE_SECS";
const DEFAULT_DEADLINE_SECS: i64 = 3600;
const SWEEP_INTERVAL: Duration = Duration::from_secs(60);

/// A receipt that verified: the rule program it is about, and what that program made public
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Verified {
    pub image_id: Hash,
    pub journal: Vec<u8>,
}

pub trait ReceiptVerifier: Send + Sync {
    fn verify(&self, receipt: &[u8]) -> std::result::Result<Verified, String>;

    /// The rule programs a receipt may be about
    fn image_ids(&self) -> Vec<Hash>;
}

pub fn parse_image_ids(raw: &str) -> std::result::Result<Vec<Hash>, String> {
    raw.split(',')
        .map(str::trim)
        .filter(|entry| !entry.is_empty())
        .map(|entry| hash_from_hex(entry).map_err(|_| format!("Invalid image ID in {}: {}", IMAGE_IDS_ENV, entry)))
        .collect()
}

/// Checks receipts of the proof program against the image IDs this deployment accepts
pub struct Risc0Verifier {
    image_ids: Vec<Hash>,
}

impl Risc0Verifier {
    pub fn new(image_ids: Vec<Hash>) -> Self {
        Self { image_ids }
    }

    pub fn from_env() -> std::result::Result<Self, String> {
        parse_image_ids(&std::env::var(IMAGE_IDS_ENV).unwrap_or_default()).map(Self::new)
    }
}

impl ReceiptVerifier for Risc0Verifier {
    fn verify(&self, receipt: &[u8]) -> std::result::Result<Verified, String> {
        let receipt: Receipt = bincode::deserialize(receipt).map_err(|e| format!("Not a receipt: {}", e))?;
        // The default parameters with development mode off, whatever RISC0_DEV_MODE says in this process's environment
        let context = VerifierContext::empty()
            .with_suites(VerifierContext::default_hash_suites())
            .with_segment_verifier_parameters(Default::default())
            .with_succinct_verifier_parameters(Default::default())
            .with_groth16_verifier_parameters(Default::default());
        let image_id = self
            .image_ids
            .iter()
            .find(|image_id| receipt.verify_with_context(&context, **image_id).is_ok())
            .ok_or_else(|| "The receipt does not verify against an accepted rule program".to_string())?;
        Ok(Verified { image_id: *image_id, journal: receipt.journal.bytes })
    }

    fn image_ids(&self) -> Vec<Hash> {
        self.image_ids.clone()
    }
}

#[derive(sqlx::FromRow)]
struct Covered {
    epoch: i64,
    first_index: i64,
    count: i64,
    fresh: bool,
    prev_head: String,
    head: String,
    proof: String,
}

type Claim = (u64, String, Vec<u64>, u32, u64);

fn told(claim: &Claim) -> serde_json::Value {
    serde_json::json!({ "trigger": claim.0, "rule": claim.1, "context": claim.2, "pid": claim.3, "started_at": claim.4 })
}

fn read_journal(agent: &Hash, verified: &Verified) -> std::result::Result<Journal, String> {
    let journal = Journal::from_bytes(&verified.journal)?;
    if journal.version != JOURNAL_VERSION {
        return Err(format!("The journal has version {} and this server reads version {}", journal.version, JOURNAL_VERSION));
    }
    if journal.agent != *agent {
        return Err("The proof is about another agent".to_string());
    }
    if journal.first_window > journal.last_window || [journal.epoch, journal.last_window, journal.first_index, journal.next_index].iter().any(|number| *number > NUMBER_LIMIT) {
        return Err("The journal carries numbers no chain has".to_string());
    }
    Ok(journal)
}

/// Holds a journal against the stored windows and releases and settles the windows it covers, inside the caller's transaction
async fn settle(conn: &mut SqliteConnection, agent_id: &str, journal: &Journal, image_id: &Hash) -> std::result::Result<Vec<SystemEventBroadcast>, Refusal> {
    let (first_window, last_window) = (journal.first_window as i64, journal.last_window as i64);
    let (state_in, state_out) = (hash_to_hex(&journal.state_in), hash_to_hex(&journal.state_out));

    let windows: Vec<Covered> = sqlx::query_as(
        "SELECT epoch, first_index, count, fresh, prev_head, head, proof FROM sealed_windows
         WHERE agent_id = ? AND window BETWEEN ? AND ? ORDER BY window",
    )
    .bind(agent_id)
    .bind(first_window)
    .bind(last_window)
    .fetch_all(&mut *conn)
    .await?;
    let (Some(first), Some(last)) = (windows.first(), windows.last()) else {
        return Err(format!("The server holds no window from {} to {}", first_window, last_window).into());
    };
    if windows.len() as u64 != journal.last_window - journal.first_window + 1 {
        return Err(format!("The server does not hold every window from {} to {}", first_window, last_window).into());
    }
    if windows.iter().any(|window| window.epoch as u64 != journal.epoch) {
        return Err(format!("The windows are not all of epoch {}", journal.epoch).into());
    }
    if first.prev_head != hash_to_hex(&journal.head_in) || last.head != hash_to_hex(&journal.head_out) {
        return Err("The proof runs between other heads than the stored windows".to_string().into());
    }
    if first.fresh != journal.fresh {
        return Err("The proof and the stored window disagree on whether the epoch starts here".to_string().into());
    }
    if first.first_index as u64 != journal.first_index || (last.first_index + last.count) as u64 != journal.next_index {
        return Err("The proof covers other events than the stored windows".to_string().into());
    }

    let known: Option<(i64, i64, String, String)> = sqlx::query_as("SELECT epoch, last_window, state_in, state_out FROM proofs WHERE agent_id = ? AND first_window = ?")
        .bind(agent_id)
        .bind(first_window)
        .fetch_optional(&mut *conn)
        .await?;
    if known == Some((journal.epoch as i64, last_window, state_in.clone(), state_out.clone())) {
        return Ok(Vec::new());
    }

    if windows.iter().any(|window| window.proof != PROOF_PENDING) {
        return Err(format!("Not every window from {} to {} waits for a proof", first_window, last_window).into());
    }

    let position = chain::position(&mut *conn, agent_id).await?;
    if journal.fresh {
        if journal.state_in != GENESIS {
            return Err("An epoch starts from no rule state".to_string().into());
        }
    } else if journal.first_window == 0 || position.proven_window != Some(journal.first_window - 1) || position.proven_state.as_deref() != Some(state_in.as_str()) {
        return Err("The proof does not start from the rule state the last proof left".to_string().into());
    }

    let matched: BTreeSet<Claim> = journal.matches.iter().map(|found| (found.trigger, found.rule.id().to_string(), found.context.clone(), found.pid, found.started_at)).collect();
    let released: Vec<(i64, String, String, i64, i64, Option<String>)> = sqlx::query_as(
        "SELECT trigger_idx, rule, context, pid, started_at, finding_event_id FROM releases
         WHERE agent_id = ? AND trigger_idx >= ? AND trigger_idx < ? ORDER BY trigger_idx",
    )
    .bind(agent_id)
    .bind(journal.first_index as i64)
    .bind(journal.next_index as i64)
    .fetch_all(&mut *conn)
    .await?;

    let mut held = BTreeSet::new();
    let mut not_proven = Vec::new();
    for (trigger, rule, context, pid, started_at, finding_event_id) in released {
        let context: Vec<u64> = serde_json::from_str(&context).map_err(|e| AppError::InternalError(format!("Stored release context is damaged: {}", e)))?;
        let claim: Claim = (trigger as u64, rule, context, pid as u32, started_at as u64);
        if !matched.contains(&claim) {
            not_proven.push(told(&claim));
            held.insert(claim);
            continue;
        }

        sqlx::query("UPDATE releases SET proven = 1 WHERE agent_id = ? AND trigger_idx = ? AND rule = ?").bind(agent_id).bind(trigger).bind(&claim.1).execute(&mut *conn).await?;
        if let Some(event_id) = finding_event_id {
            sqlx::query("UPDATE events SET data = json_set(data, '$.proof', ?) WHERE id = ?").bind(PROOF_VERIFIED).bind(event_id).execute(&mut *conn).await?;
            sqlx::query("UPDATE incidents SET evidence = json_set(evidence, '$.proof', ?) WHERE agent_id = ? AND incident_type = ? AND json_extract(evidence, '$.trigger') = ?")
                .bind(PROOF_VERIFIED)
                .bind(agent_id)
                .bind(format!("{}{}", INCIDENT_PREFIX, claim.1))
                .bind(trigger)
                .execute(&mut *conn)
                .await?;
        }
        held.insert(claim);
    }
    let not_released: Vec<serde_json::Value> = matched.difference(&held).map(told).collect();
    let status = if not_released.is_empty() && not_proven.is_empty() { PROOF_VERIFIED } else { PROOF_MISMATCH };

    sqlx::query("UPDATE sealed_windows SET proof = ? WHERE agent_id = ? AND window BETWEEN ? AND ?").bind(status).bind(agent_id).bind(first_window).bind(last_window).execute(&mut *conn).await?;
    sqlx::query("INSERT INTO proofs (agent_id, epoch, first_window, last_window, image_id, state_in, state_out, received_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)")
        .bind(agent_id)
        .bind(journal.epoch as i64)
        .bind(first_window)
        .bind(last_window)
        .bind(hash_to_hex(image_id))
        .bind(&state_in)
        .bind(&state_out)
        .bind(Utc::now().timestamp())
        .execute(&mut *conn)
        .await?;
    sqlx::query("UPDATE chain_positions SET proven_window = ?, proven_state = ? WHERE agent_id = ? AND (proven_window IS NULL OR proven_window < ?)")
        .bind(last_window)
        .bind(&state_out)
        .bind(agent_id)
        .bind(last_window)
        .execute(&mut *conn)
        .await?;

    let mut announce = Vec::new();
    for (incident_type, key, claims) in [(incidents::MATCH_NOT_RELEASED, "matches", not_released), (incidents::RELEASE_NOT_PROVEN, "releases", not_proven)] {
        if !claims.is_empty() {
            let evidence = serde_json::json!({ "epoch": journal.epoch, "first_window": journal.first_window, "last_window": journal.last_window, (key): claims });
            announce.extend(incidents::open_within(conn, agent_id, incident_type, evidence).await?);
        }
    }
    Ok(announce)
}

async fn check(state: &AppState, agent_id: &str, agent: &Hash, receipt: &str) -> std::result::Result<ProofAck, Refusal> {
    let receipt = bytes_from_base64(receipt).map_err(|_| "The receipt is not base64".to_string())?;
    let verifier = state.receipt_verifier.clone();
    let verified = tokio::task::spawn_blocking(move || verifier.verify(&receipt)).await.map_err(|_| "The receipt could not be checked".to_string())??;
    let journal = read_journal(agent, &verified)?;

    let mut tx = state.pool.begin_with("BEGIN IMMEDIATE").await?;
    match settle(&mut tx, agent_id, &journal, &verified.image_id).await {
        Ok(announce) => {
            tx.commit().await?;
            for event in announce {
                let _ = state.system_events_tx.send(event);
            }
            Ok(ProofAck { first_window: journal.first_window, last_window: journal.last_window })
        }
        Err(refusal) => {
            tx.rollback().await?;
            Err(refusal)
        }
    }
}

/// Checks a proof against what the server stored and what the agent released, and settles the windows it covers.
/// The inner error says why the proof was refused
pub async fn accept(state: &AppState, agent_id: &str, agent: &Hash, receipt: &str) -> Result<std::result::Result<ProofAck, String>> {
    match check(state, agent_id, agent, receipt).await {
        Ok(ack) => Ok(Ok(ack)),
        Err(Refusal::Failed(error)) => Err(error),
        Err(Refusal::Invalid(reason)) => {
            incidents::open(&state.pool, &state.system_events_tx, agent_id, incidents::PROOF_INVALID, serde_json::json!({ "reason": reason })).await?;
            Ok(Err(reason))
        }
    }
}

pub fn parse_deadline(raw: &str) -> std::result::Result<i64, String> {
    if raw.trim().is_empty() {
        return Ok(DEFAULT_DEADLINE_SECS);
    }
    raw.trim().parse::<i64>().ok().filter(|secs| *secs > 0).ok_or_else(|| format!("{} must be a number of seconds above zero", DEADLINE_ENV))
}

pub fn deadline_from_env() -> std::result::Result<i64, String> {
    parse_deadline(&std::env::var(DEADLINE_ENV).unwrap_or_default())
}

pub async fn sweep_once(pool: &SqlitePool, events_tx: &broadcast::Sender<SystemEventBroadcast>, now: i64, deadline_secs: i64) -> Result<()> {
    let overdue: Vec<(String, i64, i64, i64)> = sqlx::query_as(
        "SELECT w.agent_id, MIN(w.window), MIN(w.received_at), COUNT(*) FROM sealed_windows w
         JOIN agents a ON a.id = w.agent_id
         WHERE w.proof = ? AND w.received_at < ? AND a.liveness_state = ?
         GROUP BY w.agent_id",
    )
    .bind(PROOF_PENDING)
    .bind(now - deadline_secs)
    .bind(liveness::State::Active.as_str())
    .fetch_all(pool)
    .await?;

    for (agent_id, window, received_at, windows) in overdue {
        incidents::open(
            pool,
            events_tx,
            &agent_id,
            incidents::PROOF_OVERDUE,
            serde_json::json!({ "window": window, "received_at": received_at, "waiting_secs": now - received_at, "windows": windows }),
        )
        .await?;
    }

    Ok(())
}

pub fn spawn_sweeper(pool: SqlitePool, events_tx: broadcast::Sender<SystemEventBroadcast>, deadline_secs: i64) {
    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(SWEEP_INTERVAL);
        loop {
            ticker.tick().await;
            if let Err(e) = sweep_once(&pool, &events_tx, Utc::now().timestamp(), deadline_secs).await {
                tracing::error!("Proof sweep failed: {}", e);
            }
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_image_ids_are_read_as_a_list_of_hashes() {
        let (first, second) = ("ab".repeat(32), "cd".repeat(32));
        assert_eq!(parse_image_ids(&format!(" {}, {} ,", first, second)).unwrap(), vec![[0xab; 32], [0xcd; 32]]);
        assert!(parse_image_ids("").unwrap().is_empty());
        assert!(parse_image_ids("abcd").unwrap_err().contains("abcd"));
        assert!(parse_image_ids(&format!("{},{}", first, "zz".repeat(32))).is_err());
    }

    #[test]
    fn test_the_proof_deadline_is_an_hour_unless_it_is_set() {
        assert_eq!(parse_deadline(""), Ok(3600));
        assert_eq!(parse_deadline("  "), Ok(3600));
        assert_eq!(parse_deadline("900"), Ok(900));
        for refused in ["0", "-60", "an hour", "1.5"] {
            assert!(parse_deadline(refused).unwrap_err().contains(DEADLINE_ENV), "{}", refused);
        }
    }

    fn fake_receipt(image_id: Hash, journal: &[u8]) -> Vec<u8> {
        let claim = risc0_zkvm::ReceiptClaim::ok(image_id, journal.to_vec());
        let receipt = Receipt::new(risc0_zkvm::InnerReceipt::Fake(risc0_zkvm::FakeReceipt::new(claim)), journal.to_vec());
        bincode::serialize(&receipt).unwrap()
    }

    #[test]
    fn test_a_development_receipt_never_verifies_even_when_development_mode_is_asked_for() {
        std::env::set_var("RISC0_DEV_MODE", "1");
        let image_id = [5u8; 32];
        let verifier = Risc0Verifier::new(vec![image_id]);
        assert_eq!(verifier.image_ids(), vec![image_id]);
        let refused = verifier.verify(&fake_receipt(image_id, b"journal")).unwrap_err();
        assert!(refused.contains("does not verify"), "{}", refused);
    }

    /// A receipt `zedr-prover selftest <file>` wrote, and the rule program that prover carried.
    /// It stays valid when the rules change. When the journal changes its layout, write a new one and put its image ID here
    const REAL_RECEIPT: &[u8] = include_bytes!("../tests/fixtures/selftest-receipt.bin");
    const REAL_RECEIPT_IMAGE_ID: &str = "2e3d3cec4e7f76cac423d39f2e594d0a93df9a8dfa1ba6c1da53d06b7c7a14f5";

    #[test]
    fn test_a_real_receipt_verifies_against_its_rule_program_and_no_other() {
        let image_id = hash_from_hex(REAL_RECEIPT_IMAGE_ID).unwrap();
        let verified = Risc0Verifier::new(vec![[5u8; 32], image_id]).verify(REAL_RECEIPT).unwrap();
        assert_eq!(verified.image_id, image_id);
        let journal = Journal::from_bytes(&verified.journal).unwrap();
        assert_eq!((journal.agent, journal.first_window, journal.next_index, journal.matches.len()), ([7u8; 32], 0, 3, 1));

        let refused = Risc0Verifier::new(vec![[5u8; 32]]).verify(REAL_RECEIPT).unwrap_err();
        assert!(refused.contains("does not verify"), "{}", refused);

        let mut receipt: Receipt = bincode::deserialize(REAL_RECEIPT).unwrap();
        *receipt.journal.bytes.last_mut().unwrap() ^= 1;
        let altered = bincode::serialize(&receipt).unwrap();
        assert!(Risc0Verifier::new(vec![image_id]).verify(&altered).is_err(), "a journal that was changed after proving");
    }

    #[test]
    fn test_bytes_that_are_not_a_receipt_and_a_server_without_image_ids_accept_nothing() {
        assert!(Risc0Verifier::new(vec![[5u8; 32]]).verify(b"not a receipt").unwrap_err().contains("Not a receipt"));
        assert!(Risc0Verifier::new(Vec::new()).verify(&fake_receipt([5u8; 32], b"journal")).unwrap_err().contains("does not verify"));
    }
}
