use std::collections::BTreeMap;

use chrono::Utc;
use sqlx::{QueryBuilder, Sqlite, SqliteConnection, SqliteExecutor};
use zedr_ledger::{leaf, seal, Hash, WindowHeader, GENESIS};
use zedr_protocol::{bytes_from_base64, hash_from_hex, hash_to_hex, ProcessAction, Release, SealedWindow, SensorEvent, SystemEvent};
use zedr_rules::{Level, RuleId};

use crate::api::ingestion::events::store_event;
use crate::api::{AppState, SystemEventBroadcast};
use crate::detections::{self, Finding, Opened};
use crate::error::{Refusal, Result};
use crate::hunt::{self, Described};
use crate::incidents;

pub const PROOF_PENDING: &str = "pending";
pub const PROOF_VERIFIED: &str = "verified";
pub const PROOF_MISMATCH: &str = "mismatch";
pub const PROOF_NONE: &str = "none";

/// Largest epoch, window number or event index the server stores, so that every sum of them still fits a database integer
pub const NUMBER_LIMIT: u64 = 1 << 62;

const INSERT_ROWS: usize = 500;

/// No rule reads more context than the process an event belongs to and that process's parent
const CONTEXT_LIMIT: usize = 2;

/// Where the server's copy of an agent's chain stands
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Position {
    pub epoch: u64,
    pub next_window: u64,
    pub next_index: u64,
    pub head: String,
    pub proven_window: Option<u64>,
    pub proven_state: Option<String>,
}

#[derive(sqlx::FromRow)]
struct StoredPosition {
    epoch: i64,
    next_window: i64,
    next_index: i64,
    head: String,
    proven_window: Option<i64>,
    proven_state: Option<String>,
}

pub async fn position<'e>(executor: impl SqliteExecutor<'e>, agent_id: &str) -> Result<Position> {
    let stored = sqlx::query_as::<_, StoredPosition>("SELECT epoch, next_window, next_index, head, proven_window, proven_state FROM chain_positions WHERE agent_id = ?")
        .bind(agent_id)
        .fetch_optional(executor)
        .await?;

    Ok(match stored {
        Some(stored) => Position {
            epoch: stored.epoch as u64,
            next_window: stored.next_window as u64,
            next_index: stored.next_index as u64,
            head: stored.head,
            proven_window: stored.proven_window.map(|window| window as u64),
            proven_state: stored.proven_state,
        },
        None => Position { epoch: 0, next_window: 0, next_index: 0, head: hash_to_hex(&GENESIS), proven_window: None, proven_state: None },
    })
}

#[derive(Debug)]
struct Decoded {
    header: WindowHeader,
    leaves: Vec<Hash>,
    sealed: Vec<Vec<u8>>,
}

fn decode(agent: &Hash, window: &SealedWindow) -> std::result::Result<Decoded, String> {
    let sent = &window.header;
    let header = WindowHeader {
        epoch: sent.epoch,
        window: sent.window,
        first_index: sent.first_index,
        count: sent.count,
        fresh: sent.fresh,
        gap: sent.gap,
        prev_head: hash_from_hex(&sent.prev_head)?,
        root: hash_from_hex(&sent.root)?,
        head: hash_from_hex(&sent.head)?,
    };
    if header.epoch > NUMBER_LIMIT || header.window > NUMBER_LIMIT || header.first_index > NUMBER_LIMIT {
        return Err(format!("Window {} carries a number larger than {}", header.window, NUMBER_LIMIT));
    }

    let leaves = window.events.iter().map(|event| hash_from_hex(&event.leaf)).collect::<std::result::Result<Vec<_>, _>>()?;
    let sealed = window.events.iter().map(|event| bytes_from_base64(&event.sealed)).collect::<std::result::Result<Vec<_>, _>>()?;
    header.verify(agent, &leaves)?;
    Ok(Decoded { header, leaves, sealed })
}

fn continues(position: &Position, header: &WindowHeader) -> std::result::Result<(), &'static str> {
    if header.window != position.next_window {
        return Err("it is not the next window");
    }
    if header.first_index != position.next_index {
        return Err("it does not start at the next event");
    }
    if hash_to_hex(&header.prev_head) != position.head {
        return Err("it does not follow the stored head");
    }

    let first = position.next_window == 0;
    if header.fresh && !first && header.epoch <= position.epoch {
        return Err("a fresh window starts an epoch later than the stored one");
    }
    if !header.fresh && (first || header.epoch != position.epoch) {
        return Err("a window that is not fresh stays in the stored epoch");
    }
    Ok(())
}

async fn store(conn: &mut SqliteConnection, agent_id: &str, decoded: &Decoded, proving: bool, now: i64) -> Result<()> {
    let header = &decoded.header;
    let head = hash_to_hex(&header.head);

    sqlx::query(
        "INSERT INTO sealed_windows (agent_id, window, epoch, first_index, count, fresh, gap, prev_head, root, head, received_at, proving, proof)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
    )
    .bind(agent_id)
    .bind(header.window as i64)
    .bind(header.epoch as i64)
    .bind(header.first_index as i64)
    .bind(header.count)
    .bind(header.fresh)
    .bind(header.gap)
    .bind(hash_to_hex(&header.prev_head))
    .bind(hash_to_hex(&header.root))
    .bind(&head)
    .bind(now)
    .bind(proving)
    .bind(if proving { PROOF_PENDING } else { PROOF_NONE })
    .execute(&mut *conn)
    .await?;

    let events: Vec<(i64, &Hash, &Vec<u8>)> = (header.first_index as i64..).zip(&decoded.leaves).zip(&decoded.sealed).map(|((index, leaf), sealed)| (index, leaf, sealed)).collect();
    for rows in events.chunks(INSERT_ROWS) {
        let mut insert = QueryBuilder::<Sqlite>::new("INSERT INTO sealed_events (agent_id, idx, window, leaf, ciphertext) ");
        insert.push_values(rows, |mut row, (index, leaf, sealed)| {
            row.push_bind(agent_id).push_bind(*index).push_bind(header.window as i64).push_bind(hash_to_hex(leaf)).push_bind(sealed.as_slice());
        });
        insert.build().execute(&mut *conn).await?;
    }

    sqlx::query(
        "INSERT INTO chain_positions (agent_id, epoch, next_window, next_index, head) VALUES (?, ?, ?, ?, ?)
         ON CONFLICT(agent_id) DO UPDATE SET epoch = excluded.epoch, next_window = excluded.next_window, next_index = excluded.next_index, head = excluded.head",
    )
    .bind(agent_id)
    .bind(header.epoch as i64)
    .bind(header.window as i64 + 1)
    .bind(header.next_index() as i64)
    .bind(&head)
    .execute(&mut *conn)
    .await?;

    Ok(())
}

async fn repeats(conn: &mut SqliteConnection, agent_id: &str, finding: &Finding) -> Result<bool> {
    let repeated = match finding.autostart {
        None => {
            sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM releases WHERE agent_id = ? AND rule = ? AND pid = ? AND started_at = ?)")
                .bind(agent_id)
                .bind(finding.rule.id())
                .bind(finding.pid)
                .bind(finding.started_at as i64)
                .fetch_one(&mut *conn)
                .await?
        }
        Some(kind) => {
            sqlx::query_scalar(
                "SELECT EXISTS(SELECT 1 FROM releases r JOIN events f ON f.id = r.finding_event_id
                 WHERE r.agent_id = ? AND r.rule = ? AND r.pid = ? AND r.started_at = ?
                   AND json_extract(f.data, '$.autostart') = ? AND json_extract(f.data, '$.image') = ? AND json_extract(f.data, '$.subject') = ?)",
            )
            .bind(agent_id)
            .bind(finding.rule.id())
            .bind(finding.pid)
            .bind(finding.started_at as i64)
            .bind(kind)
            .bind(&finding.image)
            .bind(&finding.subject)
            .fetch_one(&mut *conn)
            .await?
        }
    };
    Ok(repeated)
}

/// Opens what a release names, checks it against the stored leaves and the shape of its rule, and only then records it.
/// A release that is refused has written nothing
async fn apply_release(
    conn: &mut SqliteConnection,
    agent_id: &str,
    agent: &Hash,
    header: &WindowHeader,
    release: &Release,
    now: i64,
    announce: &mut Vec<SystemEventBroadcast>,
) -> std::result::Result<(), Refusal> {
    let rule = RuleId::from_id(&release.rule).ok_or_else(|| "It names a rule that does not exist".to_string())?;
    if !(header.first_index..header.next_index()).contains(&release.trigger) {
        return Err(format!("Its trigger is not an event of window {}", header.window).into());
    }
    if release.context.len() > CONTEXT_LIMIT {
        return Err("It reads more context than any rule does".to_string().into());
    }
    if release.context.iter().any(|index| *index >= release.trigger) {
        return Err("Its context does not come before its trigger".to_string().into());
    }
    if release.started_at > NUMBER_LIMIT {
        return Err("Its start time is not a time".to_string().into());
    }

    let indices: Vec<u64> = std::iter::once(release.trigger).chain(release.context.iter().copied()).collect();
    let seeds: BTreeMap<u64, &str> = release.openings.iter().map(|opening| (opening.index, opening.seed.as_str())).collect();
    let exact = release.openings.len() == indices.len() && seeds.len() == indices.len() && indices.iter().all(|index| seeds.contains_key(index));
    if !exact {
        return Err("Its openings are not exactly its trigger and its context".to_string().into());
    }

    let recorded: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM releases WHERE agent_id = ? AND trigger_idx = ? AND rule = ?)")
        .bind(agent_id)
        .bind(release.trigger as i64)
        .bind(rule.id())
        .fetch_one(&mut *conn)
        .await?;
    if recorded {
        return Err("It was released before".to_string().into());
    }

    let mut events = Vec::with_capacity(indices.len());
    let mut stored_as = Vec::with_capacity(indices.len());
    for index in &indices {
        let held: Option<(String, Vec<u8>, Option<String>, i64)> = sqlx::query_as(
            "SELECT e.leaf, e.ciphertext, e.event_id, w.epoch FROM sealed_events e
             JOIN sealed_windows w ON w.agent_id = e.agent_id AND w.window = e.window
             WHERE e.agent_id = ? AND e.idx = ?",
        )
        .bind(agent_id)
        .bind(*index as i64)
        .fetch_optional(&mut *conn)
        .await?;
        let (committed, ciphertext, event_id, epoch) = held.ok_or_else(|| format!("Event {} is not held", index))?;
        if epoch as u64 != header.epoch {
            return Err(format!("Event {} belongs to another epoch", index).into());
        }

        let seed = hash_from_hex(seeds[index])?;
        let bytes = seal::open(&seed, agent, header.epoch, *index, &ciphertext)?;
        if hash_to_hex(&leaf(agent, header.epoch, *index, &seal::blind(&seed), &bytes)) != committed {
            return Err(format!("Event {} is not the one its leaf commits to", index).into());
        }
        events.push(SensorEvent::from_bytes(&bytes)?);
        stored_as.push(event_id);
    }
    let opened = detections::roles(rule, release.pid, &events[0], &events[1..])?;

    let (owner, owner_at) = match &opened {
        Opened::Process { process, parent, .. } => (Some(Described::new(process, *parent, release.started_at)), usize::from(!matches!(events[0], SensorEvent::Process(_)))),
        Opened::End { process, .. } => (Some(Described::new(process, None, release.started_at)), 1),
        Opened::Item(_) => (None, 0),
    };
    // Oldest first, so that a process is in the index before its end is
    for (at, event) in events.iter().enumerate().rev() {
        if stored_as[at].is_some() {
            continue;
        }
        let alone;
        let described = match event {
            SensorEvent::Process(process) if at != owner_at && !matches!(process.action, ProcessAction::Terminate) => {
                alone = Described::new(process, None, process.timestamp);
                Some(&alone)
            }
            _ => owner.as_ref(),
        };

        let stored = store_event(&mut *conn, agent_id, &SystemEvent::from(event.clone()), now).await?;
        hunt::index(&mut *conn, agent_id, event, described).await?;
        sqlx::query("UPDATE sealed_events SET opened_at = ?, event_id = ? WHERE agent_id = ? AND idx = ?")
            .bind(now)
            .bind(&stored.id)
            .bind(agent_id)
            .bind(indices[at] as i64)
            .execute(&mut *conn)
            .await?;
        announce.push(stored);
    }

    let mut finding_event_id = None;
    if let Some(finding) = Finding::new(rule, release.pid, release.started_at, &opened, release.trigger, header.window) {
        if !repeats(conn, agent_id, &finding).await? {
            let evidence = finding.evidence();
            let recorded = incidents::insert_event(&mut *conn, Some(agent_id), "detection", evidence.clone()).await?;
            finding_event_id = Some(recorded.id.clone());
            announce.push(recorded);
            if rule.level() == Level::High {
                announce.extend(incidents::open_within(conn, agent_id, &finding.incident_type(), evidence).await?);
            }
        }
    }

    sqlx::query("INSERT INTO releases (agent_id, window, trigger_idx, rule, pid, started_at, context, finding_event_id) VALUES (?, ?, ?, ?, ?, ?, ?, ?)")
        .bind(agent_id)
        .bind(header.window as i64)
        .bind(release.trigger as i64)
        .bind(rule.id())
        .bind(release.pid)
        .bind(release.started_at as i64)
        .bind(serde_json::json!(release.context).to_string())
        .bind(finding_event_id)
        .execute(&mut *conn)
        .await?;

    Ok(())
}

/// What became of a window an agent sent
pub enum Admission {
    /// It is not a window an honest agent seals. The stored chain stands at this position
    Malformed(Position),
    /// It does not continue the stored chain, which stands at this position
    Refused(Position),
    /// The server holds it, since now or since an earlier request
    Held { next_index: u64, head: String },
}

/// Takes a sealed window into the stored chain of its agent and opens what its releases name
pub async fn admit(state: &AppState, agent: &Hash, window: &SealedWindow) -> Result<Admission> {
    let agent_id = window.agent_id.as_str();
    let decoded = match decode(agent, window) {
        Ok(decoded) => decoded,
        Err(reason) => {
            let sent = &window.header;
            let evidence = serde_json::json!({ "reason": reason, "window": sent.window, "epoch": sent.epoch, "first_index": sent.first_index, "count": sent.count, "events": window.events.len() });
            incidents::open(&state.pool, &state.system_events_tx, agent_id, incidents::WINDOW_MALFORMED, evidence).await?;
            return Ok(Admission::Malformed(position(&state.pool, agent_id).await?));
        }
    };
    let header = &decoded.header;
    let head = hash_to_hex(&header.head);

    let mut tx = state.pool.begin_with("BEGIN IMMEDIATE").await?;
    let position = position(&mut *tx, agent_id).await?;

    if header.window < position.next_window {
        let stored: Option<String> = sqlx::query_scalar("SELECT head FROM sealed_windows WHERE agent_id = ? AND window = ?")
            .bind(agent_id)
            .bind(header.window as i64)
            .fetch_optional(&mut *tx)
            .await?;
        if stored.as_deref() == Some(head.as_str()) {
            tx.rollback().await?;
            return Ok(Admission::Held { next_index: header.next_index(), head });
        }
    }

    if let Err(reason) = continues(&position, header) {
        tx.rollback().await?;
        incidents::open(
            &state.pool,
            &state.system_events_tx,
            agent_id,
            incidents::CHAIN_FORK,
            serde_json::json!({
                "reason": reason,
                "window": header.window,
                "epoch": header.epoch,
                "first_index": header.first_index,
                "fresh": header.fresh,
                "prev_head": hash_to_hex(&header.prev_head),
                "head": head,
                "stored_epoch": position.epoch,
                "stored_next_window": position.next_window,
                "stored_next_index": position.next_index,
                "stored_head": position.head,
            }),
        )
        .await?;
        return Ok(Admission::Refused(position));
    }

    let now = Utc::now().timestamp();
    store(&mut tx, agent_id, &decoded, window.proving, now).await?;

    let mut announce = Vec::new();
    if header.gap {
        let evidence = serde_json::json!({ "window": header.window, "epoch": header.epoch, "first_index": header.first_index });
        announce.extend(incidents::open_within(&mut tx, agent_id, incidents::CHAIN_GAP, evidence).await?);
    }
    for release in &window.releases {
        match apply_release(&mut tx, agent_id, agent, header, release, now, &mut announce).await {
            Ok(()) => {}
            Err(Refusal::Failed(error)) => return Err(error),
            Err(Refusal::Invalid(reason)) => {
                let evidence = serde_json::json!({
                    "reason": reason,
                    "window": header.window,
                    "trigger": release.trigger,
                    "rule": release.rule,
                    "context": release.context,
                    "opened": release.openings.iter().map(|opening| opening.index).collect::<Vec<_>>(),
                });
                announce.extend(incidents::open_within(&mut tx, agent_id, incidents::RELEASE_INVALID, evidence).await?);
            }
        }
    }
    tx.commit().await?;

    for event in announce {
        let _ = state.system_events_tx.send(event);
    }
    Ok(Admission::Held { next_index: header.next_index(), head })
}

#[cfg(test)]
mod tests {
    use super::*;
    use zedr_protocol::{bytes_to_base64, SealedEvent, SealedWindowHeader};

    const AGENT: Hash = [3u8; 32];

    fn sealed(epoch: u64, window: u64, first_index: u64, fresh: bool, prev_head: Hash, events: &[&[u8]]) -> SealedWindow {
        let leaves: Vec<Hash> = (first_index..).zip(events).map(|(index, event)| leaf(&AGENT, epoch, index, &[9u8; 32], event)).collect();
        let header = WindowHeader::seal(&AGENT, epoch, window, first_index, fresh, false, prev_head, &leaves).unwrap();
        SealedWindow {
            agent_id: "agent-1".to_string(),
            session: 1,
            seq: 1,
            header: SealedWindowHeader {
                epoch,
                window,
                first_index,
                count: header.count,
                fresh,
                gap: false,
                prev_head: hash_to_hex(&header.prev_head),
                root: hash_to_hex(&header.root),
                head: hash_to_hex(&header.head),
            },
            events: leaves.iter().zip(events).map(|(leaf, event)| SealedEvent { leaf: hash_to_hex(leaf), sealed: bytes_to_base64(event) }).collect(),
            releases: Vec::new(),
            proving: true,
        }
    }

    fn at(epoch: u64, next_window: u64, next_index: u64, head: Hash) -> Position {
        Position { epoch, next_window, next_index, head: hash_to_hex(&head), proven_window: None, proven_state: None }
    }

    #[test]
    fn test_a_window_is_decoded_only_when_it_is_whole_and_belongs_to_the_agent() {
        let window = sealed(1, 0, 0, true, GENESIS, &[b"one", b"two"]);
        let decoded = decode(&AGENT, &window).unwrap();
        assert_eq!((decoded.header.count, decoded.leaves.len(), decoded.sealed[1].as_slice()), (2, 2, b"two".as_slice()));
        assert!(decode(&[4u8; 32], &window).is_err(), "another agent's window");

        let mut dropped = window.clone();
        dropped.events.pop();
        assert!(decode(&AGENT, &dropped).unwrap_err().contains("claims 2 events"));

        let mut swapped = window.clone();
        swapped.events.swap(0, 1);
        assert!(decode(&AGENT, &swapped).unwrap_err().contains("root"));

        let mut renumbered = window.clone();
        renumbered.header.window = 1;
        assert!(decode(&AGENT, &renumbered).unwrap_err().contains("head"));

        let mut not_hex = window.clone();
        not_hex.header.root = "root".to_string();
        assert!(decode(&AGENT, &not_hex).is_err());
        let mut not_base64 = window.clone();
        not_base64.events[0].sealed = "not base64!".to_string();
        assert!(decode(&AGENT, &not_base64).is_err());

        let huge = sealed(1, 0, u64::MAX - 1, true, GENESIS, &[]);
        assert!(decode(&AGENT, &huge).unwrap_err().contains("larger than"));
    }

    #[test]
    fn test_only_the_next_window_of_the_chain_continues_it() {
        let first = decode(&AGENT, &sealed(1, 0, 0, true, GENESIS, &[b"a", b"b"])).unwrap().header;
        let start = at(0, 0, 0, GENESIS);
        assert_eq!(continues(&start, &first), Ok(()));
        assert!(continues(&start, &decode(&AGENT, &sealed(1, 0, 0, false, GENESIS, &[])).unwrap().header).is_err(), "a chain starts with a fresh window");

        let after = at(1, 1, 2, first.head);
        let next = |epoch, window, first_index, fresh, prev_head| decode(&AGENT, &sealed(epoch, window, first_index, fresh, prev_head, &[b"c"])).unwrap().header;
        assert_eq!(continues(&after, &next(1, 1, 2, false, first.head)), Ok(()));
        assert_eq!(continues(&after, &next(2, 1, 2, true, first.head)), Ok(()), "a restart");
        assert_eq!(continues(&after, &next(1, 2, 2, false, first.head)), Err("it is not the next window"));
        assert_eq!(continues(&after, &next(1, 0, 2, false, first.head)), Err("it is not the next window"));
        assert_eq!(continues(&after, &next(1, 1, 3, false, first.head)), Err("it does not start at the next event"));
        assert_eq!(continues(&after, &next(1, 1, 2, false, [8u8; 32])), Err("it does not follow the stored head"));
        assert!(continues(&after, &next(2, 1, 2, false, first.head)).is_err(), "a new epoch is fresh");
        assert!(continues(&after, &next(1, 1, 2, true, first.head)).is_err(), "a fresh window is a new epoch");
        assert!(continues(&at(3, 1, 2, first.head), &next(2, 1, 2, true, first.head)).is_err(), "the epoch never goes down");
        assert!(continues(&at(3, 1, 2, first.head), &next(2, 1, 2, false, first.head)).is_err());
    }
}
