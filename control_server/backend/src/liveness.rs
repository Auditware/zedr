use std::time::Duration;

use chrono::Utc;
use sqlx::SqlitePool;
use zedr_protocol::StopReason;
use tokio::sync::broadcast;

use crate::api::SystemEventBroadcast;
use crate::error::Result;
use crate::incidents;

pub const HEARTBEAT_CADENCE_SECS: i64 = 30;
const SWEEP_INTERVAL: Duration = Duration::from_secs(15);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum State {
    Active,
    Stale,
    Suspect,
    Incident,
    Stopped,
}

impl State {
    pub fn as_str(self) -> &'static str {
        match self {
            State::Active => "active",
            State::Stale => "stale",
            State::Suspect => "suspect",
            State::Incident => "incident",
            State::Stopped => "stopped",
        }
    }

    pub fn parse(value: &str) -> State {
        match value {
            "stale" => State::Stale,
            "suspect" => State::Suspect,
            "incident" => State::Incident,
            "stopped" => State::Stopped,
            _ => State::Active,
        }
    }
}

pub struct Thresholds {
    pub grace: i64,
    pub stale: i64,
    pub suspect: i64,
}

impl Default for Thresholds {
    fn default() -> Self {
        Self { grace: 3, stale: 10, suspect: 30 }
    }
}

pub struct Observation {
    pub silent_secs: i64,
    pub current: State,
    pub stop_reason: Option<StopReason>,
    pub fleet_silent: bool,
}

#[derive(Debug, PartialEq, Eq)]
pub struct Verdict {
    pub state: State,
    pub open_incident: bool,
}

pub fn derive(observation: &Observation, thresholds: &Thresholds) -> Verdict {
    match observation.stop_reason {
        Some(StopReason::SystemShutdown) => {
            return Verdict { state: State::Stopped, open_incident: false }
        }
        Some(StopReason::ServiceStop) => {
            return Verdict { state: State::Incident, open_incident: false }
        }
        Some(StopReason::Upgrade) | None => {}
    }

    let silent = observation.silent_secs;
    let state = if silent <= thresholds.grace * HEARTBEAT_CADENCE_SECS {
        State::Active
    } else if silent <= thresholds.stale * HEARTBEAT_CADENCE_SECS {
        State::Stale
    } else if silent <= thresholds.suspect * HEARTBEAT_CADENCE_SECS || observation.fleet_silent {
        State::Suspect
    } else {
        State::Incident
    };

    Verdict {
        state,
        open_incident: state == State::Incident && observation.current != State::Incident,
    }
}

pub fn parse_stop_reason(value: Option<&str>) -> Option<StopReason> {
    match value {
        Some("ServiceStop") => Some(StopReason::ServiceStop),
        Some("SystemShutdown") => Some(StopReason::SystemShutdown),
        Some("Upgrade") => Some(StopReason::Upgrade),
        _ => None,
    }
}

pub fn stop_reason_label(reason: &StopReason) -> &'static str {
    match reason {
        StopReason::ServiceStop => "ServiceStop",
        StopReason::SystemShutdown => "SystemShutdown",
        StopReason::Upgrade => "Upgrade",
    }
}

pub async fn sweep_once(
    pool: &SqlitePool,
    events_tx: &broadcast::Sender<SystemEventBroadcast>,
    now: i64,
    observing_since: i64,
) -> Result<()> {
    let thresholds = Thresholds::default();

    let agents: Vec<(String, i64, String, Option<String>)> = sqlx::query_as(
        "SELECT id, last_heartbeat, liveness_state, stop_reason FROM agents WHERE public_key IS NOT NULL",
    )
    .fetch_all(pool)
    .await?;

    let observed: Vec<(String, i64, State, Option<StopReason>)> = agents
        .into_iter()
        .map(|(id, last_heartbeat, state, stop_reason)| {
            let silent_secs = now - last_heartbeat.max(observing_since);
            (id, silent_secs, State::parse(&state), parse_stop_reason(stop_reason.as_deref()))
        })
        .collect();

    let expected_to_beat = |reason: &Option<StopReason>| {
        !matches!(reason, Some(StopReason::SystemShutdown) | Some(StopReason::ServiceStop))
    };
    let grace_secs = thresholds.grace * HEARTBEAT_CADENCE_SECS;
    let peers = observed.iter().filter(|(_, _, _, reason)| expected_to_beat(reason)).count();
    let silent_peers = observed
        .iter()
        .filter(|(_, silent, _, reason)| expected_to_beat(reason) && *silent > grace_secs)
        .count();

    for (agent_id, silent_secs, current, stop_reason) in &observed {
        let fleet_silent = peers > 1 && silent_peers == peers;

        let verdict = derive(
            &Observation {
                silent_secs: *silent_secs,
                current: *current,
                stop_reason: stop_reason.clone(),
                fleet_silent,
            },
            &thresholds,
        );

        if verdict.state != *current {
            sqlx::query("UPDATE agents SET liveness_state = ? WHERE id = ?")
                .bind(verdict.state.as_str())
                .bind(agent_id)
                .execute(pool)
                .await?;
        }

        if verdict.open_incident {
            incidents::open(
                pool,
                events_tx,
                agent_id,
                incidents::SILENCE,
                serde_json::json!({ "silent_secs": silent_secs }),
            )
            .await?;
        }
    }

    Ok(())
}

pub fn spawn_sweeper(pool: SqlitePool, events_tx: broadcast::Sender<SystemEventBroadcast>) {
    let observing_since = Utc::now().timestamp();

    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(SWEEP_INTERVAL);
        loop {
            ticker.tick().await;
            if let Err(e) = sweep_once(&pool, &events_tx, Utc::now().timestamp(), observing_since).await {
                tracing::error!("Liveness sweep failed: {}", e);
            }
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    fn observe(silent_secs: i64, current: State, stop_reason: Option<StopReason>, fleet_silent: bool) -> Verdict {
        derive(
            &Observation { silent_secs, current, stop_reason, fleet_silent },
            &Thresholds::default(),
        )
    }

    #[test]
    fn test_recent_beat_is_active() {
        assert_eq!(observe(30, State::Active, None, false).state, State::Active);
        assert_eq!(observe(90, State::Active, None, false).state, State::Active);
    }

    #[test]
    fn test_short_gap_is_stale_without_incident() {
        let verdict = observe(91, State::Active, None, false);
        assert_eq!(verdict, Verdict { state: State::Stale, open_incident: false });
    }

    #[test]
    fn test_long_gap_is_suspect_without_incident() {
        let verdict = observe(301, State::Stale, None, false);
        assert_eq!(verdict, Verdict { state: State::Suspect, open_incident: false });
    }

    #[test]
    fn test_unique_long_silence_opens_incident_once() {
        let first = observe(901, State::Suspect, None, false);
        assert_eq!(first, Verdict { state: State::Incident, open_incident: true });
        let again = observe(2000, State::Incident, None, false);
        assert_eq!(again, Verdict { state: State::Incident, open_incident: false });
    }

    #[test]
    fn test_fleet_wide_silence_never_blames_one_machine() {
        let verdict = observe(5000, State::Suspect, None, true);
        assert_eq!(verdict, Verdict { state: State::Suspect, open_incident: false });
    }

    #[test]
    fn test_system_shutdown_never_alarms() {
        let verdict = observe(100_000, State::Active, Some(StopReason::SystemShutdown), false);
        assert_eq!(verdict, Verdict { state: State::Stopped, open_incident: false });
    }

    #[test]
    fn test_service_stop_stays_incident_without_duplicate() {
        let verdict = observe(10, State::Incident, Some(StopReason::ServiceStop), false);
        assert_eq!(verdict, Verdict { state: State::Incident, open_incident: false });
    }

    #[test]
    fn test_upgrade_handoff_gap_is_tolerated_but_not_forever() {
        assert_eq!(observe(60, State::Active, Some(StopReason::Upgrade), false).state, State::Active);
        let stuck = observe(901, State::Suspect, Some(StopReason::Upgrade), false);
        assert_eq!(stuck, Verdict { state: State::Incident, open_incident: true });
    }

    #[test]
    fn test_state_round_trips_through_storage() {
        for state in [State::Active, State::Stale, State::Suspect, State::Incident, State::Stopped] {
            assert_eq!(State::parse(state.as_str()), state);
        }
    }
}
