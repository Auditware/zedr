/// Plays every endpoint of a scenario at once, then keeps the ones that stay up alive
use std::io::Write;
use std::sync::Mutex;
use std::thread;
use std::time::Duration;

use zedr_shared::link::unix_now;

use crate::endpoint::Endpoint;
use crate::scenario::{self, Scenario};

const WORKERS: usize = 8;
/// A proof takes most cores for minutes, and here every endpoint proves on the same machine, so no more than two prove at the same moment
const PROVERS: usize = 2;
const TICK: Duration = Duration::from_secs(1);
const PROOF_TICK: Duration = Duration::from_millis(200);

/// Enrolls one endpoint and walks its timeline
fn played(scenario: &Scenario, mut described: scenario::Endpoint, now: u64) -> Result<Endpoint, String> {
    let timeline = std::mem::take(&mut described.timeline);
    let started = timeline.first().map(scenario::timestamp).unwrap_or(now);
    let mut endpoint = Endpoint::enroll(scenario, &described, started)?;
    endpoint.play(timeline)?;
    Ok(endpoint)
}

/// Says what went wrong on an endpoint, once for as long as it stays the same
fn note(hostname: &str, outcome: Result<(), String>, said: &mut Result<(), String>) {
    if outcome != *said {
        if let Err(reason) = &outcome {
            eprintln!("{}: {}", hostname, reason);
        }
        *said = outcome;
    }
}

/// Plays the scenario. `READY` is written once every timeline is played, and `PROVEN` once no endpoint owes its first proof any more.
/// With a heartbeat interval in the scenario this never returns: the endpoints that stay up keep reporting
pub fn run(mut scenario: Scenario, out: &mut impl Write) -> Result<(), String> {
    let now = unix_now();
    let queue = Mutex::new(std::mem::take(&mut scenario.endpoints).into_iter().enumerate());
    let done: Mutex<Vec<(usize, Result<Endpoint, String>)>> = Mutex::new(Vec::new());
    thread::scope(|scope| {
        for _ in 0..WORKERS {
            scope.spawn(|| loop {
                let next = queue.lock().expect("no worker panics while it takes an endpoint").next();
                let Some((position, described)) = next else { break };
                let hostname = described.hostname.clone();
                let outcome = played(&scenario, described, now).map_err(|e| format!("{}: {}", hostname, e));
                done.lock().expect("no worker panics while it hands an endpoint back").push((position, outcome));
            });
        }
    });

    let mut done = done.into_inner().map_err(|_| "A worker panicked".to_string())?;
    done.sort_by_key(|(position, _)| *position);
    let mut fleet = done.into_iter().map(|(_, outcome)| outcome).collect::<Result<Vec<Endpoint>, String>>()?;
    let said = |line: String, out: &mut dyn Write| writeln!(out, "{}", line).and_then(|()| out.flush()).map_err(|e| format!("Failed to write: {}", e));
    said(format!("READY {} endpoints", fleet.len()), out)?;

    let mut reported: Vec<Result<(), String>> = vec![Ok(()); fleet.len()];
    let mut proven = false;
    loop {
        if !proven && fleet.iter().all(Endpoint::first_proof_settled) {
            proven = true;
            said(format!("PROVEN {} endpoints", fleet.iter().filter(|endpoint| endpoint.proved()).count()), out)?;
        }

        let now = unix_now();
        let mut proving = fleet.iter().filter(|endpoint| endpoint.is_proving()).count();
        for (endpoint, reported) in fleet.iter_mut().zip(&mut reported) {
            let mut outcome = Ok(());
            if let (true, Some(heartbeat_seconds)) = (endpoint.stays_up(), scenario.heartbeat_seconds) {
                outcome = endpoint.keep_up(now, heartbeat_seconds);
            }
            if endpoint.stays_up() || !endpoint.first_proof_settled() {
                let was_proving = endpoint.is_proving();
                outcome = outcome.and(endpoint.prove(proving < PROVERS).map(|_| ()));
                proving = proving + usize::from(endpoint.is_proving()) - usize::from(was_proving);
            }
            note(endpoint.hostname(), outcome, reported);
        }

        match scenario.heartbeat_seconds {
            Some(_) => thread::sleep(TICK),
            None if proven => return Ok(()),
            None => thread::sleep(PROOF_TICK),
        }
    }
}
