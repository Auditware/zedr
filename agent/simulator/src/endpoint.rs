/// One simulated endpoint. It commits, seals and runs the rules with the agent's own ledger and talks to the control server
/// over the agent's own link. Only the sensor is replaced, by the timeline of the scenario
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::{Mutex, MutexGuard, PoisonError};
use std::time::{Duration, Instant};

use zedr_protocol::{AgentRegistration, HeartbeatEvent, SensorEvent, SystemEvent, SIGNATURE_HEADER};
use zedr_rules::proof::{self, Journal};
use zedr_rules::{RuleId, State};
use zedr_shared::identity::Identity;
use zedr_shared::ledger::{Ledger, SealedWindow};
use zedr_shared::link::{ControlLink, WindowDelivery};
use zedr_shared::runtime::{DEFAULT_PROOF_EVENTS, DEFAULT_PROOF_REST_SECS};

use crate::scenario::{self, Scenario};

/// Seconds between two looks of the sensor, the agent's default
const POLL_SECONDS: u64 = 5;
const TIMEOUT_SECS: u64 = 30;
/// A receipt is megabytes, and the control server checks it before it answers
const PROOF_TIMEOUT_SECS: u64 = 300;
const PROOF_RETRY_AFTER: Duration = Duration::from_secs(600);
/// What the agent said about itself in the past travels in batches, the control server reads the time of each event from the event
const LIFECYCLE_BATCH: usize = 500;
const PROOFS_DIR: &str = "proofs";

static WIRE: Mutex<()> = Mutex::new(());

/// Endpoints are played side by side and their ledgers do their disk work at the same time, but one request at a time reaches the
/// control server. It keeps everything in one SQLite file, and a run must not fail because that file was busy
fn one_at_a_time() -> MutexGuard<'static, ()> {
    WIRE.lock().unwrap_or_else(PoisonError::into_inner)
}

struct Proof {
    prover: Child,
    input: PathBuf,
    receipt: PathBuf,
    journal: Journal,
    state: State,
}

pub struct Endpoint {
    hostname: String,
    link: ControlLink,
    ledger: Ledger,
    prover: Option<PathBuf>,
    withheld: Vec<RuleId>,
    stays_up: bool,
    /// Time of the sensor's last look
    clock: u64,
    last_beat: Option<u64>,
    lifecycle: Vec<SystemEvent>,
    proof: Option<Proof>,
    proofs: u64,
    proof_failed: bool,
    prove_not_before: Instant,
    proving_rests_until: Instant,
}

/// Enrolls the endpoint with a registration signed by its new identity, as an agent does. The agent's own registration describes
/// the machine it runs on, so this one is filled in from the scenario and signed with the same identity code
fn register(server: &str, dir: &Path, described: &scenario::Endpoint) -> Result<(), String> {
    let mut identity = Identity::load_or_create(dir)?;
    let registration = AgentRegistration {
        agent_id: identity.key_fingerprint(),
        hostname: described.hostname.clone(),
        platform: described.platform.clone(),
        os_version: described.os_version.clone(),
        architecture: described.architecture.clone(),
        version: described.version.clone(),
        ip_address: described.ip_address.clone(),
        public_key: identity.public_key_hex(),
        enrollment_key: described.enrollment_key.clone(),
        session: identity.session(),
        seq: identity.next_seq(),
    };
    let body = serde_json::to_string(&registration).map_err(|e| format!("Failed to encode registration: {}", e))?;

    let _turn = one_at_a_time();
    let response = minreq::post(format!("{}/api/agents/register", server))
        .with_header("Content-Type", "application/json")
        .with_header(SIGNATURE_HEADER, identity.sign(body.as_bytes()))
        .with_body(body)
        .with_timeout(TIMEOUT_SECS)
        .send()
        .map_err(|e| format!("Registration failed: {}", e))?;
    if response.status_code != 200 {
        return Err(format!("Registration rejected: HTTP {}", response.status_code));
    }
    Ok(())
}

/// For the dishonest endpoint of a demo only: takes the releases of the withheld rules out of a sealed window on its way to the control server.
/// A window header commits to the events alone, so the server takes the window, and only a proof shows that a match was not reported
fn withhold_releases(window: &mut SealedWindow, withheld: &[RuleId]) {
    window.releases.retain(|release| !withheld.contains(&release.found.rule));
}

impl Endpoint {
    /// Enrolls the endpoint and opens its ledger at the moment its timeline starts
    pub fn enroll(scenario: &Scenario, described: &scenario::Endpoint, started: u64) -> Result<Self, String> {
        let dir = scenario.state_dir.join(&described.hostname);
        std::fs::create_dir_all(&dir).map_err(|e| format!("Failed to create {}: {}", dir.display(), e))?;
        register(&scenario.server, &dir, described)?;

        let link = ControlLink::open_trusting(scenario.server.clone(), &dir, None, scenario.deployment_key()?)?;
        let ledger = link.open_ledger(started)?;
        Ok(Endpoint {
            hostname: described.hostname.clone(),
            link,
            ledger,
            prover: scenario.prover.clone().filter(|_| described.proving),
            withheld: described.withheld()?,
            stays_up: described.stays_up,
            clock: started,
            last_beat: None,
            lifecycle: Vec::new(),
            proof: None,
            proofs: 0,
            proof_failed: false,
            prove_not_before: Instant::now(),
            proving_rests_until: Instant::now(),
        })
    }

    pub fn hostname(&self) -> &str {
        &self.hostname
    }

    pub fn stays_up(&self) -> bool {
        self.stays_up
    }

    pub fn proved(&self) -> bool {
        self.proofs > 0
    }

    /// Walks the timeline. The sensor looks every few seconds and at every event, a window is sealed when the ledger says it is due,
    /// and every sealed window is delivered before the next one is sealed
    pub fn play(&mut self, timeline: Vec<SystemEvent>) -> Result<(), String> {
        for event in timeline {
            let at = scenario::timestamp(&event);
            self.idle_until(at)?;
            self.clock = at;

            match SensorEvent::try_from(event) {
                Ok(sensed) => {
                    if self.ledger.admit(&[sensed]) > 0 {
                        eprintln!("{}: an event at {} is too large to seal, it is left out and its window says so", self.hostname, at);
                    }
                    self.poll(at)?;
                }
                Err(SystemEvent::AgentStopping(stopping)) => {
                    // As on the agent: what the sensor saw is sealed and delivered first, and the stop notice is a request of its own
                    self.report()?;
                    self.ledger.seal_now(at)?;
                    self.deliver(at)?;
                    self.lifecycle.push(SystemEvent::AgentStopping(stopping));
                    self.report()?;
                }
                Err(reported) => {
                    if matches!(reported, SystemEvent::Heartbeat(_)) {
                        self.last_beat = Some(at);
                    }
                    self.lifecycle.push(reported);
                    if self.lifecycle.len() >= LIFECYCLE_BATCH {
                        self.report()?;
                    }
                }
            }
        }
        self.report()
    }

    /// Keeps a running endpoint alive: the sensor goes on looking and finds nothing, and a heartbeat goes out when one is due
    pub fn keep_up(&mut self, now: u64, heartbeat_seconds: u64) -> Result<(), String> {
        self.idle_until(now)?;
        if self.last_beat.is_none_or(|last| now >= last + heartbeat_seconds) {
            self.last_beat = Some(now);
            self.lifecycle.push(SystemEvent::Heartbeat(HeartbeatEvent { timestamp: now }));
            self.report()?;
        }
        Ok(())
    }

    fn idle_until(&mut self, now: u64) -> Result<(), String> {
        while self.clock + POLL_SECONDS <= now {
            self.clock += POLL_SECONDS;
            self.poll(self.clock)?;
        }
        Ok(())
    }

    fn poll(&mut self, now: u64) -> Result<(), String> {
        self.ledger.seal_due(now)?;
        self.deliver(now)
    }

    /// Sends the sealed windows in order, as the agent does, and follows a refusal the deployment signed onto the position it names
    fn deliver(&mut self, now: u64) -> Result<(), String> {
        let proving = self.prover.is_some();
        while let Some(mut window) = self.ledger.next_undelivered()? {
            withhold_releases(&mut window, &self.withheld);
            let delivery = {
                let _turn = one_at_a_time();
                self.link.send_window(&window, proving, TIMEOUT_SECS)?
            };
            match delivery {
                WindowDelivery::Accepted => self.ledger.delivered(window.header.window, proving)?,
                WindowDelivery::Refused(position) => {
                    self.discard_proof();
                    self.ledger.rebase(position.epoch, position.next_window, position.next_index, position.head, now)?;
                    return Err(format!("The control server refused window {}, its copy of the chain stands at window {}", window.header.window, position.next_window));
                }
            }
        }
        Ok(())
    }

    fn report(&mut self) -> Result<(), String> {
        if self.lifecycle.is_empty() {
            return Ok(());
        }
        let response = {
            let _turn = one_at_a_time();
            self.link.send_events(std::mem::take(&mut self.lifecycle), TIMEOUT_SECS)?
        };
        match response.status_code {
            200 => Ok(()),
            status => Err(format!("The control server answered what the agent reported with HTTP {}", status)),
        }
    }

    /// Whether nothing waits for this endpoint's first proof any more: it has no prover, made one, failed at one, or has nothing to prove
    pub fn first_proof_settled(&self) -> bool {
        self.prover.is_none() || self.proofs > 0 || self.proof_failed || (self.proof.is_none() && self.ledger.unproven() == 0)
    }

    pub fn is_proving(&self) -> bool {
        self.proof.is_some()
    }

    /// Moves proving one step without waiting for the prover, as the agent does: builds the input of the next proof from the ledger,
    /// runs the prover on it when one may start, and hands the receipt to the control server. True once a proof reached the server in this step
    pub fn prove(&mut self, may_start: bool) -> Result<bool, String> {
        let Some(program) = self.prover.clone() else {
            return Ok(false);
        };
        if Instant::now() < self.prove_not_before {
            return Ok(false);
        }

        let stepped = match self.proof.take() {
            Some(proof) => self.finish_proof(proof),
            None if may_start => self.start_proof(&program).map(|()| false),
            None => Ok(false),
        };
        if stepped.is_err() {
            self.discard_proof();
            self.proof_failed = true;
            self.prove_not_before = Instant::now() + PROOF_RETRY_AFTER;
        }
        stepped
    }

    fn start_proof(&mut self, program: &Path) -> Result<(), String> {
        // As on the agent, proving rests after a proof, and the rest ends early once a whole proof's worth of events waits
        if Instant::now() < self.proving_rests_until && self.ledger.unproven_events() < DEFAULT_PROOF_EVENTS {
            return Ok(());
        }
        let Some(input) = self.ledger.proof_input(DEFAULT_PROOF_EVENTS as usize)? else {
            return Ok(());
        };

        let encoded = input.to_bytes();
        let (journal, state) = proof::run(input)?;
        let dir = self.ledger.dir().join(PROOFS_DIR);
        std::fs::create_dir_all(&dir).map_err(|e| format!("Failed to create {}: {}", dir.display(), e))?;
        let input = dir.join(format!("input-{}.bin", journal.first_window));
        let receipt = dir.join(format!("receipt-{}.bin", journal.first_window));
        std::fs::write(&input, encoded).map_err(|e| format!("Failed to write {}: {}", input.display(), e))?;

        let prover = Command::new(program)
            .arg("prove")
            .arg(&input)
            .arg(&receipt)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .spawn()
            .map_err(|e| format!("Failed to start {}: {}", program.display(), e))?;
        self.proof = Some(Proof { prover, input, receipt, journal, state });
        Ok(())
    }

    fn finish_proof(&mut self, mut proof: Proof) -> Result<bool, String> {
        match proof.prover.try_wait() {
            Ok(Some(status)) if status.success() => {
                let receipt = std::fs::read(&proof.receipt).map_err(|e| format!("The prover left no receipt: {}", e))?;
                {
                    let _turn = one_at_a_time();
                    self.link.send_proof(&receipt, PROOF_TIMEOUT_SECS)?;
                }
                self.ledger.proven(&proof.journal, proof.state)?;
                let _ = std::fs::remove_file(&proof.input);
                let _ = std::fs::remove_file(&proof.receipt);
                self.proofs += 1;
                self.proving_rests_until = Instant::now() + Duration::from_secs(DEFAULT_PROOF_REST_SECS);
                Ok(true)
            }
            Ok(Some(status)) => Err(format!("The prover ended with {}", status)),
            Ok(None) => {
                self.proof = Some(proof);
                Ok(false)
            }
            Err(e) => {
                self.proof = Some(proof);
                Err(format!("Failed to wait for the prover: {}", e))
            }
        }
    }

    /// Ends the proof that is being made, if any, and removes what was written for it
    fn discard_proof(&mut self) {
        if let Some(mut proof) = self.proof.take() {
            let _ = proof.prover.kill();
            let _ = proof.prover.wait();
            let _ = std::fs::remove_file(&proof.input);
            let _ = std::fs::remove_file(&proof.receipt);
        }
    }
}

impl Drop for Endpoint {
    fn drop(&mut self) {
        self.discard_proof();
    }
}
