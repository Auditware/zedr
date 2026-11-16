use std::collections::{BTreeMap, VecDeque};
use std::process::Command;
use std::sync::{mpsc, Arc, Mutex, TryLockError};
use std::thread;
use std::time::{Duration, Instant};

use ed25519_dalek::VerifyingKey;
use serde::Deserialize;
use zedr_protocol::{HeartbeatEvent, ShellCommand, StopReason, SystemEvent, UpgradeCommand};

use crate::link::{unix_now, ControlLink, HostDescription};
use crate::sensor::{Outbox, Sensor, Source};
use crate::shell::{self, CommandResult, ShellSessions};
use crate::Refusal;

const EVENT_TIMEOUT_SECS: u64 = 30;
const DEFAULT_HEARTBEAT_INTERVAL_SECS: u64 = 30;
const DEFAULT_SENSOR_INTERVAL_SECS: u64 = 5;
const DEFAULT_PERSISTENCE_INTERVAL_SECS: u64 = 60;
const DEFAULT_PACKAGE_INTERVAL_SECS: u64 = 300;
const SENSOR_QUEUE_LIMIT: usize = 20_000;
const SENSOR_BATCH_SIZE: usize = 200;
const SHELL_RESULT_QUEUE_LIMIT: usize = 16;
const REGISTRATION_RETRY_START: Duration = Duration::from_secs(30);
const REGISTRATION_RETRY_LIMIT: Duration = Duration::from_secs(600);

pub trait Platform: Send + Sync + 'static {
    fn log(&self, message: &str);
    fn shell_invocation(&self, command_text: &str) -> Command;
    fn upgrade(&self, command: UpgradeCommand);
}

fn interval(variable: &str, default_seconds: u64) -> Duration {
    let seconds = match std::env::var(variable).ok().and_then(|value| value.parse::<u64>().ok()) {
        Some(seconds) if seconds > 0 => seconds,
        _ => default_seconds,
    };
    Duration::from_secs(seconds)
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
    #[serde(default)]
    shell_command: Option<ShellCommand>,
}

struct RegistrationRetry {
    not_before: Instant,
    delay: Duration,
}

#[derive(Default)]
struct ShellResults {
    queued: VecDeque<CommandResult>,
    reported: Option<String>,
}

enum Delivery {
    Accepted,
    Refused(String),
    Unanswered(String),
}

pub struct Runtime<P: Platform> {
    link: Arc<ControlLink>,
    platform: P,
    host: HostDescription,
    sessions: ShellSessions,
    shell_results: Mutex<ShellResults>,
    registration_retry: Mutex<RegistrationRetry>,
    trusted_key: fn() -> Result<VerifyingKey, String>,
}

impl<P: Platform> Runtime<P> {
    pub fn new(link: Arc<ControlLink>, platform: P, host: HostDescription) -> Self {
        let runtime = Self {
            link,
            platform,
            host,
            sessions: ShellSessions::new(),
            shell_results: Mutex::new(ShellResults::default()),
            registration_retry: Mutex::new(RegistrationRetry {
                not_before: Instant::now(),
                delay: REGISTRATION_RETRY_START,
            }),
            trusted_key: crate::signing_public_key,
        };
        runtime.answer_commands_of_an_earlier_run();
        runtime
    }

    fn answer_commands_of_an_earlier_run(&self) {
        let unanswered = match self.link.unanswered_shell_commands() {
            Ok(unanswered) => unanswered,
            Err(e) => {
                self.platform.log(&format!("Shell and upgrade commands are refused: {}", e));
                return;
            }
        };

        for command in unanswered {
            let Some(session_id) = &command.shell_session_id else { continue };
            self.platform.log(&format!(
                "Shell command {} of session {} had no answer when this agent stopped, answering it without running it",
                command.nonce, session_id
            ));
            self.queue_shell_result(CommandResult::interrupted(session_id, &command.nonce));
        }
    }

    fn shell_command_answered(&self, result: &CommandResult) {
        if let Err(e) = self.link.shell_command_answered(result.command_id()) {
            self.platform.log(&format!("Shell command {} stays recorded as unanswered: {}", result.command_id(), e));
        }
    }

    pub fn run_until_stopped(
        self: &Arc<Self>,
        stop: &mpsc::Receiver<StopReason>,
        heartbeat_interval: Duration,
    ) -> Option<StopReason> {
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
        let runtime = Arc::clone(self);
        let sensor = Sensor::new(source, std::process::id(), intervals.persistence.as_secs(), intervals.packages.as_secs());
        thread::spawn(move || runtime.run_sensor(sensor, intervals.poll));
    }

    fn run_sensor<S: Source>(&self, mut sensor: Sensor<S>, interval: Duration) {
        let batch_bytes = match self.link.event_bytes_per_batch() {
            Ok(batch_bytes) => batch_bytes,
            Err(e) => {
                self.platform.log(&format!("Sensor cannot start: {}", e));
                return;
            }
        };
        let mut outbox = Outbox::new(SENSOR_QUEUE_LIMIT, batch_bytes);
        let mut reported_errors = Vec::new();
        let mut reported_delivery = Ok(());
        let mut announced = false;

        loop {
            let observation = sensor.poll(unix_now());

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

            outbox.push(observation.events);
            let unsendable = outbox.take_unsendable();
            if unsendable > 0 {
                self.platform.log(&format!("Sensor produced {} events larger than a whole batch, discarded them", unsendable));
            }
            let dropped = outbox.take_dropped();
            if dropped > 0 {
                self.platform.log(&format!("Sensor queue is full, dropped the {} oldest events", dropped));
            }

            let delivery = self.deliver(&mut outbox);
            if delivery != reported_delivery {
                match &delivery {
                    Ok(()) => self.platform.log("Sensor events are being delivered again"),
                    Err(e) => self.platform.log(&format!("Sensor events are queued, {} waiting: {}", outbox.len(), e)),
                }
                reported_delivery = delivery;
            }

            thread::sleep(interval);
        }
    }

    fn deliver(&self, outbox: &mut Outbox) -> Result<(), String> {
        let mut refused = BTreeMap::new();
        let delivery = self.send_queued(outbox, &mut refused);

        for (status, events) in refused {
            self.platform.log(&format!(
                "Server answered HTTP {} to {} sensor events sent on their own, discarded them",
                status, events
            ));
        }

        delivery
    }

    fn send_queued(&self, outbox: &mut Outbox, refused: &mut BTreeMap<i32, u64>) -> Result<(), String> {
        let mut size = SENSOR_BATCH_SIZE;

        while !outbox.is_empty() {
            let batch = outbox.next_batch(size);
            let sent = batch.len();
            let response = self.link.send_events(batch, EVENT_TIMEOUT_SECS)?;

            match response.status_code {
                200 => {
                    outbox.confirm(sent);
                    size = (size * 2).min(SENSOR_BATCH_SIZE);
                }
                400 | 413 | 422 if sent > 1 => size = sent / 2,
                status @ (400 | 413 | 422) => {
                    outbox.confirm(sent);
                    *refused.entry(status).or_default() += 1;
                }
                status => return Err(format!("HTTP {}", status)),
            }
        }

        Ok(())
    }

    pub fn notify_stopping(&self, reason: StopReason) {
        match self.link.notify_stopping(reason) {
            Ok(status) => self.platform.log(&format!("Stop notice response: {}", status)),
            Err(e) => self.platform.log(&format!("Stop notice failed: {}", e)),
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

        for event in self.sessions.expire() {
            self.send(SystemEvent::ShellSessionTerminated(event));
        }
    }

    fn heartbeat(self: &Arc<Self>) -> Result<(), String> {
        let heartbeat = SystemEvent::Heartbeat(HeartbeatEvent { timestamp: unix_now() });
        let response = self.link.send_events(vec![heartbeat], EVENT_TIMEOUT_SECS)?;

        match response.status_code {
            200 => {
                self.retry_shell_results();
                let reply: HeartbeatReply = serde_json::from_slice(response.as_bytes())
                    .map_err(|e| format!("Unreadable heartbeat response: {}", e))?;
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

        if let Some(command) = reply.shell_command {
            let runtime = Arc::clone(self);
            thread::spawn(move || runtime.run_shell_command(command));
        }
    }

    fn run_shell_command(&self, command: ShellCommand) {
        let verified = match (self.trusted_key)() {
            Ok(key) => crate::verify_shell_command_with_key(&key, &command, self.link.agent_id()),
            Err(e) => Err(Refusal::Other(e)),
        };
        match verified {
            Ok(()) => {}
            Err(Refusal::OutOfDate(reason)) => {
                self.answer_without_running(&command, &reason);
                return;
            }
            Err(Refusal::Other(reason)) => {
                self.platform.log(&format!("Shell command verification failed: {}", reason));
                return;
            }
        }

        if let Err(e) = self.link.accept_shell_command(&command) {
            self.platform.log(&format!("Shell command is not run: {}", e));
            return;
        }

        self.platform.log(&format!("Shell command for session {}: {}", command.session_id, command.command_text));

        if let Err(e) = self.sessions.touch(&command.session_id) {
            self.platform.log(&format!("Failed to track shell session: {}", e));
            return;
        }

        let invocation = self.platform.shell_invocation(&command.command_text);
        let result = match shell::execute(invocation, &command, shell::command_timeout()) {
            Ok(result) => {
                self.platform.log(&format!("Shell command finished with exit code {}", result.exit_code()));
                result
            }
            Err(e) => {
                self.platform.log(&format!("Shell command execution failed: {}", e));
                CommandResult::failed(&command, &e)
            }
        };

        if let Err(e) = self.sessions.touch(&command.session_id) {
            self.platform.log(&format!("Failed to track shell session: {}", e));
        }

        self.queue_shell_result(result);
        self.deliver_shell_results();
    }

    fn answer_without_running(&self, command: &ShellCommand, reason: &str) {
        if let Err(e) = self.link.accept_shell_command(command) {
            self.platform.log(&format!("Shell command is not run: {}. It is not answered: {}", reason, e));
            return;
        }

        self.platform.log(&format!(
            "Shell command for session {} is answered and not run: {}",
            command.session_id, reason
        ));
        self.queue_shell_result(CommandResult::not_run(command, reason));
        self.deliver_shell_results();
    }

    fn queue_shell_result(&self, result: CommandResult) {
        let mut results = match self.shell_results.lock() {
            Ok(results) => results,
            Err(e) => {
                self.platform.log(&format!("Failed to lock shell command results: {}", e));
                return;
            }
        };

        results.queued.push_back(result);
        if results.queued.len() > SHELL_RESULT_QUEUE_LIMIT {
            results.queued.pop_front();
            self.platform.log("Shell command result queue is full, dropped the oldest result");
        }
    }

    fn retry_shell_results(self: &Arc<Self>) {
        let waiting = match self.shell_results.try_lock() {
            Ok(results) => !results.queued.is_empty(),
            Err(_) => false,
        };

        if waiting {
            let runtime = Arc::clone(self);
            thread::spawn(move || runtime.deliver_shell_results());
        }
    }

    fn deliver_shell_results(&self) {
        let mut results = match self.shell_results.try_lock() {
            Ok(results) => results,
            Err(TryLockError::WouldBlock) => return,
            Err(TryLockError::Poisoned(e)) => {
                self.platform.log(&format!("Failed to lock shell command results: {}", e));
                return;
            }
        };

        let batch_bytes = match self.link.event_bytes_per_batch() {
            Ok(batch_bytes) => batch_bytes,
            Err(e) => {
                self.platform.log(&format!("Shell command results cannot be sent: {}", e));
                return;
            }
        };

        let mut unanswered = None;
        while let Some(result) = results.queued.front() {
            match self.report(result, batch_bytes) {
                Delivery::Accepted => self.shell_command_answered(result),
                Delivery::Refused(reason) => {
                    self.platform.log(&format!("Shell command result was discarded: {}", reason));
                    self.shell_command_answered(result);
                }
                Delivery::Unanswered(reason) => {
                    unanswered = Some(reason);
                    break;
                }
            }
            results.queued.pop_front();
        }

        if unanswered != results.reported {
            match &unanswered {
                Some(reason) => self.platform.log(&format!(
                    "Shell command results are queued, {} waiting: {}",
                    results.queued.len(),
                    reason
                )),
                None => self.platform.log("Shell command results are being delivered again"),
            }
            results.reported = unanswered;
        }
    }

    fn report(&self, result: &CommandResult, batch_bytes: usize) -> Delivery {
        let mut room = batch_bytes;
        let mut refused_bytes = None;

        loop {
            let fitted = match result.event(room) {
                Ok(fitted) => fitted,
                Err(e) => return Delivery::Refused(e),
            };
            let sent_bytes = fitted.encoded_bytes;
            if refused_bytes.is_some_and(|refused_bytes| sent_bytes >= refused_bytes) {
                return Delivery::Refused("HTTP 413 and no output left to cut".to_string());
            }

            let event = SystemEvent::ShellCommandExecuted(fitted.event);
            let response = match self.link.send_events(vec![event], EVENT_TIMEOUT_SECS) {
                Ok(response) => response,
                Err(e) => return Delivery::Unanswered(e),
            };

            match response.status_code {
                200 => {
                    if refused_bytes.is_some() {
                        self.platform.log(&format!(
                            "Server answered HTTP 413 to the shell command result until it was cut to {} bytes",
                            sent_bytes
                        ));
                    }
                    return Delivery::Accepted;
                }
                413 => {
                    refused_bytes = Some(sent_bytes);
                    room = sent_bytes / 2;
                }
                status @ (400 | 422) => return Delivery::Refused(format!("HTTP {}", status)),
                status => return Delivery::Unanswered(format!("HTTP {}", status)),
            }
        }
    }

    fn send(&self, event: SystemEvent) {
        match self.link.send_events(vec![event], EVENT_TIMEOUT_SECS) {
            Ok(response) if response.status_code == 200 => {}
            Ok(response) => self.platform.log(&format!("Event was not accepted: HTTP {}", response.status_code)),
            Err(e) => self.platform.log(&format!("Failed to send event: {}", e)),
        }
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use ed25519_dalek::{Signature, Signer, SigningKey, Verifier};
    use std::collections::HashMap;
    use std::io::{BufRead, BufReader, Read, Write};
    use std::net::TcpListener;
    use std::path::PathBuf;
    use zedr_protocol::{shell_command_signing_bytes, ProcessAction, ProcessEvent, MAX_EVENT_BATCH_BYTES, SIGNATURE_HEADER};

    const NO_ANSWER: u16 = 0;

    struct Received {
        path: String,
        signature: Option<String>,
        body: String,
        answer: u16,
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
                    if status == NO_ANSWER {
                        continue;
                    }
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
        Received { path, signature, body: String::from_utf8(body).unwrap(), answer: 0 }
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

        fn shell_invocation(&self, command_text: &str) -> Command {
            let mut command = Command::new("/bin/sh");
            command.arg("-c").arg(command_text);
            command
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
        HostDescription {
            hostname: "test-host".to_string(),
            os_version: "Test OS 1".to_string(),
            agent_version: "0.1.0".to_string(),
        }
    }

    fn deployment_key() -> SigningKey {
        SigningKey::from_bytes(&[9u8; 32])
    }

    fn trust_deployment_key() -> Result<VerifyingKey, String> {
        Ok(deployment_key().verifying_key())
    }

    fn runtime(server: &StubServer, dir: &std::path::Path) -> (Arc<Runtime<Arc<TestPlatform>>>, Arc<TestPlatform>) {
        let platform = Arc::new(TestPlatform::default());
        let link = Arc::new(ControlLink::open_with_key_id(server.url.clone(), dir).unwrap());
        let mut runtime = Runtime::new(link, Arc::clone(&platform), host());
        runtime.trusted_key = trust_deployment_key;
        (Arc::new(runtime), platform)
    }

    fn signed_shell_reply(key: &SigningKey, agent_id: &str, command_text: &str, nonce: &str) -> String {
        signed_shell_reply_issued_at(key, agent_id, command_text, nonce, unix_now())
    }

    fn signed_shell_reply_issued_at(key: &SigningKey, agent_id: &str, command_text: &str, nonce: &str, issued_at: u64) -> String {
        let bytes = shell_command_signing_bytes(agent_id, "session-1", command_text, nonce, issued_at).unwrap();
        serde_json::json!({
            "shell_command": {
                "session_id": "session-1",
                "agent_id": agent_id,
                "command_text": command_text,
                "signature": key.sign(&bytes).to_bytes().to_vec(),
                "issued_at": issued_at,
                "nonce": nonce,
            }
        })
        .to_string()
    }

    fn accept_everything(_: &Received) -> (u16, String) {
        (200, "{}".to_string())
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
    fn test_shell_command_signed_by_the_deployment_runs_and_reports() {
        let dir = state_dir("shell-runs");
        let agent_id = ControlLink::open_with_key_id("http://unused".to_string(), &dir).unwrap().agent_id().to_string();
        let reply = signed_shell_reply(&deployment_key(), &agent_id, "echo from-agent; exit 4", "runtime-shell-runs");
        let server = StubServer::start(move |request| {
            if request.body.contains("Heartbeat") {
                (200, reply.clone())
            } else {
                (200, "{}".to_string())
            }
        });
        let (runtime, _) = runtime(&server, &dir);

        runtime.tick();

        let executed = server.wait_for_event("ShellCommandExecuted").expect("the result is reported");
        assert_eq!(executed["stdout"], "from-agent\n");
        assert_eq!(executed["exit_code"], 4);
        assert_eq!(executed["session_id"], "session-1");
        assert_eq!(executed["command_id"], "runtime-shell-runs");
        assert!(wait_until(|| recorded_as_answered(&dir, "runtime-shell-runs")));

        std::fs::remove_dir_all(&dir).unwrap();
    }

    fn assert_command_never_runs(name: &str, reply_for: impl Fn(&str, &std::path::Path) -> String, expected_log: &str) {
        let dir = state_dir(name);
        let marker = dir.join("command-ran");
        let agent_id = ControlLink::open_with_key_id("http://unused".to_string(), &dir).unwrap().agent_id().to_string();
        let reply = reply_for(&agent_id, &marker);
        let server = StubServer::start(move |request| {
            if request.body.contains("Heartbeat") {
                (200, reply.clone())
            } else {
                (200, "{}".to_string())
            }
        });
        let (runtime, platform) = runtime(&server, &dir);

        runtime.tick();

        let deadline = Instant::now() + Duration::from_secs(5);
        while !platform.logged("Shell command verification failed") && Instant::now() < deadline {
            thread::sleep(Duration::from_millis(20));
        }
        thread::sleep(Duration::from_millis(200));

        assert!(platform.logged(expected_log), "expected a refusal mentioning {:?}", expected_log);
        assert!(!marker.exists(), "the command must not have run");
        assert!(server.requests_to("/api/events").iter().all(|batch| !batch.to_string().contains("ShellCommandExecuted")));

        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn test_shell_command_signed_by_another_key_never_runs() {
        assert_command_never_runs(
            "shell-wrong-key",
            |agent_id, marker| signed_shell_reply(&SigningKey::from_bytes(&[8u8; 32]), agent_id, &format!("touch {}", marker.display()), "runtime-wrong-key"),
            "Signature verification failed",
        );
    }

    #[test]
    fn test_shell_command_issued_for_another_agent_never_runs() {
        assert_command_never_runs(
            "shell-other-agent",
            |_, marker| signed_shell_reply(&deployment_key(), "some-other-agent", &format!("touch {}", marker.display()), "runtime-other-agent"),
            "different agent",
        );
    }

    #[test]
    fn test_old_shell_command_signed_by_another_key_gets_no_answer() {
        assert_command_never_runs(
            "shell-old-wrong-key",
            |agent_id, marker| {
                signed_shell_reply_issued_at(
                    &SigningKey::from_bytes(&[8u8; 32]),
                    agent_id,
                    &format!("touch {}", marker.display()),
                    "runtime-old-wrong-key",
                    unix_now() - 310,
                )
            },
            "Signature verification failed",
        );
    }

    #[test]
    fn test_old_shell_command_issued_for_another_agent_gets_no_answer() {
        assert_command_never_runs(
            "shell-old-other-agent",
            |_, marker| {
                signed_shell_reply_issued_at(
                    &deployment_key(),
                    "some-other-agent",
                    &format!("touch {}", marker.display()),
                    "runtime-old-other-agent",
                    unix_now() - 310,
                )
            },
            "different agent",
        );
    }

    fn recorded_without_an_answer(dir: &std::path::Path, nonce: &str) -> bool {
        let Ok(raw) = std::fs::read_to_string(dir.join("accepted-commands.json")) else { return true };
        let Ok(record) = serde_json::from_str::<serde_json::Value>(&raw) else { return true };
        record.as_array().is_some_and(|commands| commands.iter().any(|command| command["nonce"] == nonce && command["answered"] == false))
    }

    #[test]
    fn test_shell_command_refused_for_its_age_is_answered_once_and_never_run() {
        let cases = [("too-old", -310i64, "Command expired (older than 5 minutes)"), ("ahead", 70, "Command timestamp is in the future")];
        for (case, seconds_from_now, reason) in cases {
            let name = format!("shell-age-{}", case);
            let dir = state_dir(&name);
            let marker = dir.join("command-ran");
            let agent_id = ControlLink::open_with_key_id("http://unused".to_string(), &dir).unwrap().agent_id().to_string();
            let issued_at = (unix_now() as i64 + seconds_from_now) as u64;
            let reply = signed_shell_reply_issued_at(&deployment_key(), &agent_id, &format!("touch {}", marker.display()), &name, issued_at);
            let taking_results = Arc::new(Mutex::new(false));
            let gate = Arc::clone(&taking_results);
            let server = StubServer::start(move |request| match (request.body.contains("Heartbeat"), *gate.lock().unwrap()) {
                (true, false) => (200, reply.clone()),
                (false, false) => (503, "{}".to_string()),
                (_, true) => (200, "{}".to_string()),
            });
            let (runtime, platform) = runtime(&server, &dir);

            runtime.tick();
            assert!(wait_until(|| platform.logged(&format!("Shell command for session session-1 is answered and not run: {}", reason))));
            assert!(wait_until(|| platform.logged("Shell command results are queued, 1 waiting: HTTP 503")));

            runtime.tick();
            let handed_out_again = format!("Shell command is not run: {}. It is not answered: Command was already accepted by this agent", reason);
            assert!(wait_until(|| platform.logged(&handed_out_again)), "{:?}", platform.logs.lock().unwrap());

            *taking_results.lock().unwrap() = true;
            runtime.tick();
            assert!(wait_until(|| !shell_results(&server, 200).is_empty()), "the command is answered");
            assert!(wait_until(|| !recorded_without_an_answer(&dir, &name)));
            let answers = shell_results(&server, 200);
            assert_eq!(answers.len(), 1);
            assert_eq!(answers[0]["command_id"], name.as_str());
            assert_eq!(answers[0]["session_id"], "session-1");
            assert_eq!(answers[0]["exit_code"], -1);
            assert_eq!(answers[0]["stdout"], "");
            assert_eq!(answers[0]["stderr"], format!("[NOT RUN] {}", reason));

            assert_no_result_is_sent_after_another_heartbeat(&runtime, &server);
            assert!(!marker.exists(), "the command must not have run");
            assert!(!platform.logged("Shell command verification failed"));

            std::fs::remove_dir_all(&dir).unwrap();
        }
    }

    #[test]
    fn test_agent_that_was_not_sealed_by_a_control_server_runs_no_command() {
        let dir = state_dir("shell-unsealed");
        let marker = dir.join("command-ran");
        let agent_id = ControlLink::open_with_key_id("http://unused".to_string(), &dir).unwrap().agent_id().to_string();
        let reply = signed_shell_reply(&deployment_key(), &agent_id, &format!("touch {}", marker.display()), "runtime-unsealed");
        let server = StubServer::start(accept_everything);
        let platform = Arc::new(TestPlatform::default());
        let link = Arc::new(ControlLink::open_with_key_id(server.url.clone(), &dir).unwrap());
        let runtime = Runtime::new(link, Arc::clone(&platform), host());

        let reply: HeartbeatReply = serde_json::from_str(&reply).unwrap();
        runtime.run_shell_command(reply.shell_command.unwrap());

        assert!(platform.logged("not been patched"));
        assert!(!marker.exists());

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

    struct ScriptedSource {
        processes: Vec<(crate::sensor::ProcessKey, crate::sensor::ProcessDetails)>,
    }

    impl ScriptedSource {
        fn with(count: u32) -> Self {
            let processes = (1..=count)
                .map(|pid| {
                    (
                        crate::sensor::ProcessKey { pid, started: 1_000 + pid as u64, image: 1 },
                        crate::sensor::ProcessDetails {
                            ppid: pid.saturating_sub(1),
                            uid: 0,
                            executable_path: format!("/usr/bin/program-{}", pid),
                            command_line: vec![format!("program-{}", pid)],
                            started_at: 1_000 + pid as u64,
                        },
                    )
                })
                .collect();
            Self { processes }
        }
    }

    impl Source for ScriptedSource {
        fn processes(&mut self) -> Result<Vec<crate::sensor::ProcessKey>, String> {
            Ok(self.processes.iter().map(|(key, _)| *key).collect())
        }

        fn describe(&mut self, process: &crate::sensor::ProcessKey) -> Option<crate::sensor::ProcessDetails> {
            self.processes.iter().find(|(key, _)| key == process).map(|(_, details)| details.clone())
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

    fn every_50_milliseconds() -> SensorIntervals {
        SensorIntervals {
            poll: Duration::from_millis(50),
            persistence: Duration::from_secs(60),
            packages: Duration::from_secs(300),
        }
    }

    fn process_pids(server: &StubServer) -> Vec<u64> {
        server
            .received
            .lock()
            .unwrap()
            .iter()
            .filter(|request| request.path == "/api/events" && request.answer == 200)
            .flat_map(|request| request.json()["events"].as_array().cloned().unwrap_or_default())
            .filter_map(|event| event.get("Process").and_then(|process| process["pid"].as_u64()))
            .collect()
    }

    fn answers(server: &StubServer) -> Vec<u16> {
        server.received.lock().unwrap().iter().map(|request| request.answer).collect()
    }

    fn largest_request(server: &StubServer) -> usize {
        server.received.lock().unwrap().iter().map(|request| request.body.len()).max().unwrap()
    }

    fn refuse_above(limit: usize) -> impl Fn(&Received) -> (u16, String) {
        move |request| if request.body.len() > limit { (413, "{}".to_string()) } else { (200, "{}".to_string()) }
    }

    fn started(pid: u32, executable_path: &str, argument: &str) -> SystemEvent {
        SystemEvent::Process(ProcessEvent {
            timestamp: 1_000 + pid as u64,
            pid,
            ppid: 1,
            executable_path: executable_path.to_string(),
            command_line: vec![argument.to_string()],
            action: ProcessAction::Create,
            uid: 1000,
            hash: None,
        })
    }

    fn queued(runtime: &Runtime<Arc<TestPlatform>>, events: Vec<SystemEvent>) -> Outbox {
        let mut outbox = Outbox::new(SENSOR_QUEUE_LIMIT, runtime.link.event_bytes_per_batch().unwrap());
        outbox.push(events);
        outbox
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
    fn test_sensor_snapshot_is_delivered_in_order_and_in_batches() {
        let server = StubServer::start(accept_everything);
        let dir = state_dir("sensor-delivery");
        let (runtime, platform) = runtime(&server, &dir);

        runtime.start_sensor(ScriptedSource::with(450), every_50_milliseconds());

        assert!(wait_until(|| process_pids(&server).len() == 450));
        assert_eq!(process_pids(&server), (1..=450).collect::<Vec<u64>>());
        let batch_sizes: Vec<usize> = server.requests_to("/api/events").iter().map(|batch| batch["events"].as_array().unwrap().len()).collect();
        assert_eq!(batch_sizes, vec![200, 200, 50]);
        assert!(platform.logged("Sensor started, 450 processes, 0 persistence items and 0 packages"));

        thread::sleep(Duration::from_millis(200));
        assert_eq!(process_pids(&server).len(), 450, "an unchanged system sends nothing more");

        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn test_sensor_events_wait_for_the_server_to_accept_the_agent() {
        let accepting = Arc::new(Mutex::new(false));
        let gate = Arc::clone(&accepting);
        let server = StubServer::start(move |_| if *gate.lock().unwrap() { (200, "{}".to_string()) } else { (401, "{}".to_string()) });
        let dir = state_dir("sensor-queued");
        let (runtime, platform) = runtime(&server, &dir);

        runtime.start_sensor(ScriptedSource::with(3), every_50_milliseconds());
        assert!(wait_until(|| platform.logged("Sensor events are queued, 3 waiting: HTTP 401")));

        server.received.lock().unwrap().clear();
        *accepting.lock().unwrap() = true;

        assert!(wait_until(|| platform.logged("Sensor events are being delivered again")));
        assert_eq!(process_pids(&server), vec![1, 2, 3], "the queued snapshot arrives once, complete and in order");

        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn test_two_hundred_events_with_worst_case_command_lines_are_all_delivered() {
        let server = StubServer::start(refuse_above(MAX_EVENT_BATCH_BYTES));
        let dir = state_dir("sensor-worst-case");
        let (runtime, platform) = runtime(&server, &dir);
        let control_characters = "\u{1}".repeat(4096);
        let mut outbox = queued(&runtime, (1..=200).map(|pid| started(pid, &control_characters, &control_characters)).collect());
        assert_eq!(outbox.len(), 200);

        assert_eq!(runtime.deliver(&mut outbox), Ok(()));

        assert!(outbox.is_empty());
        assert_eq!(process_pids(&server), (1..=200).collect::<Vec<u64>>(), "every event arrives once and in order");
        assert!(answers(&server).iter().all(|answer| *answer == 200), "no batch was larger than the server reads: {:?}", answers(&server));
        assert!(largest_request(&server) > MAX_EVENT_BATCH_BYTES - 6 * 2 * 4096 - 1024, "a batch is filled up to the limit");
        assert_eq!(answers(&server).len(), 5, "200 events of 49 KB at 2 MiB a batch");
        assert!(!platform.logged("discarded"));

        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn test_event_the_server_refuses_is_discarded_without_the_events_around_it() {
        let server = StubServer::start(|request| {
            if request.body.contains("unknown-to-this-server") {
                (400, "{}".to_string())
            } else {
                (200, "{}".to_string())
            }
        });
        let dir = state_dir("sensor-refused-event");
        let (runtime, platform) = runtime(&server, &dir);
        let refused = [137, 138, 302];
        let events = (1..=450)
            .map(|pid| started(pid, "/usr/bin/program", if refused.contains(&pid) { "unknown-to-this-server" } else { "--flag" }))
            .collect();
        let mut outbox = queued(&runtime, events);

        assert_eq!(runtime.deliver(&mut outbox), Ok(()));

        assert!(outbox.is_empty());
        assert_eq!(
            process_pids(&server),
            (1..=450).filter(|pid| !refused.contains(&(*pid as u32))).collect::<Vec<u64>>(),
            "every other event arrives once and in order"
        );
        assert!(platform.logged("Server answered HTTP 400 to 3 sensor events sent on their own, discarded them"));
        assert!(answers(&server).len() < 64, "narrowing down takes tens of requests, not one per event: {}", answers(&server).len());

        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn test_limit_the_agent_does_not_know_about_costs_requests_and_no_event() {
        let limit_of_a_proxy = 64 * 1024;
        let server = StubServer::start(refuse_above(limit_of_a_proxy));
        let dir = state_dir("sensor-proxy-limit");
        let (runtime, platform) = runtime(&server, &dir);
        let argument = "a".repeat(1024);
        let mut outbox = queued(&runtime, (1..=450).map(|pid| started(pid, "/usr/bin/program", &argument)).collect());

        assert_eq!(runtime.deliver(&mut outbox), Ok(()));

        assert!(outbox.is_empty());
        assert_eq!(process_pids(&server), (1..=450).collect::<Vec<u64>>());
        assert!(answers(&server).contains(&413));
        assert!(!platform.logged("discarded"));

        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn test_event_too_large_for_the_route_to_the_server_is_discarded_alone() {
        let limit_of_a_proxy = 64 * 1024;
        let server = StubServer::start(refuse_above(limit_of_a_proxy));
        let dir = state_dir("sensor-proxy-limit-one-event");
        let (runtime, platform) = runtime(&server, &dir);
        let events = (1..=50).map(|pid| started(pid, "/usr/bin/program", &"a".repeat(if pid == 20 { 2 * limit_of_a_proxy } else { 16 }))).collect();
        let mut outbox = queued(&runtime, events);

        assert_eq!(runtime.deliver(&mut outbox), Ok(()));

        assert_eq!(process_pids(&server), (1..=50).filter(|pid| *pid != 20).collect::<Vec<u64>>());
        assert!(platform.logged("Server answered HTTP 413 to 1 sensor events sent on their own, discarded them"));

        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn test_batch_the_server_does_not_answer_for_stays_queued_and_whole() {
        for status in [401, 403, 409, 500, 503] {
            let server = StubServer::start(move |_| (status, "{}".to_string()));
            let dir = state_dir(&format!("sensor-kept-{}", status));
            let (runtime, platform) = runtime(&server, &dir);
            let mut outbox = queued(&runtime, (1..=450).map(|pid| started(pid, "/usr/bin/program", "--flag")).collect());

            assert_eq!(runtime.deliver(&mut outbox), Err(format!("HTTP {}", status)));

            assert_eq!(outbox.len(), 450);
            assert_eq!(answers(&server).len(), 1, "the batch is not split and not sent again in the same round");
            assert!(!platform.logged("discarded"));

            std::fs::remove_dir_all(&dir).unwrap();
        }
    }

    #[test]
    fn test_event_larger_than_a_whole_batch_is_left_out_and_the_rest_is_delivered() {
        let server = StubServer::start(refuse_above(MAX_EVENT_BATCH_BYTES));
        let dir = state_dir("sensor-oversized-event");
        let (runtime, platform) = runtime(&server, &dir);
        let mut source = ScriptedSource::with(5);
        source.processes[2].1.command_line = vec!["a".repeat(MAX_EVENT_BATCH_BYTES)];

        runtime.start_sensor(source, every_50_milliseconds());

        assert!(wait_until(|| process_pids(&server).len() == 4));
        assert_eq!(process_pids(&server), vec![1, 2, 4, 5]);
        assert!(platform.logged("Sensor produced 1 events larger than a whole batch, discarded them"));
        assert!(answers(&server).iter().all(|answer| *answer == 200), "what cannot fit is never sent");

        std::fs::remove_dir_all(&dir).unwrap();
    }

    fn issue_shell_command(
        name: &str,
        command_text: &str,
        answer_result: impl Fn(&Received) -> (u16, String) + Send + 'static,
    ) -> (Arc<Runtime<Arc<TestPlatform>>>, StubServer, Arc<TestPlatform>, PathBuf) {
        let dir = state_dir(name);
        let agent_id = ControlLink::open_with_key_id("http://unused".to_string(), &dir).unwrap().agent_id().to_string();
        let reply = signed_shell_reply(&deployment_key(), &agent_id, command_text, name);
        let server = StubServer::start(move |request| {
            if request.body.contains("Heartbeat") {
                (200, reply.clone())
            } else {
                answer_result(request)
            }
        });
        let (runtime, platform) = runtime(&server, &dir);

        runtime.tick();

        (runtime, server, platform, dir)
    }

    fn shell_results(server: &StubServer, answer: u16) -> Vec<serde_json::Value> {
        server
            .received
            .lock()
            .unwrap()
            .iter()
            .filter(|request| request.answer == answer && request.body.contains("ShellCommandExecuted"))
            .map(|request| request.json()["events"][0]["ShellCommandExecuted"].clone())
            .collect()
    }

    #[test]
    fn test_shell_result_larger_than_a_batch_is_cut_to_one_request_and_keeps_its_exit_code() {
        let (_, server, platform, dir) = issue_shell_command(
            "shell-large-result",
            "head -c 1100000 /dev/zero; head -c 1100000 /dev/zero >&2; exit 4",
            refuse_above(MAX_EVENT_BATCH_BYTES),
        );

        assert!(wait_until(|| !shell_results(&server, 200).is_empty()), "the result is reported");
        let executed = &shell_results(&server, 200)[0];
        assert_eq!(executed["exit_code"], 4);
        assert_eq!(executed["command_id"], "shell-large-result");
        for stream in ["stdout", "stderr"] {
            let output = executed[stream].as_str().unwrap();
            assert!(output.starts_with(&"\0".repeat(174_000)), "{} carries half of what one request holds", stream);
            assert!(output.ends_with(" BYTES TO FIT THE RESULT IN ONE REQUEST]"), "{} says that it was cut", stream);
        }
        assert!(answers(&server).iter().all(|answer| *answer == 200), "the result was never larger than the server reads: {:?}", answers(&server));
        assert!(largest_request(&server) <= MAX_EVENT_BATCH_BYTES);
        assert!(largest_request(&server) > MAX_EVENT_BATCH_BYTES - 64, "the request is filled up to the limit");
        assert!(!platform.logged("discarded") && !platform.logged("queued"));
        assert!(wait_until(|| recorded_as_answered(&dir, "shell-large-result")));

        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn test_shell_result_refused_for_its_size_is_sent_again_with_less_output() {
        let limit_of_a_proxy = 64 * 1024;
        let (_, server, platform, dir) = issue_shell_command(
            "shell-proxy-limit",
            "head -c 300000 /dev/zero | tr '\\0' 'a'; echo problem >&2; exit 3",
            refuse_above(limit_of_a_proxy),
        );

        assert!(wait_until(|| !shell_results(&server, 200).is_empty()), "the result is reported");
        let executed = &shell_results(&server, 200)[0];
        assert_eq!(executed["exit_code"], 3);
        assert_eq!(executed["stderr"], "problem\n");
        let stdout = executed["stdout"].as_str().unwrap();
        assert!(stdout.starts_with(&"a".repeat(limit_of_a_proxy / 2)));
        assert!(stdout.ends_with(" BYTES TO FIT THE RESULT IN ONE REQUEST]"));
        assert_eq!(shell_results(&server, 413).len(), 3, "refused at 300 KB, 150 KB and 75 KB");
        assert!(wait_until(|| platform.logged("Server answered HTTP 413 to the shell command result until it was cut to")));
        assert!(!platform.logged("discarded") && !platform.logged("queued"));
        assert!(wait_until(|| recorded_as_answered(&dir, "shell-proxy-limit")));

        std::fs::remove_dir_all(&dir).unwrap();
    }

    fn assert_no_result_is_sent_after_another_heartbeat(runtime: &Arc<Runtime<Arc<TestPlatform>>>, server: &StubServer) {
        let sent = server.received.lock().unwrap().iter().filter(|request| request.body.contains("ShellCommandExecuted")).count();
        let heartbeats = server.received.lock().unwrap().iter().filter(|request| request.body.contains("Heartbeat")).count();

        runtime.tick();
        thread::sleep(Duration::from_millis(200));

        let received = server.received.lock().unwrap();
        assert_eq!(received.iter().filter(|request| request.body.contains("Heartbeat")).count(), heartbeats + 1);
        assert_eq!(received.iter().filter(|request| request.body.contains("ShellCommandExecuted")).count(), sent);
    }

    #[test]
    fn test_shell_result_refused_for_its_size_without_output_is_discarded() {
        let (runtime, server, platform, dir) =
            issue_shell_command("shell-always-too-large", "head -c 10000 /dev/zero | tr '\\0' 'a'; exit 2", |_| (413, "{}".to_string()));

        assert!(wait_until(|| platform.logged("Shell command result was discarded: HTTP 413 and no output left to cut")));
        let refused = shell_results(&server, 413);
        assert!(refused.len() > 2 && refused.len() < 16, "every attempt is half the one before: {}", refused.len());
        let last = refused.last().unwrap();
        assert_eq!(last["exit_code"], 2);
        assert_eq!(last["stdout"], "\n[OUTPUT TRUNCATED AT 0 BYTES TO FIT THE RESULT IN ONE REQUEST]");
        assert!(wait_until(|| recorded_as_answered(&dir, "shell-always-too-large")), "a discarded result is not answered again after a restart");
        assert_no_result_is_sent_after_another_heartbeat(&runtime, &server);

        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn test_shell_result_the_server_cannot_read_is_discarded() {
        for status in [400, 422] {
            let name = format!("shell-unreadable-{}", status);
            let (runtime, server, platform, dir) = issue_shell_command(&name, "echo out; exit 1", move |_| (status, "{}".to_string()));

            assert!(wait_until(|| platform.logged(&format!("Shell command result was discarded: HTTP {}", status))));
            assert_eq!(shell_results(&server, status).len(), 1);
            assert!(wait_until(|| recorded_as_answered(&dir, &name)));
            assert_no_result_is_sent_after_another_heartbeat(&runtime, &server);
            assert!(!platform.logged("queued"));

            std::fs::remove_dir_all(&dir).unwrap();
        }
    }

    #[test]
    fn test_shell_result_the_server_did_not_take_is_sent_again_after_every_accepted_heartbeat() {
        for status in [401, 403, 409, 500, 503, NO_ANSWER] {
            let name = format!("shell-kept-{}", status);
            let runs = std::env::temp_dir().join(format!("zedr-runtime-{}-{}-runs", std::process::id(), name));
            let _ = std::fs::remove_file(&runs);
            let taking_results = Arc::new(Mutex::new(false));
            let gate = Arc::clone(&taking_results);
            let (runtime, server, platform, dir) = issue_shell_command(
                &name,
                &format!("echo ran >> {}; echo out; exit 5", runs.display()),
                move |_| if *gate.lock().unwrap() { (200, "{}".to_string()) } else { (status, "{}".to_string()) },
            );

            let seen_by_the_agent = if status == NO_ANSWER { 503 } else { status };
            assert!(
                wait_until(|| platform.logged(&format!("Shell command results are queued, 1 waiting: HTTP {}", seen_by_the_agent))),
                "{:?}",
                platform.logs.lock().unwrap()
            );
            assert_eq!(shell_results(&server, status).len(), 1);

            runtime.tick();
            assert!(wait_until(|| shell_results(&server, status).len() == 2), "the result is sent again after a heartbeat the server took");

            *taking_results.lock().unwrap() = true;
            runtime.tick();
            assert!(wait_until(|| platform.logged("Shell command results are being delivered again")));
            let delivered = shell_results(&server, 200);
            assert_eq!(delivered.len(), 1);
            assert_eq!(delivered[0]["command_id"], name.as_str());
            assert_eq!(delivered[0]["exit_code"], 5);
            assert_eq!(delivered[0]["stdout"], "out\n");

            assert_no_result_is_sent_after_another_heartbeat(&runtime, &server);
            assert_eq!(std::fs::read_to_string(&runs).unwrap(), "ran\n", "the command ran once, although every heartbeat handed it out again");
            assert!(!platform.logged("discarded"));
            assert!(recorded_as_answered(&dir, &name));

            std::fs::remove_file(&runs).unwrap();
            std::fs::remove_dir_all(&dir).unwrap();
        }
    }

    #[test]
    fn test_shell_result_waits_while_the_server_takes_no_heartbeat() {
        for status in [401, 503, NO_ANSWER] {
            let name = format!("shell-server-down-{}", status);
            let dir = state_dir(&name);
            let agent_id = ControlLink::open_with_key_id("http://unused".to_string(), &dir).unwrap().agent_id().to_string();
            let reply = signed_shell_reply(&deployment_key(), &agent_id, "echo out; exit 6", &name);
            let down = Arc::new(Mutex::new(false));
            let switch = Arc::clone(&down);
            let server = StubServer::start(move |request| {
                let mut down = switch.lock().unwrap();
                if *down {
                    (status, "{}".to_string())
                } else if request.body.contains("Heartbeat") && request.json()["seq"] == 1 {
                    *down = true;
                    (200, reply.clone())
                } else {
                    (200, "{}".to_string())
                }
            });
            let (runtime, platform) = runtime(&server, &dir);

            runtime.tick();
            assert!(wait_until(|| platform.logged("Shell command results are queued, 1 waiting")));
            assert_eq!(shell_results(&server, status).len(), 1);

            for _ in 0..3 {
                assert_no_result_is_sent_after_another_heartbeat(&runtime, &server);
            }

            *down.lock().unwrap() = false;
            runtime.tick();
            assert!(wait_until(|| shell_results(&server, 200).len() == 1), "the result arrives with the first heartbeat the server takes");
            assert_eq!(shell_results(&server, 200)[0]["exit_code"], 6);
            assert_eq!(shell_results(&server, 200)[0]["command_id"], name.as_str());
            assert_eq!(shell_results(&server, status).len(), 1, "nothing was uploaded while the server was down");
            assert!(wait_until(|| recorded_as_answered(&dir, &name)));

            std::fs::remove_dir_all(&dir).unwrap();
        }
    }

    #[test]
    fn test_shell_result_waits_for_a_server_that_cannot_be_reached() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let unreachable = StubServer { url: format!("http://{}", listener.local_addr().unwrap()), received: Arc::new(Mutex::new(Vec::new())) };
        drop(listener);
        let dir = state_dir("shell-unreachable");
        let (runtime, platform) = runtime(&unreachable, &dir);
        runtime.queue_shell_result(not_started(0));

        runtime.deliver_shell_results();
        runtime.deliver_shell_results();

        let waits: Vec<String> = platform.logs.lock().unwrap().iter().filter(|line| line.contains("are queued")).cloned().collect();
        assert_eq!(waits.len(), 1, "a wait is logged once: {:?}", waits);
        assert!(waits[0].starts_with("Shell command results are queued, 1 waiting: Request to /api/events failed"), "{}", waits[0]);
        assert!(!platform.logged("discarded"));

        std::fs::remove_dir_all(&dir).unwrap();
    }

    fn not_started(number: usize) -> CommandResult {
        let command = ShellCommand {
            session_id: "session-1".to_string(),
            agent_id: String::new(),
            command_text: String::new(),
            signature: Vec::new(),
            issued_at: 0,
            nonce: format!("command-{}", number),
        };
        CommandResult::failed(&command, "not started")
    }

    fn delivered_commands(server: &StubServer) -> Vec<String> {
        shell_results(server, 200).iter().map(|result| result["command_id"].as_str().unwrap().to_string()).collect()
    }

    #[test]
    fn test_shell_results_are_delivered_oldest_first_and_stop_at_the_one_the_server_does_not_take() {
        let server = StubServer::start(|request| {
            if request.body.contains("command-2") && !request.body.contains("command-2-retried") {
                (503, "{}".to_string())
            } else {
                (200, "{}".to_string())
            }
        });
        let dir = state_dir("shell-queue-order");
        let (runtime, platform) = runtime(&server, &dir);
        for number in 0..5 {
            runtime.queue_shell_result(not_started(number));
        }

        runtime.deliver_shell_results();

        assert_eq!(delivered_commands(&server), vec!["command-0", "command-1"]);
        assert!(platform.logged("Shell command results are queued, 3 waiting: HTTP 503"));

        runtime.deliver_shell_results();
        assert_eq!(delivered_commands(&server), vec!["command-0", "command-1"], "the results behind it wait as well");
        assert_eq!(shell_results(&server, 503).len(), 2);
        assert_eq!(platform.logs.lock().unwrap().iter().filter(|line| line.contains("are queued")).count(), 1, "a wait is logged once");

        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn test_more_shell_results_than_the_queue_holds_cost_the_oldest() {
        let server = StubServer::start(accept_everything);
        let dir = state_dir("shell-queue-full");
        let (runtime, platform) = runtime(&server, &dir);
        for number in 0..SHELL_RESULT_QUEUE_LIMIT + 2 {
            runtime.queue_shell_result(not_started(number));
        }

        runtime.deliver_shell_results();

        let dropped = platform.logs.lock().unwrap().iter().filter(|line| line.contains("Shell command result queue is full, dropped the oldest result")).count();
        assert_eq!(dropped, 2);
        let kept: Vec<String> = (2..SHELL_RESULT_QUEUE_LIMIT + 2).map(|number| format!("command-{}", number)).collect();
        assert_eq!(delivered_commands(&server), kept);

        std::fs::remove_dir_all(&dir).unwrap();
    }

    fn recorded_as_answered(dir: &std::path::Path, nonce: &str) -> bool {
        let Ok(raw) = std::fs::read_to_string(dir.join("accepted-commands.json")) else { return false };
        let Ok(record) = serde_json::from_str::<serde_json::Value>(&raw) else { return false };
        record.as_array().is_some_and(|commands| commands.iter().any(|command| command["nonce"] == nonce && command["answered"] == true))
    }

    fn restart(server: &StubServer, dir: &std::path::Path, nonce: &str) -> (Arc<Runtime<Arc<TestPlatform>>>, Arc<TestPlatform>) {
        crate::forget_nonce_as_a_new_process_would(nonce);
        runtime(server, dir)
    }

    #[test]
    fn test_shell_command_without_an_answer_is_answered_after_a_restart_and_never_run_again() {
        let name = "shell-restart-unanswered";
        let runs = std::env::temp_dir().join(format!("zedr-runtime-{}-{}-runs", std::process::id(), name));
        let _ = std::fs::remove_file(&runs);
        let taking_results = Arc::new(Mutex::new(false));
        let gate = Arc::clone(&taking_results);
        let (stopped, server, platform, dir) = issue_shell_command(
            name,
            &format!("echo ran >> {}; echo out; exit 0", runs.display()),
            move |_| if *gate.lock().unwrap() { (200, "{}".to_string()) } else { (503, "{}".to_string()) },
        );
        assert!(wait_until(|| platform.logged("Shell command results are queued, 1 waiting")));
        drop(stopped);
        *taking_results.lock().unwrap() = true;

        let (restarted, platform) = restart(&server, &dir, name);
        assert!(platform.logged(&format!("Shell command {} of session session-1 had no answer when this agent stopped", name)));

        restarted.tick();

        assert!(wait_until(|| recorded_as_answered(&dir, name)), "the command is answered");
        let answers = shell_results(&server, 200);
        assert_eq!(answers.len(), 1);
        assert_eq!(answers[0]["command_id"], name);
        assert_eq!(answers[0]["session_id"], "session-1");
        assert_eq!(answers[0]["exit_code"], -1);
        assert_eq!(answers[0]["stdout"], "");
        assert_eq!(answers[0]["stderr"], "[AGENT RESTARTED BEFORE THE RESULT WAS SENT, THE COMMAND MAY NOT HAVE FINISHED]");
        assert!(wait_until(|| platform.logged("Shell command is not run: Command was already accepted by this agent")));

        let (restarted_again, platform) = restart(&server, &dir, name);
        assert!(!platform.logged("had no answer"));
        assert_no_result_is_sent_after_another_heartbeat(&restarted_again, &server);
        assert!(wait_until(|| platform.logged("Shell command is not run: Command was already accepted by this agent")));
        assert_eq!(std::fs::read_to_string(&runs).unwrap(), "ran\n", "the command ran once, however often it was handed out");

        std::fs::remove_file(&runs).unwrap();
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn test_shell_command_with_an_answer_is_left_alone_after_a_restart() {
        let name = "shell-restart-answered";
        let runs = std::env::temp_dir().join(format!("zedr-runtime-{}-{}-runs", std::process::id(), name));
        let _ = std::fs::remove_file(&runs);
        let (stopped, server, _, dir) =
            issue_shell_command(name, &format!("echo ran >> {}; exit 3", runs.display()), accept_everything);
        assert!(wait_until(|| recorded_as_answered(&dir, name)));
        drop(stopped);

        let (restarted, platform) = restart(&server, &dir, name);
        assert!(!platform.logged("had no answer"));
        assert_no_result_is_sent_after_another_heartbeat(&restarted, &server);

        assert!(wait_until(|| platform.logged("Shell command is not run: Command was already accepted by this agent")));
        let answers = shell_results(&server, 200);
        assert_eq!(answers.len(), 1);
        assert_eq!(answers[0]["exit_code"], 3);
        assert_eq!(std::fs::read_to_string(&runs).unwrap(), "ran\n");

        std::fs::remove_file(&runs).unwrap();
        std::fs::remove_dir_all(&dir).unwrap();
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

        let (restarted, platform) = restart(&server, &dir, name);
        let refused = restarted.link.verify_upgrade_command_with_key(&trusted, &command).unwrap_err();
        assert!(refused.contains("already accepted by this agent"), "{}", refused);
        assert!(!platform.logged("had no answer"), "an upgrade command is not answered like a shell command");
        assert!(restarted.shell_results.lock().unwrap().queued.is_empty());

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
        let key = deployment_key();
        let link = ControlLink::open_with_key_id("http://unused".to_string(), &dir).unwrap();
        let command = signed_upgrade(&key, link.agent_id(), name);

        let refused = link.verify_upgrade_command_with_key(&key.verifying_key(), &command).unwrap_err();
        assert!(refused.contains("Record of accepted commands is corrupt"), "{}", refused);
        assert_eq!(std::fs::read_to_string(dir.join("accepted-commands.json")).unwrap(), "not a record", "the record is left as it was");

        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn test_shell_commands_are_refused_while_the_record_of_accepted_commands_cannot_be_read() {
        let name = "shell-record-corrupt";
        let dir = state_dir(name);
        std::fs::write(dir.join("accepted-commands.json"), "not a record").unwrap();
        let marker = dir.join("command-ran");
        let agent_id = ControlLink::open_with_key_id("http://unused".to_string(), &dir).unwrap().agent_id().to_string();
        let reply = signed_shell_reply(&deployment_key(), &agent_id, &format!("touch {}", marker.display()), name);
        let server = StubServer::start(move |request| {
            if request.body.contains("Heartbeat") {
                (200, reply.clone())
            } else {
                (200, "{}".to_string())
            }
        });
        let (runtime, platform) = runtime(&server, &dir);
        assert!(platform.logged("Shell and upgrade commands are refused: Record of accepted commands is corrupt"));

        runtime.tick();

        assert!(wait_until(|| platform.logged("Shell command is not run: Record of accepted commands is corrupt")));
        thread::sleep(Duration::from_millis(200));
        assert!(!marker.exists(), "the command must not have run");
        assert!(shell_results(&server, 200).is_empty());

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
