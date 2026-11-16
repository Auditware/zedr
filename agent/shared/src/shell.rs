use std::collections::HashMap;
use std::io::Read;
use std::process::{Command, Stdio};
use std::sync::{mpsc, Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use zedr_protocol::{ShellCommand, ShellCommandExecutedEvent, ShellSessionTerminatedEvent, SystemEvent};

use crate::link::unix_now;

const MAX_OUTPUT_SIZE: usize = 1024 * 1024;
const CAPTURE_LIMIT_MARKER: &str = "\n[OUTPUT TRUNCATED AT 1MB]";
const INTERRUPTED_NOTE: &str = "[AGENT RESTARTED BEFORE THE RESULT WAS SENT, THE COMMAND MAY NOT HAVE FINISHED]";
const OUTPUT_DRAIN_GRACE: Duration = Duration::from_secs(2);
const EXIT_POLL_INTERVAL: Duration = Duration::from_millis(50);

fn seconds_from_env(name: &str, default: u64) -> u64 {
    match std::env::var(name).ok().and_then(|value| value.parse::<u64>().ok()) {
        Some(seconds) => seconds,
        None => default,
    }
}

pub fn command_timeout() -> Duration {
    Duration::from_secs(seconds_from_env("ZEDR_SHELL_COMMAND_TIMEOUT_SECS", 60))
}

fn session_absolute_timeout_secs() -> u64 {
    seconds_from_env("ZEDR_SHELL_SESSION_ABSOLUTE_TIMEOUT_SECS", 1800)
}

fn session_idle_timeout_secs() -> u64 {
    seconds_from_env("ZEDR_SHELL_SESSION_IDLE_TIMEOUT_SECS", 300)
}

struct SessionClock {
    last_activity_at: u64,
    expires_at: u64,
}

#[derive(Default)]
pub struct ShellSessions {
    sessions: Mutex<HashMap<String, SessionClock>>,
}

impl ShellSessions {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn touch(&self, session_id: &str) -> Result<(), String> {
        self.touch_at(session_id, unix_now())
    }

    fn touch_at(&self, session_id: &str, now: u64) -> Result<(), String> {
        let mut sessions = self.sessions.lock()
            .map_err(|e| format!("Failed to lock sessions: {}", e))?;

        match sessions.get_mut(session_id) {
            Some(session) => session.last_activity_at = now,
            None => {
                sessions.insert(session_id.to_string(), SessionClock {
                    last_activity_at: now,
                    expires_at: now + session_absolute_timeout_secs(),
                });
            }
        }

        Ok(())
    }

    pub fn expire(&self) -> Vec<ShellSessionTerminatedEvent> {
        self.expire_at(unix_now())
    }

    fn expire_at(&self, now: u64) -> Vec<ShellSessionTerminatedEvent> {
        let mut sessions = match self.sessions.lock() {
            Ok(sessions) => sessions,
            Err(_) => return Vec::new(),
        };

        let idle_timeout = session_idle_timeout_secs();
        let mut terminated = Vec::new();

        sessions.retain(|session_id, session| {
            let reason = if now >= session.expires_at {
                "timeout_absolute"
            } else if now.saturating_sub(session.last_activity_at) >= idle_timeout {
                "timeout_idle"
            } else {
                return true;
            };

            terminated.push(ShellSessionTerminatedEvent {
                timestamp: now,
                session_id: session_id.clone(),
                reason: reason.to_string(),
                executed_commands: Vec::new(),
            });
            false
        });

        terminated
    }
}

struct Capture {
    buffer: Arc<Mutex<Vec<u8>>>,
    finished: mpsc::Receiver<()>,
}

impl Capture {
    fn start<R: Read + Send + 'static>(stream: Option<R>) -> Self {
        let buffer = Arc::new(Mutex::new(Vec::new()));
        let (finished_tx, finished) = mpsc::channel();

        match stream {
            Some(mut stream) => {
                let sink = Arc::clone(&buffer);
                thread::spawn(move || {
                    let mut chunk = [0u8; 8192];
                    loop {
                        let read = match stream.read(&mut chunk) {
                            Ok(0) | Err(_) => break,
                            Ok(read) => read,
                        };
                        if let Ok(mut sink) = sink.lock() {
                            let room = (MAX_OUTPUT_SIZE + 1).saturating_sub(sink.len());
                            sink.extend_from_slice(&chunk[..read.min(room)]);
                        }
                    }
                    let _ = finished_tx.send(());
                });
            }
            None => {
                let _ = finished_tx.send(());
            }
        }

        Self { buffer, finished }
    }

    fn collect(self) -> Output {
        let _ = self.finished.recv_timeout(OUTPUT_DRAIN_GRACE);

        let captured = match self.buffer.lock() {
            Ok(buffer) => buffer.clone(),
            Err(_) => Vec::new(),
        };

        let kept = &captured[..captured.len().min(MAX_OUTPUT_SIZE)];
        Output::new(String::from_utf8_lossy(kept).to_string(), captured.len() > MAX_OUTPUT_SIZE)
    }
}

fn fit_marker(shown_bytes: usize) -> String {
    format!("\n[OUTPUT TRUNCATED AT {} BYTES TO FIT THE RESULT IN ONE REQUEST]", shown_bytes)
}

fn encoded_char_len(character: char) -> usize {
    match character {
        '"' | '\\' | '\u{8}' | '\t' | '\n' | '\u{c}' | '\r' => 2,
        '\0'..='\u{1f}' => 6,
        _ => character.len_utf8(),
    }
}

fn encoded_len(text: &str) -> usize {
    text.chars().map(encoded_char_len).sum()
}

fn head_within(text: &str, room: usize) -> &str {
    let mut used = 0;
    for (index, character) in text.char_indices() {
        used += encoded_char_len(character);
        if used > room {
            return &text[..index];
        }
    }
    text
}

#[derive(Default)]
struct Output {
    captured: String,
    captured_encoded_bytes: usize,
    overflowed: bool,
    note: Option<String>,
}

impl Output {
    fn new(captured: String, overflowed: bool) -> Self {
        let captured_encoded_bytes = encoded_len(&captured);
        Self { captured, captured_encoded_bytes, overflowed, note: None }
    }

    fn ending(&self, head: &str, marker: &str) -> String {
        let mut ending = marker.to_string();
        if let Some(note) = &self.note {
            if !head.is_empty() || !ending.is_empty() {
                ending.push('\n');
            }
            ending.push_str(note);
        }
        ending
    }

    fn whole_ending(&self) -> String {
        self.ending(&self.captured, if self.overflowed { CAPTURE_LIMIT_MARKER } else { "" })
    }

    fn whole_bytes(&self) -> usize {
        self.captured_encoded_bytes + encoded_len(&self.whole_ending())
    }

    fn within(&self, room: usize) -> String {
        let whole_bytes = self.whole_bytes();

        if whole_bytes > room {
            let reserved = encoded_len(&self.ending("", &fit_marker(self.captured.len())));
            let head = head_within(&self.captured, room.saturating_sub(reserved));
            let ending = self.ending(head, &fit_marker(head.len()));
            if encoded_len(head) + encoded_len(&ending) < whole_bytes {
                return format!("{}{}", head, ending);
            }
        }

        format!("{}{}", self.captured, self.whole_ending())
    }
}

pub struct FittedResult {
    pub event: ShellCommandExecutedEvent,
    pub encoded_bytes: usize,
}

pub struct CommandResult {
    timestamp: u64,
    session_id: String,
    command_id: String,
    exit_code: i32,
    stdout: Output,
    stderr: Output,
    execution_time_ms: u64,
}

impl CommandResult {
    fn without_output(session_id: &str, command_id: &str, note: String) -> Self {
        Self {
            timestamp: unix_now(),
            session_id: session_id.to_string(),
            command_id: command_id.to_string(),
            exit_code: -1,
            stdout: Output::default(),
            stderr: Output { note: Some(note), ..Output::default() },
            execution_time_ms: 0,
        }
    }

    pub fn failed(cmd: &ShellCommand, error: &str) -> Self {
        Self::without_output(&cmd.session_id, &cmd.nonce, format!("[EXECUTION ERROR] {}", error))
    }

    pub fn not_run(cmd: &ShellCommand, reason: &str) -> Self {
        Self::without_output(&cmd.session_id, &cmd.nonce, format!("[NOT RUN] {}", reason))
    }

    pub fn interrupted(session_id: &str, command_id: &str) -> Self {
        Self::without_output(session_id, command_id, INTERRUPTED_NOTE.to_string())
    }

    pub fn exit_code(&self) -> i32 {
        self.exit_code
    }

    pub fn command_id(&self) -> &str {
        &self.command_id
    }

    pub fn event(&self, room: usize) -> Result<FittedResult, String> {
        let mut event = ShellCommandExecutedEvent {
            timestamp: self.timestamp,
            session_id: self.session_id.clone(),
            command_id: self.command_id.clone(),
            exit_code: self.exit_code,
            stdout: String::new(),
            stderr: String::new(),
            execution_time_ms: self.execution_time_ms,
        };

        let without_output = serde_json::to_vec(&SystemEvent::ShellCommandExecuted(event.clone()))
            .map_err(|e| format!("Failed to encode shell command result: {}", e))?
            .len();
        let room = room.saturating_sub(without_output);
        let half = room / 2;

        event.stdout = self.stdout.within(half.max(room.saturating_sub(self.stderr.whole_bytes())));
        event.stderr = self.stderr.within((room - half).max(room.saturating_sub(self.stdout.whole_bytes())));

        let encoded_bytes = without_output + encoded_len(&event.stdout) + encoded_len(&event.stderr);
        Ok(FittedResult { event, encoded_bytes })
    }
}

pub fn execute(
    mut invocation: Command,
    cmd: &ShellCommand,
    timeout: Duration,
) -> Result<CommandResult, String> {
    let timestamp = unix_now();
    let started = Instant::now();

    let mut child = invocation
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| format!("Failed to spawn shell: {}", e))?;

    let pid = child.id();
    let stdout = Capture::start(child.stdout.take());
    let stderr = Capture::start(child.stderr.take());

    let exit_status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break Some(status),
            Ok(None) if started.elapsed() >= timeout => {
                let _ = child.kill();
                let _ = child.wait();
                break None;
            }
            Ok(None) => thread::sleep(EXIT_POLL_INTERVAL),
            Err(e) => return Err(format!("Failed to check process status: {}", e)),
        }
    };

    let stdout = stdout.collect();
    let mut stderr = stderr.collect();

    let exit_code = exit_status.and_then(|status| status.code()).unwrap_or(-1);

    if exit_status.is_none() {
        stderr.note = Some(format!("[COMMAND TIMEOUT AFTER {}s - PID {}]", timeout.as_secs(), pid));
    }

    Ok(CommandResult {
        timestamp,
        session_id: cmd.session_id.clone(),
        command_id: cmd.nonce.clone(),
        exit_code,
        stdout,
        stderr,
        execution_time_ms: started.elapsed().as_millis() as u64,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use zedr_protocol::MAX_EVENT_BATCH_BYTES;

    const ROOM: usize = MAX_EVENT_BATCH_BYTES;

    fn shell_command(nonce: &str) -> ShellCommand {
        ShellCommand {
            session_id: "session-1".to_string(),
            agent_id: "agent-a".to_string(),
            command_text: String::new(),
            signature: Vec::new(),
            issued_at: 0,
            nonce: nonce.to_string(),
        }
    }

    fn result(stdout: &str, stderr: &str) -> CommandResult {
        CommandResult {
            timestamp: 1_794_780_000,
            session_id: "session-1".to_string(),
            command_id: "command-1".to_string(),
            exit_code: 7,
            stdout: Output::new(stdout.to_string(), false),
            stderr: Output::new(stderr.to_string(), false),
            execution_time_ms: 1_200,
        }
    }

    fn encoded(event: &ShellCommandExecutedEvent) -> usize {
        serde_json::to_vec(&SystemEvent::ShellCommandExecuted(event.clone())).unwrap().len()
    }

    fn shown_before_the_cut(stream: &str) -> &str {
        let (shown, marker) = stream.split_once("\n[OUTPUT TRUNCATED AT ").expect("the stream says that it was cut");
        assert_eq!(marker, format!("{} BYTES TO FIT THE RESULT IN ONE REQUEST]", shown.len()));
        shown
    }

    #[test]
    fn test_encoded_length_of_every_character_is_what_the_encoder_writes() {
        for character in '\0'..=char::MAX {
            let text = character.to_string();
            assert_eq!(encoded_len(&text) + 2, serde_json::to_vec(&text).unwrap().len(), "U+{:04X}", character as u32);
        }
    }

    #[test]
    fn test_result_that_fits_is_reported_as_it_was_captured() {
        let fitted = result("a \"quoted\" \\ path\n", "\u{e9}\u{1f600}\u{fffd}\r\n").event(ROOM).unwrap();

        assert_eq!(fitted.event.exit_code, 7);
        assert_eq!(fitted.event.stdout, "a \"quoted\" \\ path\n");
        assert_eq!(fitted.event.stderr, "\u{e9}\u{1f600}\u{fffd}\r\n");
        assert_eq!(fitted.event.session_id, "session-1");
        assert_eq!(fitted.event.command_id, "command-1");
        assert_eq!(fitted.event.execution_time_ms, 1_200);
        assert_eq!(fitted.encoded_bytes, encoded(&fitted.event));
    }

    #[test]
    fn test_small_stream_stays_whole_and_the_other_gets_the_room_it_leaves() {
        let control_characters = "\u{1}".repeat(MAX_OUTPUT_SIZE);

        let fitted = result(&control_characters, "warning: disk is full\n").event(ROOM).unwrap();
        assert_eq!(fitted.event.stderr, "warning: disk is full\n");
        assert!(shown_before_the_cut(&fitted.event.stdout).len() > 349_000);
        assert_eq!(fitted.encoded_bytes, encoded(&fitted.event));
        assert!(fitted.encoded_bytes <= ROOM);
        assert!(fitted.encoded_bytes > ROOM - 8, "the room is used up: {}", fitted.encoded_bytes);

        let fitted = result("done\n", &control_characters).event(ROOM).unwrap();
        assert_eq!(fitted.event.stdout, "done\n");
        assert!(shown_before_the_cut(&fitted.event.stderr).len() > 349_000);
        assert!(fitted.encoded_bytes <= ROOM);
        assert!(fitted.encoded_bytes > ROOM - 8, "the room is used up: {}", fitted.encoded_bytes);
    }

    #[test]
    fn test_cut_falls_between_characters_and_fills_whatever_room_there_is() {
        let mixed = "\u{e9}\"\\\n\u{1f600}\u{1}a\u{fffd}\t".repeat(40);
        let result = result(&mixed, &mixed);
        let whole = result.event(ROOM).unwrap().encoded_bytes;
        let smallest = result.event(0).unwrap().encoded_bytes;
        assert!(smallest < whole / 4);

        for room in 0..whole + 8 {
            let fitted = result.event(room).unwrap();
            assert_eq!(fitted.encoded_bytes, encoded(&fitted.event), "room {}", room);
            assert!(fitted.encoded_bytes <= room.max(smallest), "room {}", room);

            let cut: Vec<&String> = [&fitted.event.stdout, &fitted.event.stderr].into_iter().filter(|stream| **stream != mixed).collect();
            for stream in &cut {
                assert!(mixed.starts_with(shown_before_the_cut(stream)), "room {}", room);
            }
            assert_eq!(cut.is_empty(), room >= whole, "room {}", room);
            assert!(cut.is_empty() || fitted.encoded_bytes + 16 > room, "room {} holds more than {}", room, fitted.encoded_bytes);
        }
    }

    #[test]
    fn test_notes_on_a_stream_survive_the_cut() {
        let mut result = result(&"x".repeat(5_000), &"y".repeat(5_000));
        result.stdout.overflowed = true;
        result.stderr.note = Some("[COMMAND TIMEOUT AFTER 60s - PID 4242]".to_string());

        let whole = result.event(ROOM).unwrap().event;
        assert_eq!(whole.stdout, format!("{}\n[OUTPUT TRUNCATED AT 1MB]", "x".repeat(5_000)));
        assert_eq!(whole.stderr, format!("{}\n[COMMAND TIMEOUT AFTER 60s - PID 4242]", "y".repeat(5_000)));

        let fitted = result.event(2_000).unwrap();
        assert_eq!(fitted.encoded_bytes, encoded(&fitted.event));
        assert!(fitted.encoded_bytes <= 2_000);
        assert!(fitted.encoded_bytes > 2_000 - 16);
        assert!(shown_before_the_cut(&fitted.event.stdout).len() > 700);
        let (stderr, note) = fitted.event.stderr.rsplit_once('\n').unwrap();
        assert_eq!(note, "[COMMAND TIMEOUT AFTER 60s - PID 4242]");
        assert!(shown_before_the_cut(stderr).len() > 700);
    }

    #[test]
    fn test_result_keeps_its_exit_code_and_notes_when_there_is_no_room_for_output() {
        let failed = CommandResult::failed(&shell_command("n-8"), "Failed to spawn shell: not found").event(0).unwrap();
        assert_eq!(failed.event.exit_code, -1);
        assert_eq!(failed.event.command_id, "n-8");
        assert_eq!(failed.event.stdout, "");
        assert_eq!(failed.event.stderr, "[EXECUTION ERROR] Failed to spawn shell: not found");

        let mut timed_out = result(&"x".repeat(5_000), &"y".repeat(5_000));
        timed_out.stderr.note = Some("[COMMAND TIMEOUT AFTER 60s - PID 4242]".to_string());
        let fitted = timed_out.event(0).unwrap();
        assert_eq!(fitted.event.exit_code, 7);
        assert_eq!(fitted.event.stdout, fit_marker(0));
        assert_eq!(fitted.event.stderr, format!("{}\n[COMMAND TIMEOUT AFTER 60s - PID 4242]", fit_marker(0)));

        let short = result("out\n", "err\n").event(0).unwrap();
        assert_eq!(short.event.stdout, "out\n", "a marker would take more room than what it replaces");
        assert_eq!(short.event.stderr, "err\n");
    }

    #[test]
    fn test_session_expires_when_idle_and_at_its_absolute_limit() {
        let sessions = ShellSessions::new();
        sessions.touch_at("idle", 1_000).unwrap();
        sessions.touch_at("busy", 1_000).unwrap();

        assert!(sessions.expire_at(1_000 + 299).is_empty());

        sessions.touch_at("busy", 1_000 + 299).unwrap();
        let expired = sessions.expire_at(1_000 + 300);
        assert_eq!(expired.len(), 1);
        assert_eq!(expired[0].session_id, "idle");
        assert_eq!(expired[0].reason, "timeout_idle");

        for second in (1_000 + 300..1_000 + 1_800).step_by(200) {
            sessions.touch_at("busy", second).unwrap();
            assert!(sessions.expire_at(second).is_empty());
        }

        let expired = sessions.expire_at(1_000 + 1_800);
        assert_eq!(expired.len(), 1);
        assert_eq!(expired[0].session_id, "busy");
        assert_eq!(expired[0].reason, "timeout_absolute");
        assert!(sessions.expire_at(1_000 + 5_000).is_empty());
    }

    #[cfg(unix)]
    mod unix {
        use super::*;

        fn sh(script: &str) -> Command {
            let mut command = Command::new("/bin/sh");
            command.arg("-c").arg(script);
            command
        }

        fn run(script: &str, nonce: &str, timeout: Duration) -> ShellCommandExecutedEvent {
            execute(sh(script), &shell_command(nonce), timeout).unwrap().event(ROOM).unwrap().event
        }

        #[test]
        fn test_command_output_and_exit_code_are_captured() {
            let event = run("echo out; echo err >&2; exit 3", "n-1", Duration::from_secs(10));

            assert_eq!(event.exit_code, 3);
            assert_eq!(event.stdout, "out\n");
            assert_eq!(event.stderr, "err\n");
            assert_eq!(event.session_id, "session-1");
            assert_eq!(event.command_id, "n-1");
        }

        #[test]
        fn test_command_gets_no_stdin() {
            let event = run("cat; echo done", "n-2", Duration::from_secs(10));
            assert_eq!(event.exit_code, 0);
            assert_eq!(event.stdout, "done\n");
        }

        #[test]
        fn test_output_larger_than_a_pipe_does_not_stall_the_command() {
            let event = run("head -c 300000 /dev/zero | tr '\\0' 'a'; echo; echo end", "n-3", Duration::from_secs(20));

            assert_eq!(event.exit_code, 0);
            assert_eq!(event.stdout.len(), 300_000 + 1 + 4);
            assert!(event.stdout.ends_with("\nend\n"));
        }

        #[test]
        fn test_output_is_cut_at_the_limit() {
            let event = run("head -c 1200000 /dev/zero | tr '\\0' 'b'", "n-4", Duration::from_secs(20));

            assert_eq!(event.exit_code, 0);
            assert!(event.stdout.ends_with("\n[OUTPUT TRUNCATED AT 1MB]"));
            assert_eq!(event.stdout.len(), MAX_OUTPUT_SIZE + "\n[OUTPUT TRUNCATED AT 1MB]".len());
        }

        #[test]
        fn test_command_that_fills_both_streams_with_control_characters_reports_its_exit_code_and_what_fits() {
            let result = execute(
                sh("head -c 1200000 /dev/zero; head -c 1200000 /dev/zero >&2; exit 7"),
                &shell_command("n-9"),
                Duration::from_secs(20),
            )
            .unwrap();
            assert_eq!(result.stdout.captured_encoded_bytes, 6 * MAX_OUTPUT_SIZE);
            assert_eq!(result.stderr.captured_encoded_bytes, 6 * MAX_OUTPUT_SIZE);

            let fitted = result.event(ROOM).unwrap();

            assert_eq!(fitted.event.exit_code, 7);
            assert_eq!(fitted.event.command_id, "n-9");
            assert_eq!(fitted.encoded_bytes, encoded(&fitted.event));
            assert!(fitted.encoded_bytes <= ROOM);
            assert!(fitted.encoded_bytes > ROOM - 16, "the room is used up: {}", fitted.encoded_bytes);
            for stream in [&fitted.event.stdout, &fitted.event.stderr] {
                let shown = shown_before_the_cut(stream);
                assert!(shown.len() > 174_000, "each stream gets half of the room: {}", shown.len());
                assert!(shown.chars().all(|character| character == '\0'));
            }
        }

        #[test]
        fn test_command_past_its_timeout_is_killed_and_reported() {
            let started = Instant::now();
            let event = run("echo before; exec sleep 30", "n-5", Duration::from_millis(300));

            assert!(started.elapsed() < Duration::from_secs(10));
            assert_eq!(event.exit_code, -1);
            assert_eq!(event.stdout, "before\n");
            assert!(event.stderr.contains("[COMMAND TIMEOUT AFTER 0s"));
        }

        #[test]
        fn test_background_process_holding_the_pipe_does_not_hang_the_result() {
            let started = Instant::now();
            let event = run("sleep 6 & echo started", "n-6", Duration::from_secs(10));

            assert!(started.elapsed() < Duration::from_secs(8));
            assert_eq!(event.exit_code, 0);
            assert_eq!(event.stdout, "started\n");
        }

        #[test]
        fn test_missing_shell_is_an_error() {
            let result = execute(Command::new("/nonexistent/zedr-shell"), &shell_command("n-7"), Duration::from_secs(1));
            assert!(result.is_err());
        }
    }
}
