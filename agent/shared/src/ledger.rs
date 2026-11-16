/// The agent's ledger: every sensor event is committed, sealed and run through the rules here before anything leaves the endpoint.
/// Windows are kept on disk until the control server has them and a proof covers them.
use std::collections::BTreeMap;
use std::fs;
use std::ops::Range;
use std::path::{Path, PathBuf};

use borsh::{BorshDeserialize, BorshSerialize};
use zedr_ledger::{leaf, seal, Hash, WindowHeader, GENESIS};
use zedr_protocol::SensorEvent;
use zedr_rules::proof::{Committed, Input, Journal, WindowInput};
use zedr_rules::{Match, State};

use crate::identity::replace_private_file;

/// A window is sealed at least this often, even when empty, so a silent sensor shows on the control server
pub const WINDOW_SECONDS: u64 = 60;
pub const WINDOW_EVENTS: usize = 1000;
pub const WINDOW_SEALED_BYTES: usize = 1024 * 1024;
/// Delivered windows whose plaintext may wait for a proof, two days of one-minute windows. Past it the oldest is dropped
pub const UNPROVEN_WINDOWS_LIMIT: u64 = 2880;
/// Sealed windows that may wait for the control server to acknowledge them. Past it they are all given up
pub const UNDELIVERED_WINDOWS_LIMIT: u64 = 2880;

const CHAIN_FILE: &str = "chain.bin";
const PROVING_FILE: &str = "proving.bin";
const WINDOWS_DIR: &str = "windows";

/// The secret that opens one committed event
#[derive(Debug, Clone, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct Opening {
    pub index: u64,
    pub seed: Hash,
}

/// A rule that fired, with the secrets of the events it opens
#[derive(Debug, Clone, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct Release {
    pub found: Match,
    pub openings: Vec<Opening>,
}

/// A sealed window as it rests on disk, the plaintext never leaves the endpoint
#[derive(Debug, Clone, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct StoredWindow {
    pub header: WindowHeader,
    pub events: Vec<Vec<u8>>,
    pub releases: Vec<Release>,
}

/// What the control server receives of a window
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SealedWindow {
    pub header: WindowHeader,
    pub leaves: Vec<Hash>,
    pub sealed: Vec<Vec<u8>>,
    pub releases: Vec<Release>,
}

#[derive(Debug, Clone, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
struct Chain {
    epoch: u64,
    next_window: u64,
    next_index: u64,
    head: Hash,
    /// First window the control server has not acknowledged, and the index and head its copy of the chain stands at before it
    deliver_from: u64,
    delivered_index: u64,
    delivered_head: Hash,
}

/// Where proving stands: the next window to prove and the rule state it starts from
#[derive(Debug, Clone, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
struct Proving {
    next_window: u64,
    state: State,
    /// Plaintext before `next_window` was dropped without a proof, so nothing is proven until a window that opens an epoch
    needs_fresh: bool,
}

struct OpenWindow {
    opened_at: u64,
    events: Vec<Vec<u8>>,
    leaves: Vec<Hash>,
    releases: Vec<Release>,
    sealed_bytes: usize,
    gap: bool,
}

impl OpenWindow {
    fn new(opened_at: u64, gap: bool) -> Self {
        OpenWindow { opened_at, events: Vec::new(), leaves: Vec::new(), releases: Vec::new(), sealed_bytes: 0, gap }
    }
}

pub struct Ledger {
    dir: PathBuf,
    agent: Hash,
    master: Hash,
    chain: Chain,
    proving: Proving,
    unproven_limit: u64,
    undelivered_limit: u64,
    /// What the ledger gave up or started over on its own, for whoever runs it to say so
    notices: Vec<String>,
    open: OpenWindow,
    fresh: bool,
    state: State,
    /// Seeds of the events a later match may still open, by index
    seeds: BTreeMap<u64, Hash>,
}

fn window_file(window: u64) -> String {
    format!("{:020}.bin", window)
}

fn window_path(dir: &Path, window: u64) -> PathBuf {
    dir.join(WINDOWS_DIR).join(window_file(window))
}

fn write<T: BorshSerialize>(dir: &Path, name: &str, what: &str, value: &T) -> Result<(), String> {
    let bytes = borsh::to_vec(value).map_err(|e| format!("Failed to encode {}: {}", what, e))?;
    replace_private_file(dir, name, what, &bytes)
}

/// What a ledger file holds, nothing when it is not there, and why not when it is there and cannot be used
fn read_optional<T: BorshDeserialize>(path: &Path) -> Result<Option<T>, String> {
    match fs::read(path) {
        Ok(bytes) => borsh::from_slice(&bytes).map(Some).map_err(|e| format!("{} is damaged: {}", path.display(), e)),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(format!("Failed to read {}: {}", path.display(), e)),
    }
}

/// Removes every file of the windows directory that is not a window of this range, what a crash or a lost chain left behind
fn sweep(dir: &Path, kept: Range<u64>) -> Result<(), String> {
    let windows = dir.join(WINDOWS_DIR);
    for entry in fs::read_dir(&windows).map_err(|e| format!("Failed to list {}: {}", windows.display(), e))? {
        let path = entry.map_err(|e| format!("Failed to list {}: {}", windows.display(), e))?.path();
        let window = path.file_name().and_then(|name| name.to_str()).and_then(|name| name.strip_suffix(".bin")).and_then(|number| number.parse::<u64>().ok());
        if !window.is_some_and(|window| kept.contains(&window)) {
            fs::remove_file(&path).map_err(|e| format!("Failed to remove {}: {}", path.display(), e))?;
        }
    }
    Ok(())
}

impl Ledger {
    /// Opens the ledger of this agent and starts a new epoch, since the sensor reports everything again after a start.
    /// A chain file that cannot be used does not stop it: the chain starts over at the first window with a gap,
    /// and the control server answers that window with where its copy stands
    pub fn open(dir: &Path, agent: Hash, master: Hash, now: u64) -> Result<Self, String> {
        fs::create_dir_all(dir.join(WINDOWS_DIR)).map_err(|e| format!("Failed to create {}: {}", dir.display(), e))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            for private in [dir.to_path_buf(), dir.join(WINDOWS_DIR)] {
                fs::set_permissions(&private, fs::Permissions::from_mode(0o700)).map_err(|e| format!("Failed to protect {}: {}", private.display(), e))?;
            }
        }

        let mut notices = Vec::new();
        let known_chain = read_optional::<Chain>(&dir.join(CHAIN_FILE)).unwrap_or_else(|reason| {
            notices.push(format!("Ledger chain cannot be used, starting over at the first window with a gap: {}", reason));
            None
        });
        let lost = !notices.is_empty();
        let known_proving = match &known_chain {
            Some(_) => read_optional::<Proving>(&dir.join(PROVING_FILE)).unwrap_or_else(|reason| {
                notices.push(format!("Ledger proving state cannot be used, nothing is proven before the next epoch: {}", reason));
                None
            }),
            None => None,
        };

        let mut chain = known_chain.unwrap_or(Chain {
            epoch: 0,
            next_window: 0,
            next_index: 0,
            head: GENESIS,
            deliver_from: 0,
            delivered_index: 0,
            delivered_head: GENESIS,
        });
        chain.epoch += 1;
        let proving = known_proving.clone().unwrap_or(Proving { next_window: chain.deliver_from, state: State::default(), needs_fresh: true });
        sweep(dir, proving.next_window.min(chain.deliver_from)..chain.next_window)?;

        let ledger = Ledger {
            dir: dir.to_path_buf(),
            agent,
            master,
            chain,
            proving,
            unproven_limit: UNPROVEN_WINDOWS_LIMIT,
            undelivered_limit: UNDELIVERED_WINDOWS_LIMIT,
            notices,
            open: OpenWindow::new(now, lost),
            fresh: true,
            state: State::default(),
            seeds: BTreeMap::new(),
        };
        ledger.save_chain()?;
        if known_proving.is_none() {
            ledger.save_proving()?;
        }
        Ok(ledger)
    }

    #[cfg(test)]
    pub(crate) fn keeping_undelivered(mut self, limit: u64) -> Self {
        self.undelivered_limit = limit;
        self
    }

    /// What the ledger gave up or started over on its own since this was last asked
    pub fn take_notices(&mut self) -> Vec<String> {
        std::mem::take(&mut self.notices)
    }

    fn save_chain(&self) -> Result<(), String> {
        write(&self.dir, CHAIN_FILE, "ledger chain", &self.chain)
    }

    fn save_proving(&self) -> Result<(), String> {
        write(&self.dir, PROVING_FILE, "ledger proving state", &self.proving)
    }

    pub fn dir(&self) -> &Path {
        &self.dir
    }

    pub fn epoch(&self) -> u64 {
        self.chain.epoch
    }

    /// The rules start over with nothing remembered, in a window that says events before it are missing
    fn start_epoch(&mut self, epoch: u64, now: u64) {
        self.chain.epoch = epoch;
        self.open = OpenWindow::new(now, true);
        self.fresh = true;
        self.state = State::default();
        self.seeds.clear();
    }

    /// Commits and seals the events in order, runs the rules over them, and returns how many could not be committed
    pub fn admit(&mut self, events: &[SensorEvent]) -> u64 {
        let mut refused = 0;
        for event in events {
            let bytes = event.to_bytes();
            let index = self.chain.next_index + self.open.events.len() as u64;
            let seed = seal::seed(&self.master, &self.agent, self.chain.epoch, index, &bytes);
            let Some(sealed_len) = seal::sealed_len(bytes.len()) else {
                self.open.gap = true;
                refused += 1;
                continue;
            };

            self.open.leaves.push(leaf(&self.agent, self.chain.epoch, index, &seal::blind(&seed), &bytes));
            self.open.sealed_bytes += sealed_len;
            self.seeds.insert(index, seed);
            for found in self.state.observe(index, event) {
                let openings = found.opened().filter_map(|opened| self.seeds.get(&opened).map(|seed| Opening { index: opened, seed: *seed })).collect();
                self.open.releases.push(Release { found, openings });
            }
            self.open.events.push(bytes);
        }

        let first_open = self.chain.next_index;
        let referenced = self.state.referenced();
        self.seeds.retain(|index, _| *index >= first_open || referenced.contains(index));
        refused
    }

    /// Marks that events were lost before they reached the ledger, the next sealed window says so
    pub fn note_gap(&mut self) {
        self.open.gap = true;
    }

    fn due(&self, now: u64) -> bool {
        let timed_out = now < self.open.opened_at || now - self.open.opened_at >= WINDOW_SECONDS;
        timed_out || self.open.events.len() >= WINDOW_EVENTS || self.open.sealed_bytes >= WINDOW_SEALED_BYTES || !self.open.releases.is_empty()
    }

    /// Seals the open window when its time is up, it is full, or a rule fired in it
    pub fn seal_due(&mut self, now: u64) -> Result<Option<u64>, String> {
        if !self.due(now) {
            return Ok(None);
        }
        self.seal_now(now).map(Some)
    }

    /// Seals the open window whatever it holds, for a clean stop.
    /// A window that cannot be written is lost, and a new epoch starts so the rules never refer to events the chain does not hold.
    /// When more windows than the limit wait for the control server, this one is given up with them
    pub fn seal_now(&mut self, now: u64) -> Result<u64, String> {
        let open = std::mem::replace(&mut self.open, OpenWindow::new(now, false));
        let header = match self.store(open) {
            Ok(header) => header,
            Err(e) => {
                self.start_epoch(self.chain.epoch + 1, now);
                return Err(e);
            }
        };

        self.chain.next_window = header.window + 1;
        self.chain.next_index = header.next_index();
        self.chain.head = header.head;
        self.fresh = false;
        self.save_chain()?;
        if self.undelivered() > self.undelivered_limit {
            self.give_up_undelivered(&format!("more than {} waited for the control server", self.undelivered_limit))?;
        }
        Ok(header.window)
    }

    fn store(&self, open: OpenWindow) -> Result<WindowHeader, String> {
        let header = WindowHeader::seal(
            &self.agent,
            self.chain.epoch,
            self.chain.next_window,
            self.chain.next_index,
            self.fresh,
            open.gap,
            self.chain.head,
            &open.leaves,
        )?;
        let stored = StoredWindow { header, events: open.events, releases: open.releases };
        write(&self.dir.join(WINDOWS_DIR), &window_file(stored.header.window), "ledger window", &stored)?;
        Ok(stored.header)
    }

    /// Continues the chain at a position the control server holds, in a new epoch with a gap, for the sensor to report everything again.
    /// Every window that was sealed and not acknowledged is gone
    fn restart_at(&mut self, next_window: u64, next_index: u64, head: Hash, epoch: u64, now: u64) -> Result<(), String> {
        let unacknowledged = self.chain.deliver_from..self.chain.next_window;
        self.start_epoch(epoch, now);
        self.chain = Chain { next_window, next_index, head, deliver_from: next_window, delivered_index: next_index, delivered_head: head, ..self.chain };
        self.save_chain()?;
        for window in unacknowledged {
            remove_window(&self.dir, window)?;
        }
        Ok(())
    }

    /// The control server's signed position replaces the local chain, and nothing of the old one is proven any more.
    /// The server takes a window that opens an epoch only in a later one than it holds, which a ledger that was lost
    /// counts from one again. So the new epoch is later than both the one this ledger counts and the one the server holds
    pub fn rebase(&mut self, epoch: u64, next_window: u64, next_index: u64, head: Hash, now: u64) -> Result<(), String> {
        let epoch = self.chain.epoch.max(epoch).checked_add(1).ok_or_else(|| "The control server holds the last epoch there is".to_string())?;
        let unproven = self.proving.next_window.min(self.chain.deliver_from)..self.chain.deliver_from;
        self.restart_at(next_window, next_index, head, epoch, now)?;
        self.proving = Proving { next_window, state: State::default(), needs_fresh: true };
        self.save_proving()?;
        for window in unproven {
            remove_window(&self.dir, window)?;
        }
        Ok(())
    }

    /// Gives up every sealed window the control server has not acknowledged and continues where its copy of the chain stands.
    /// What it acknowledged and still waits for a proof is kept
    pub fn give_up_undelivered(&mut self, reason: &str) -> Result<(), String> {
        let (window, index, head) = (self.chain.deliver_from, self.chain.delivered_index, self.chain.delivered_head);
        self.notices.push(format!("Gave up {} sealed windows and continue at window {} with a gap: {}", self.undelivered(), window, reason));
        self.restart_at(window, index, head, self.chain.epoch + 1, self.open.opened_at)
    }

    fn stored(&self, window: u64) -> Result<Option<StoredWindow>, String> {
        read_optional(&window_path(&self.dir, window))
    }

    fn sealed(&self, stored: StoredWindow) -> Result<SealedWindow, String> {
        let header = stored.header;
        let mut leaves = Vec::with_capacity(stored.events.len());
        let mut sealed = Vec::with_capacity(stored.events.len());
        for (offset, bytes) in stored.events.iter().enumerate() {
            let index = header.first_index + offset as u64;
            let seed = seal::seed(&self.master, &self.agent, header.epoch, index, bytes);
            leaves.push(leaf(&self.agent, header.epoch, index, &seal::blind(&seed), bytes));
            sealed.push(seal::seal(&seed, &self.agent, header.epoch, index, bytes)?);
        }
        header.verify(&self.agent, &leaves)?;
        Ok(SealedWindow { header, leaves, sealed, releases: stored.releases })
    }

    /// The oldest sealed window the control server has not acknowledged.
    /// One that can no longer be read would hold back everything after it, so it is given up with what follows
    pub fn next_undelivered(&mut self) -> Result<Option<SealedWindow>, String> {
        if self.chain.deliver_from >= self.chain.next_window {
            return Ok(None);
        }
        let window = self.chain.deliver_from;
        let stored = self.stored(window).and_then(|stored| stored.ok_or_else(|| "its file is gone".to_string()));
        match stored.and_then(|stored| self.sealed(stored)) {
            Ok(sealed) => Ok(Some(sealed)),
            Err(reason) => {
                self.give_up_undelivered(&format!("window {} cannot be read, {}", window, reason))?;
                Ok(None)
            }
        }
    }

    /// Records that the control server acknowledged a window, in order
    pub fn delivered(&mut self, window: u64, keep_for_proof: bool) -> Result<(), String> {
        if window != self.chain.deliver_from {
            return Err(format!("Window {} was acknowledged while {} is next", window, self.chain.deliver_from));
        }
        let Ok(Some(acknowledged)) = self.stored(window) else {
            return Err(format!("Window {} was acknowledged and can no longer be read", window));
        };
        self.chain.deliver_from = window + 1;
        self.chain.delivered_index = acknowledged.header.next_index();
        self.chain.delivered_head = acknowledged.header.head;
        self.save_chain()?;
        self.keep_unproven(if keep_for_proof { self.unproven_limit } else { 0 })
    }

    pub fn undelivered(&self) -> u64 {
        self.chain.next_window - self.chain.deliver_from
    }

    /// Drops the plaintext of the oldest delivered windows so that no more than `kept` wait for a proof
    fn keep_unproven(&mut self, kept: u64) -> Result<(), String> {
        let first_kept = self.chain.deliver_from.saturating_sub(kept);
        if self.proving.next_window >= first_kept {
            return Ok(());
        }
        for window in self.proving.next_window..first_kept {
            remove_window(&self.dir, window)?;
        }
        self.proving = Proving { next_window: first_kept, state: State::default(), needs_fresh: true };
        self.save_proving()
    }

    /// Input of the next proof: delivered windows of one epoch, in order, up to a number of events
    pub fn proof_input(&mut self, max_events: usize) -> Result<Option<Input>, String> {
        self.pass_unprovable()?;
        self.build_input(max_events)
    }

    /// Moves proving past the windows no proof can cover. Once plaintext is gone the rule state after it is unknown,
    /// so every window up to the next one that opens an epoch is removed as it is passed
    fn pass_unprovable(&mut self) -> Result<(), String> {
        let before = (self.proving.next_window, self.proving.needs_fresh);
        while self.proving.next_window < self.chain.deliver_from {
            match self.stored(self.proving.next_window) {
                Ok(Some(stored)) if stored.header.fresh => {
                    self.proving.needs_fresh = false;
                    break;
                }
                Ok(Some(_)) if !self.proving.needs_fresh => break,
                _ => {
                    remove_window(&self.dir, self.proving.next_window)?;
                    self.proving = Proving { next_window: self.proving.next_window + 1, state: State::default(), needs_fresh: true };
                }
            }
        }
        if before != (self.proving.next_window, self.proving.needs_fresh) {
            self.save_proving()?;
        }
        Ok(())
    }

    fn build_input(&self, max_events: usize) -> Result<Option<Input>, String> {
        let mut windows: Vec<WindowInput> = Vec::new();
        let mut epoch = 0;
        let mut fresh = false;
        let mut events = 0;
        let mut head_in = GENESIS;
        for window in self.proving.next_window..self.chain.deliver_from {
            let Ok(Some(stored)) = self.stored(window) else { break };
            let header = &stored.header;
            if windows.is_empty() {
                epoch = header.epoch;
                fresh = header.fresh;
                head_in = header.prev_head;
            } else if header.epoch != epoch || events + stored.events.len() > max_events {
                break;
            }
            events += stored.events.len();
            let committed = stored
                .events
                .iter()
                .enumerate()
                .map(|(offset, bytes)| {
                    let seed = seal::seed(&self.master, &self.agent, header.epoch, header.first_index + offset as u64, bytes);
                    Committed { blind: seal::blind(&seed), event: bytes.clone() }
                })
                .collect();
            windows.push(WindowInput { window: header.window, first_index: header.first_index, gap: header.gap, events: committed });
        }

        let (Some(first), Some(last)) = (windows.first(), windows.last()) else {
            return Ok(None);
        };
        Ok(Some(Input {
            agent: self.agent,
            epoch,
            fresh,
            head_in,
            state: if fresh { State::default() } else { self.proving.state.clone() },
            salt_in: seal::salt(&self.master, &self.agent, first.window),
            salt_out: seal::salt(&self.master, &self.agent, last.window + 1),
            windows,
        }))
    }

    /// Records that a proof with this journal reached the control server, and drops the plaintext it covered
    pub fn proven(&mut self, journal: &Journal, state: State) -> Result<(), String> {
        if journal.first_window != self.proving.next_window || journal.last_window >= self.chain.deliver_from || self.proving.needs_fresh {
            return Err(format!(
                "The proof covers windows {} to {} while proving stands at window {}",
                journal.first_window, journal.last_window, self.proving.next_window
            ));
        }
        for window in journal.first_window..=journal.last_window {
            remove_window(&self.dir, window)?;
        }
        self.proving = Proving { next_window: journal.last_window + 1, state, needs_fresh: false };
        self.save_proving()
    }

    pub fn unproven(&self) -> u64 {
        self.chain.deliver_from.saturating_sub(self.proving.next_window)
    }

    /// How many delivered events wait for a proof
    pub fn unproven_events(&self) -> u64 {
        match self.stored(self.proving.next_window) {
            Ok(Some(first)) if self.unproven() > 0 => self.chain.delivered_index.saturating_sub(first.header.first_index),
            _ => 0,
        }
    }
}

fn remove_window(dir: &Path, window: u64) -> Result<(), String> {
    match fs::remove_file(window_path(dir, window)) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(format!("Failed to remove window {}: {}", window, e)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use zedr_protocol::{ProcessAction, ProcessEvent};
    use zedr_rules::{proof, RuleId};

    const AGENT: Hash = [4u8; 32];
    const MASTER: Hash = [5u8; 32];

    fn test_dir(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("zedr-ledger-{}-{}", std::process::id(), name));
        let _ = fs::remove_dir_all(&dir);
        dir
    }

    fn process(timestamp: u64, pid: u32, ppid: u32, path: &str, args: &[&str]) -> SensorEvent {
        let mut command_line = vec![path.to_string()];
        command_line.extend(args.iter().map(|arg| arg.to_string()));
        SensorEvent::Process(ProcessEvent {
            timestamp,
            pid,
            ppid,
            executable_path: path.to_string(),
            command_line,
            action: ProcessAction::Create,
            uid: 0,
            hash: None,
        })
    }

    fn quiet(pid: u32) -> SensorEvent {
        process(u64::from(pid), pid, 0, "/usr/bin/sleep", &["60"])
    }

    fn open_all(agent: &Hash, window: &SealedWindow) -> Vec<Option<SensorEvent>> {
        let opened: BTreeMap<u64, Hash> =
            window.releases.iter().flat_map(|release| release.openings.iter().map(|opening| (opening.index, opening.seed))).collect();
        (0..window.header.count as u64)
            .map(|offset| {
                let index = window.header.first_index + offset;
                opened.get(&index).map(|seed| {
                    SensorEvent::from_bytes(&seal::open(seed, agent, window.header.epoch, index, &window.sealed[offset as usize]).unwrap()).unwrap()
                })
            })
            .collect()
    }

    #[test]
    fn test_a_quiet_window_is_sealed_on_time_and_gives_the_server_nothing_to_open() {
        let dir = test_dir("quiet");
        let mut ledger = Ledger::open(&dir, AGENT, MASTER, 1000).unwrap();
        assert_eq!(ledger.admit(&[quiet(1), quiet(2)]), 0);
        assert_eq!(ledger.seal_due(1000 + WINDOW_SECONDS - 1).unwrap(), None);
        assert_eq!(ledger.seal_due(1000 + WINDOW_SECONDS).unwrap(), Some(0));

        let window = ledger.next_undelivered().unwrap().unwrap();
        assert!(window.header.fresh && !window.header.gap);
        assert_eq!((window.header.epoch, window.header.window, window.header.first_index, window.header.count), (1, 0, 0, 2));
        window.header.verify(&AGENT, &window.leaves).unwrap();
        assert!(window.releases.is_empty());
        assert_eq!(open_all(&AGENT, &window), vec![None, None]);
        assert!(window.sealed.iter().all(|sealed| seal::BUCKETS.contains(&(sealed.len() - 16))));

        assert_eq!(ledger.seal_due(1000 + 2 * WINDOW_SECONDS).unwrap(), Some(1), "an empty window is sealed too");
        ledger.delivered(0, true).unwrap();
        let empty = ledger.next_undelivered().unwrap().unwrap();
        assert_eq!((empty.header.count, empty.header.fresh, empty.header.prev_head), (0, false, window.header.head));

        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn test_a_clock_set_back_does_not_hold_a_window_open() {
        let dir = test_dir("clock");
        let mut ledger = Ledger::open(&dir, AGENT, MASTER, 90_000).unwrap();
        ledger.admit(&[quiet(1)]);
        assert_eq!(ledger.seal_due(2_000).unwrap(), Some(0));
        assert_eq!(ledger.seal_due(2_000 + WINDOW_SECONDS - 1).unwrap(), None);
        assert_eq!(ledger.seal_due(2_000 + WINDOW_SECONDS).unwrap(), Some(1));

        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn test_a_match_seals_at_once_and_opens_exactly_what_the_rule_read() {
        let dir = test_dir("match");
        let mut ledger = Ledger::open(&dir, AGENT, MASTER, 1000).unwrap();
        ledger.admit(&[process(1, 20, 0, "/usr/sbin/nginx", &[]), quiet(30)]);
        assert_eq!(ledger.seal_now(1001).unwrap(), 0);
        ledger.admit(&[quiet(31), process(2, 21, 20, "/bin/sh", &["-c", "id"]), quiet(32)]);
        assert_eq!(ledger.seal_due(1002).unwrap(), Some(1), "a rule fired, the window does not wait for its minute");

        let first = ledger.next_undelivered().unwrap().unwrap();
        ledger.delivered(0, true).unwrap();
        let second = ledger.next_undelivered().unwrap().unwrap();
        assert_eq!(second.releases.len(), 1);
        let release = &second.releases[0];
        assert_eq!(release.found, Match { trigger: 3, rule: RuleId::ServerChild, context: vec![0], pid: 21, started_at: 2 });
        assert_eq!(release.openings.iter().map(|opening| opening.index).collect::<Vec<_>>(), vec![3, 0]);

        let parent = release.openings.iter().find(|opening| opening.index == 0).unwrap();
        let opened = seal::open(&parent.seed, &AGENT, first.header.epoch, 0, &first.sealed[0]).unwrap();
        assert_eq!(leaf(&AGENT, first.header.epoch, 0, &seal::blind(&parent.seed), &opened), first.leaves[0], "the opened parent is the committed one");
        assert_eq!(SensorEvent::from_bytes(&opened).unwrap(), process(1, 20, 0, "/usr/sbin/nginx", &[]));

        let opened = open_all(&AGENT, &second);
        assert_eq!(opened, vec![None, Some(process(2, 21, 20, "/bin/sh", &["-c", "id"])), None], "the neighbours stay sealed");

        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn test_an_unacknowledged_window_is_offered_again_byte_for_byte_after_a_restart() {
        let dir = test_dir("restart");
        let mut ledger = Ledger::open(&dir, AGENT, MASTER, 1000).unwrap();
        ledger.admit(&[quiet(1), process(2, 21, 0, "/tmp/.x/kworker", &[])]);
        ledger.seal_due(1001).unwrap();
        let before = ledger.next_undelivered().unwrap().unwrap();
        ledger.admit(&[quiet(3)]);
        drop(ledger);

        let mut ledger = Ledger::open(&dir, AGENT, MASTER, 2000).unwrap();
        assert_eq!(ledger.epoch(), 2);
        assert_eq!(ledger.next_undelivered().unwrap().unwrap(), before);
        ledger.delivered(0, true).unwrap();
        assert_eq!(ledger.next_undelivered().unwrap(), None);

        ledger.admit(&[quiet(4)]);
        ledger.seal_now(2001).unwrap();
        let after = ledger.next_undelivered().unwrap().unwrap();
        assert!(after.header.fresh, "the sensor starts over, so does the rule state");
        assert_eq!(
            (after.header.epoch, after.header.window, after.header.first_index, after.header.prev_head),
            (2, 1, 2, before.header.head),
            "the event that was never sealed left no trace in the chain"
        );
        assert!(ledger.delivered(5, true).is_err(), "windows are acknowledged in order");

        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn test_proofs_cover_delivered_windows_in_order_and_free_their_plaintext() {
        let dir = test_dir("prove");
        let mut ledger = Ledger::open(&dir, AGENT, MASTER, 1000).unwrap();
        ledger.admit(&[process(1, 20, 0, "/usr/sbin/nginx", &[])]);
        ledger.seal_now(1001).unwrap();
        ledger.admit(&[process(2, 21, 20, "/bin/sh", &["-c", "id"])]);
        ledger.seal_now(1002).unwrap();
        ledger.admit(&[quiet(40), quiet(41), quiet(42)]);
        ledger.seal_now(1003).unwrap();
        assert_eq!(ledger.proof_input(100).unwrap(), None, "nothing is proven before the control server has it");

        let mut heads = Vec::new();
        while let Some(window) = ledger.next_undelivered().unwrap() {
            heads.push(window.header.head);
            ledger.delivered(window.header.window, true).unwrap();
        }
        assert_eq!(ledger.unproven(), 3);

        let input = ledger.proof_input(2).unwrap().unwrap();
        assert_eq!(input.windows.iter().map(|window| window.window).collect::<Vec<_>>(), vec![0, 1], "the third window would pass the event limit");
        let (journal, state) = proof::run(input).unwrap();
        assert!(journal.fresh);
        assert_eq!((journal.head_in, journal.head_out), (GENESIS, heads[1]));
        assert_eq!(journal.matches.len(), 1);
        ledger.proven(&journal, state).unwrap();
        assert!(!window_path(&dir, 0).exists() && !window_path(&dir, 1).exists() && window_path(&dir, 2).exists());

        let input = ledger.proof_input(100).unwrap().unwrap();
        assert!(!input.fresh);
        let (next, state) = proof::run(input).unwrap();
        assert_eq!(next.state_in, journal.state_out, "the second proof picks up the state the first one left");
        assert_eq!((next.first_window, next.head_in, next.head_out), (2, heads[1], heads[2]));
        ledger.proven(&next, state).unwrap();
        assert_eq!(ledger.proof_input(100).unwrap(), None);
        assert_eq!(ledger.unproven(), 0);

        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn test_a_proof_never_spans_two_epochs() {
        let dir = test_dir("epochs");
        let mut ledger = Ledger::open(&dir, AGENT, MASTER, 1000).unwrap();
        ledger.admit(&[quiet(1)]);
        ledger.seal_now(1001).unwrap();
        drop(ledger);
        let mut ledger = Ledger::open(&dir, AGENT, MASTER, 2000).unwrap();
        ledger.admit(&[quiet(2)]);
        ledger.seal_now(2001).unwrap();
        while let Some(window) = ledger.next_undelivered().unwrap() {
            ledger.delivered(window.header.window, true).unwrap();
        }

        let first = ledger.proof_input(100).unwrap().unwrap();
        assert_eq!((first.epoch, first.windows.len(), first.fresh), (1, 1, true));
        let (journal, state) = proof::run(first).unwrap();
        ledger.proven(&journal, state).unwrap();
        let second = ledger.proof_input(100).unwrap().unwrap();
        assert_eq!((second.epoch, second.windows.len(), second.fresh, &second.state), (2, 1, true, &State::default()));
        proof::run(second).unwrap();

        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn test_without_a_prover_plaintext_goes_as_soon_as_the_server_has_the_window() {
        let dir = test_dir("noprover");
        let mut ledger = Ledger::open(&dir, AGENT, MASTER, 1000).unwrap();
        ledger.admit(&[quiet(1)]);
        ledger.seal_now(1001).unwrap();
        assert!(window_path(&dir, 0).exists());
        ledger.delivered(0, false).unwrap();
        assert!(!window_path(&dir, 0).exists());
        assert_eq!(ledger.proof_input(100).unwrap(), None);
        assert_eq!(ledger.unproven(), 0);

        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn test_an_event_too_large_to_seal_is_refused_and_the_window_says_so() {
        let dir = test_dir("gap");
        let mut ledger = Ledger::open(&dir, AGENT, MASTER, 1000).unwrap();
        let huge = process(1, 9, 0, "/bin/true", &[&"x".repeat(seal::MAX_EVENT_BYTES)]);
        assert_eq!(ledger.admit(&[quiet(1), huge, quiet(2)]), 1);
        ledger.seal_now(1001).unwrap();
        let window = ledger.next_undelivered().unwrap().unwrap();
        assert!(window.header.gap);
        assert_eq!(window.header.count, 2);

        ledger.note_gap();
        ledger.seal_now(1002).unwrap();
        ledger.delivered(0, true).unwrap();
        assert!(ledger.next_undelivered().unwrap().unwrap().header.gap);

        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn test_the_ledger_directory_is_private() {
        let dir = test_dir("private");
        let mut ledger = Ledger::open(&dir, AGENT, MASTER, 1000).unwrap();
        ledger.admit(&[quiet(1)]);
        ledger.seal_now(1001).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(fs::metadata(&dir).unwrap().permissions().mode() & 0o777, 0o700);
            assert_eq!(fs::metadata(window_path(&dir, 0)).unwrap().permissions().mode() & 0o777, 0o600);
        }

        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn test_plaintext_dropped_in_the_middle_of_an_epoch_stops_proving_until_the_next_epoch() {
        let dir = test_dir("dropped");
        let mut ledger = Ledger::open(&dir, AGENT, MASTER, 1000).unwrap();
        for pid in 1..=4 {
            ledger.admit(&[quiet(pid)]);
            ledger.seal_now(1000 + u64::from(pid)).unwrap();
        }
        ledger.delivered(0, false).unwrap();
        ledger.delivered(1, false).unwrap();
        ledger.delivered(2, true).unwrap();
        ledger.delivered(3, true).unwrap();
        assert!(!window_path(&dir, 1).exists() && window_path(&dir, 2).exists() && window_path(&dir, 3).exists());
        assert_eq!(ledger.unproven(), 2);

        assert_eq!(ledger.proof_input(100).unwrap(), None, "the rule state after the dropped windows is unknown");
        assert!(!window_path(&dir, 2).exists() && !window_path(&dir, 3).exists(), "what cannot be proven is not kept");
        assert_eq!(ledger.unproven(), 0);
        drop(ledger);

        let mut ledger = Ledger::open(&dir, AGENT, MASTER, 2000).unwrap();
        ledger.admit(&[quiet(5)]);
        ledger.seal_now(2001).unwrap();
        ledger.admit(&[quiet(6)]);
        ledger.seal_now(2002).unwrap();
        ledger.delivered(4, true).unwrap();
        ledger.delivered(5, true).unwrap();

        let input = ledger.proof_input(100).unwrap().unwrap();
        assert_eq!((input.epoch, input.fresh, input.windows.iter().map(|window| window.window).collect::<Vec<_>>()), (2, true, vec![4, 5]));
        let (journal, state) = proof::run(input).unwrap();
        ledger.proven(&journal, state).unwrap();
        assert_eq!(ledger.unproven(), 0);

        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn test_past_the_limit_the_oldest_unproven_plaintext_is_dropped() {
        let dir = test_dir("limit");
        let mut ledger = Ledger::open(&dir, AGENT, MASTER, 1000).unwrap();
        assert_eq!(ledger.unproven_limit, UNPROVEN_WINDOWS_LIMIT);
        ledger.unproven_limit = 2;
        for pid in 1..=4 {
            ledger.admit(&[quiet(pid)]);
            let window = ledger.seal_now(1000 + u64::from(pid)).unwrap();
            ledger.delivered(window, true).unwrap();
        }

        assert!(!window_path(&dir, 0).exists() && !window_path(&dir, 1).exists() && window_path(&dir, 2).exists() && window_path(&dir, 3).exists());
        assert_eq!(ledger.unproven(), 2);
        assert_eq!(ledger.proof_input(100).unwrap(), None, "the windows that are left start from a rule state nobody can prove");
        assert_eq!(ledger.unproven(), 0);

        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn test_a_delivered_window_whose_plaintext_is_gone_is_passed() {
        let dir = test_dir("gone");
        let mut ledger = Ledger::open(&dir, AGENT, MASTER, 1000).unwrap();
        for pid in 1..=2 {
            ledger.admit(&[quiet(pid)]);
            let window = ledger.seal_now(1000 + u64::from(pid)).unwrap();
            ledger.delivered(window, true).unwrap();
        }
        fs::remove_file(window_path(&dir, 0)).unwrap();

        assert_eq!(ledger.proof_input(100).unwrap(), None);
        assert!(!window_path(&dir, 1).exists());
        assert_eq!(ledger.unproven(), 0);

        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn test_rebase_starts_a_new_epoch_at_the_position_the_server_signed() {
        let dir = test_dir("rebase");
        let mut ledger = Ledger::open(&dir, AGENT, MASTER, 1000).unwrap();
        ledger.admit(&[process(1, 20, 0, "/usr/sbin/nginx", &[])]);
        ledger.seal_now(1001).unwrap();
        ledger.delivered(0, true).unwrap();
        let (stale, stale_state) = proof::run(ledger.proof_input(100).unwrap().unwrap()).unwrap();
        ledger.admit(&[quiet(30)]);
        ledger.seal_now(1002).unwrap();
        ledger.admit(&[quiet(31)]);
        ledger.seal_now(1003).unwrap();
        ledger.admit(&[quiet(32)]);
        assert_eq!(ledger.undelivered(), 2);

        let head = [9u8; 32];
        ledger.rebase(1, 0, 50, head, 2000).unwrap();
        assert_eq!((ledger.epoch(), ledger.undelivered(), ledger.unproven()), (2, 0, 0));
        assert_eq!(ledger.next_undelivered().unwrap(), None);
        assert!((0..3).all(|window| !window_path(&dir, window).exists()), "nothing of the replaced chain is kept");
        assert!(ledger.proven(&stale, stale_state).is_err(), "a proof of the replaced chain frees nothing of the new one");

        ledger.admit(&[process(2, 21, 20, "/bin/sh", &["-c", "id"])]);
        assert_eq!(ledger.seal_due(2000 + WINDOW_SECONDS - 1).unwrap(), None, "the rules forgot the server process, its shell fires nothing");
        assert_eq!(ledger.seal_due(2000 + WINDOW_SECONDS).unwrap(), Some(0));
        let window = ledger.next_undelivered().unwrap().unwrap();
        assert!(window.header.fresh && window.header.gap);
        assert_eq!((window.header.epoch, window.header.window, window.header.first_index, window.header.count, window.header.prev_head), (2, 0, 50, 1, head));
        window.header.verify(&AGENT, &window.leaves).unwrap();

        ledger.delivered(0, true).unwrap();
        let input = ledger.proof_input(100).unwrap().unwrap();
        assert_eq!((input.epoch, input.fresh, input.head_in, input.windows.len(), input.windows[0].first_index), (2, true, head, 1, 50));
        let (journal, state) = proof::run(input).unwrap();
        assert_eq!((journal.first_window, journal.head_out), (0, window.header.head));
        ledger.proven(&journal, state).unwrap();
        drop(ledger);

        let mut ledger = Ledger::open(&dir, AGENT, MASTER, 3000).unwrap();
        ledger.seal_now(3001).unwrap();
        let next = ledger.next_undelivered().unwrap().unwrap();
        assert_eq!(
            (next.header.epoch, next.header.window, next.header.first_index, next.header.prev_head),
            (3, 1, 51, window.header.head),
            "the position survives a restart"
        );

        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn test_rebase_onto_a_longer_chain_continues_from_its_end_in_an_epoch_later_than_the_servers() {
        let dir = test_dir("ahead");
        let mut ledger = Ledger::open(&dir, AGENT, MASTER, 1000).unwrap();
        ledger.admit(&[quiet(1)]);
        ledger.seal_now(1001).unwrap();

        let head = [7u8; 32];
        ledger.rebase(57, 40, 900, head, 2000).unwrap();
        assert_eq!(ledger.epoch(), 58, "a ledger that counts from one again still opens an epoch the server takes");
        assert!(!window_path(&dir, 0).exists());
        ledger.rebase(3, 40, 900, head, 2000).unwrap();
        assert_eq!(ledger.epoch(), 59, "and never goes back to an epoch it has used");
        assert!(ledger.rebase(u64::MAX, 41, 901, [8u8; 32], 2000).is_err(), "there is no epoch after the last one");

        ledger.admit(&[quiet(2)]);
        ledger.seal_now(2001).unwrap();
        let window = ledger.next_undelivered().unwrap().unwrap();
        assert!(window.header.fresh && window.header.gap);
        assert_eq!(
            (window.header.epoch, window.header.window, window.header.first_index, window.header.prev_head),
            (59, 40, 900, head),
            "a position that cannot be taken up changes nothing"
        );

        ledger.delivered(40, true).unwrap();
        let input = ledger.proof_input(100).unwrap().unwrap();
        assert_eq!((input.windows[0].window, input.windows[0].first_index, input.head_in), (40, 900, head));
        proof::run(input).unwrap();

        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn test_a_window_that_cannot_be_written_is_lost_and_the_next_one_says_so() {
        let dir = test_dir("unwritable");
        let mut ledger = Ledger::open(&dir, AGENT, MASTER, 1000).unwrap();
        ledger.admit(&[process(1, 20, 0, "/usr/sbin/nginx", &[])]);
        fs::remove_dir_all(dir.join(WINDOWS_DIR)).unwrap();
        assert!(ledger.seal_now(1001).is_err());
        assert_eq!(ledger.epoch(), 2);
        assert_eq!(ledger.undelivered(), 0);

        fs::create_dir_all(dir.join(WINDOWS_DIR)).unwrap();
        ledger.admit(&[process(2, 21, 20, "/bin/sh", &["-c", "id"])]);
        assert_eq!(ledger.seal_now(1002).unwrap(), 0);
        let window = ledger.next_undelivered().unwrap().unwrap();
        assert!(window.header.fresh && window.header.gap);
        assert_eq!((window.header.epoch, window.header.first_index, window.header.count), (2, 0, 1));
        assert!(window.releases.is_empty(), "the rules started over, they do not refer to an event the chain does not hold");

        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn test_more_undelivered_windows_than_the_limit_are_given_up_and_the_chain_continues_where_the_server_stands() {
        let dir = test_dir("backlog");
        let mut ledger = Ledger::open(&dir, AGENT, MASTER, 1000).unwrap();
        assert_eq!(ledger.undelivered_limit, UNDELIVERED_WINDOWS_LIMIT);
        ledger.undelivered_limit = 3;
        ledger.admit(&[process(1, 20, 0, "/usr/sbin/nginx", &[])]);
        ledger.seal_now(1001).unwrap();
        let acknowledged = ledger.next_undelivered().unwrap().unwrap().header;
        ledger.delivered(0, true).unwrap();

        for pid in 1..=3 {
            ledger.admit(&[quiet(pid)]);
            ledger.seal_now(1001 + u64::from(pid)).unwrap();
        }
        assert_eq!((ledger.undelivered(), ledger.epoch()), (3, 1));
        assert!(ledger.take_notices().is_empty());

        ledger.admit(&[quiet(4)]);
        ledger.seal_now(1005).unwrap();
        assert_eq!((ledger.undelivered(), ledger.epoch()), (0, 2));
        assert!((1..=4).all(|window| !window_path(&dir, window).exists()));
        assert_eq!(
            ledger.take_notices(),
            vec!["Gave up 4 sealed windows and continue at window 1 with a gap: more than 3 waited for the control server".to_string()]
        );

        ledger.admit(&[process(2, 21, 20, "/bin/sh", &["-c", "id"])]);
        ledger.seal_now(1006).unwrap();
        let window = ledger.next_undelivered().unwrap().unwrap();
        assert!(window.header.fresh && window.header.gap);
        assert!(window.releases.is_empty(), "the rules started over, the server process is not remembered");
        assert_eq!(
            (window.header.epoch, window.header.window, window.header.first_index, window.header.prev_head),
            (2, 1, acknowledged.next_index(), acknowledged.head)
        );

        let input = ledger.proof_input(100).unwrap().unwrap();
        assert_eq!(input.windows.iter().map(|window| window.window).collect::<Vec<_>>(), vec![0], "what the server acknowledged still gets its proof");
        drop(ledger);

        let mut ledger = Ledger::open(&dir, AGENT, MASTER, 2000).unwrap();
        assert_eq!(ledger.next_undelivered().unwrap().unwrap(), window, "the position survives a restart");

        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn test_a_chain_file_that_is_cut_short_starts_the_chain_over_instead_of_stopping_the_ledger() {
        let dir = test_dir("chain-damaged");
        let mut ledger = Ledger::open(&dir, AGENT, MASTER, 1000).unwrap();
        ledger.admit(&[quiet(1)]);
        ledger.seal_now(1001).unwrap();
        ledger.delivered(0, true).unwrap();
        ledger.admit(&[quiet(2)]);
        ledger.seal_now(1002).unwrap();
        drop(ledger);
        let chain = fs::read(dir.join(CHAIN_FILE)).unwrap();
        fs::write(dir.join(CHAIN_FILE), &chain[..chain.len() / 2]).unwrap();

        let mut ledger = Ledger::open(&dir, AGENT, MASTER, 2000).unwrap();
        let notices = ledger.take_notices();
        assert!(notices.len() == 1 && notices[0].starts_with("Ledger chain cannot be used, starting over at the first window with a gap"), "{:?}", notices);
        assert!(ledger.take_notices().is_empty(), "it is said once");
        assert_eq!((ledger.epoch(), ledger.undelivered(), ledger.unproven()), (1, 0, 0));
        assert_eq!(fs::read_dir(dir.join(WINDOWS_DIR)).unwrap().count(), 0, "nothing of the lost chain is kept");

        ledger.admit(&[quiet(3)]);
        ledger.seal_now(2001).unwrap();
        let window = ledger.next_undelivered().unwrap().unwrap();
        assert!(window.header.fresh && window.header.gap);
        assert_eq!((window.header.window, window.header.first_index, window.header.prev_head), (0, 0, GENESIS));
        drop(ledger);

        let mut ledger = Ledger::open(&dir, AGENT, MASTER, 3000).unwrap();
        assert!(ledger.take_notices().is_empty());
        assert_eq!((ledger.epoch(), ledger.undelivered()), (2, 1));

        fs::write(dir.join("occupied"), "").unwrap();
        assert!(Ledger::open(&dir.join("occupied"), AGENT, MASTER, 3000).is_err(), "a place no ledger can be kept in is still an error");

        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn test_a_proving_file_that_is_garbage_resets_proving_and_leaves_the_chain_alone() {
        let dir = test_dir("proving-damaged");
        let mut ledger = Ledger::open(&dir, AGENT, MASTER, 1000).unwrap();
        for pid in 1..=3 {
            ledger.admit(&[quiet(pid)]);
            ledger.seal_now(1000 + u64::from(pid)).unwrap();
        }
        ledger.delivered(0, true).unwrap();
        drop(ledger);
        fs::write(dir.join(PROVING_FILE), b"not a proving state").unwrap();

        let mut ledger = Ledger::open(&dir, AGENT, MASTER, 2000).unwrap();
        let notices = ledger.take_notices();
        assert!(notices.len() == 1 && notices[0].starts_with("Ledger proving state cannot be used, nothing is proven before the next epoch"), "{:?}", notices);
        assert!(!window_path(&dir, 0).exists(), "plaintext that no proof will cover is not kept");
        assert_eq!((ledger.undelivered(), ledger.unproven()), (2, 0), "the chain is as it was");

        ledger.delivered(1, true).unwrap();
        ledger.delivered(2, true).unwrap();
        assert_eq!(ledger.proof_input(100).unwrap(), None, "the rule state these windows start from is not known any more");
        ledger.admit(&[quiet(4)]);
        ledger.seal_now(2001).unwrap();
        ledger.delivered(3, true).unwrap();
        let input = ledger.proof_input(100).unwrap().unwrap();
        assert_eq!((input.fresh, input.windows.iter().map(|window| window.window).collect::<Vec<_>>()), (true, vec![3]));

        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn test_an_undelivered_window_that_cannot_be_read_is_given_up_with_what_follows_it() {
        let dir = test_dir("window-gone");
        let mut ledger = Ledger::open(&dir, AGENT, MASTER, 1000).unwrap();
        ledger.admit(&[quiet(1)]);
        ledger.seal_now(1001).unwrap();
        let acknowledged = ledger.next_undelivered().unwrap().unwrap().header;
        ledger.delivered(0, false).unwrap();
        for pid in 2..=3 {
            ledger.admit(&[quiet(pid)]);
            ledger.seal_now(1000 + u64::from(pid)).unwrap();
        }
        fs::remove_file(window_path(&dir, 1)).unwrap();

        assert_eq!(ledger.next_undelivered().unwrap(), None);
        assert_eq!(
            ledger.take_notices(),
            vec!["Gave up 2 sealed windows and continue at window 1 with a gap: window 1 cannot be read, its file is gone".to_string()]
        );
        assert_eq!((ledger.epoch(), ledger.undelivered()), (2, 0));
        assert!(!window_path(&dir, 2).exists(), "the window after it chains to it and cannot be delivered either");

        ledger.admit(&[quiet(4)]);
        ledger.seal_now(1004).unwrap();
        let window = ledger.next_undelivered().unwrap().unwrap();
        assert!(window.header.fresh && window.header.gap);
        assert_eq!(
            (window.header.epoch, window.header.window, window.header.first_index, window.header.prev_head),
            (2, 1, acknowledged.next_index(), acknowledged.head)
        );

        fs::write(window_path(&dir, 1), b"not a window").unwrap();
        assert_eq!(ledger.next_undelivered().unwrap(), None);
        let notices = ledger.take_notices();
        assert!(notices.len() == 1 && notices[0].contains("window 1 cannot be read") && notices[0].contains("is damaged"), "{:?}", notices);
        assert_eq!((ledger.epoch(), ledger.undelivered()), (3, 0));

        fs::remove_dir_all(&dir).unwrap();
    }
}
