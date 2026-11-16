use risc0_zkvm::{compute_image_id, default_prover, ExecutorEnv, ProverOpts, Receipt, SessionStats};
use std::path::Path;
use std::process::ExitCode;
use zedr_protocol::{NetworkAction, NetworkEvent, ProcessAction, ProcessEvent, SensorEvent};
use zedr_rules::proof::{run, Committed, Input, Journal, WindowInput};
use zedr_rules::State;

static GUEST: &[u8] = include_bytes!(env!("ZEDR_GUEST_BIN"));

#[cfg(target_env = "musl")]
#[global_allocator]
static ALLOCATOR: mimalloc::MiMalloc = mimalloc::MiMalloc;

const USAGE: &str = "usage:
  zedr-prover image-id                     print the ID of the rule program this prover carries
  zedr-prover prove <input> <receipt>      prove a run of sealed windows
  zedr-prover verify <receipt> <image-id>  check a receipt against a rule program
  zedr-prover selftest [receipt]           prove and verify three built-in events, to see that proving works on this machine
  zedr-prover bench <events>               prove that many made-up events of an ordinary workload, to see what a proof costs on this machine";

fn image_id() -> Result<String, String> {
    compute_image_id(GUEST).map(|digest| hex::encode(digest.as_bytes())).map_err(|e| format!("The embedded rule program has no image ID: {}", e))
}

/// The rule run is proven in segments of at most two to this power cycles. The memory a proof needs grows with the segment, about twofold per step,
/// and an endpoint has other work for its memory than a server has, so this is below the zkVM's own default of 20
const DEFAULT_SEGMENT_PO2: u32 = 18;
const SEGMENT_PO2_ENV: &str = "ZEDR_PROOF_SEGMENT_PO2";

fn segment_po2() -> Result<u32, String> {
    let Ok(set) = std::env::var(SEGMENT_PO2_ENV) else {
        return Ok(DEFAULT_SEGMENT_PO2);
    };
    set.parse().ok().filter(|po2| (13..=24).contains(po2)).ok_or_else(|| format!("{} is a whole number from 13 to 24, not {:?}", SEGMENT_PO2_ENV, set))
}

fn prove_bytes(bytes: &[u8]) -> Result<(Receipt, Journal, SessionStats), String> {
    let (expected, _) = run(Input::from_bytes(bytes)?)?;

    let env = ExecutorEnv::builder().write_slice(bytes).segment_limit_po2(segment_po2()?).build().map_err(|e| format!("Failed to prepare the proof: {}", e))?;
    // One proof per segment and nothing on top. Folding them into one small receipt took two thirds of the work of a proof when it was measured,
    // and the endpoint is the side that cannot spare it: the control server verifies every segment in well under a second and keeps no receipt
    let proven = default_prover().prove_with_opts(env, GUEST, &ProverOpts::composite()).map_err(|e| format!("Proving failed: {}", e))?;
    let journal = Journal::from_bytes(&proven.receipt.journal.bytes)?;
    if journal != expected {
        return Err("The proof says something else than the rules do on this machine".to_string());
    }
    Ok((proven.receipt, journal, proven.stats))
}

fn write_receipt(receipt: &Receipt, path: &Path) -> Result<usize, String> {
    let encoded = bincode::serialize(receipt).map_err(|e| format!("Failed to encode the receipt: {}", e))?;
    let partial = path.with_extension("partial");
    std::fs::write(&partial, &encoded).map_err(|e| format!("Failed to write {}: {}", partial.display(), e))?;
    std::fs::rename(&partial, path).map_err(|e| format!("Failed to move the receipt into place: {}", e))?;
    Ok(encoded.len())
}

fn prove(input_path: &Path, receipt_path: &Path) -> Result<String, String> {
    let bytes = std::fs::read(input_path).map_err(|e| format!("Failed to read {}: {}", input_path.display(), e))?;
    let (receipt, journal, _) = prove_bytes(&bytes)?;
    let size = write_receipt(&receipt, receipt_path)?;
    Ok(format!("windows {} to {}, {} events, {} matches, {} byte receipt", journal.first_window, journal.last_window, journal.next_index - journal.first_index, journal.matches.len(), size))
}

fn verify_receipt(receipt: &Receipt, image_id: &str) -> Result<Journal, String> {
    let mut id = [0u8; 32];
    hex::decode_to_slice(image_id, &mut id).map_err(|_| "The image ID is 64 hex characters".to_string())?;
    receipt.verify(id).map_err(|e| format!("The receipt does not verify: {}", e))?;
    Journal::from_bytes(&receipt.journal.bytes)
}

fn verify(receipt_path: &Path, image_id: &str) -> Result<String, String> {
    let bytes = std::fs::read(receipt_path).map_err(|e| format!("Failed to read {}: {}", receipt_path.display(), e))?;
    let receipt: Receipt = bincode::deserialize(&bytes).map_err(|e| format!("Not a receipt: {}", e))?;
    let journal = verify_receipt(&receipt, image_id)?;
    Ok(format!("verified windows {} to {} with {} matches", journal.first_window, journal.last_window, journal.matches.len()))
}

fn started(timestamp: u64, pid: u32, ppid: u32, path: &str, arguments: &[&str]) -> Committed {
    let mut command_line = vec![path.to_string()];
    command_line.extend(arguments.iter().map(|argument| argument.to_string()));
    let event = SensorEvent::Process(ProcessEvent { timestamp, pid, ppid, executable_path: path.to_string(), command_line, action: ProcessAction::Create, uid: 0, hash: None });
    Committed { blind: [pid as u8; 32], event: event.to_bytes() }
}

fn selftest(receipt_path: Option<&Path>) -> Result<String, String> {
    let events = vec![started(1, 20, 0, "/usr/sbin/nginx", &[]), started(2, 21, 20, "/bin/sh", &["-c", "id"]), started(3, 22, 0, "/usr/bin/sleep", &["60"])];
    let input = Input { agent: [7u8; 32], epoch: 1, fresh: true, head_in: [0u8; 32], state: State::default(), salt_in: [0u8; 32], salt_out: [9u8; 32], windows: vec![WindowInput { window: 0, first_index: 0, gap: false, events }] };

    let started_at = std::time::Instant::now();
    let (receipt, journal, _) = prove_bytes(&input.to_bytes())?;
    let seconds = started_at.elapsed().as_secs();
    let id = image_id()?;
    verify_receipt(&receipt, &id)?;
    if journal.matches.len() != 1 {
        return Err(format!("The built-in events should fire one rule and fired {}", journal.matches.len()));
    }
    if verify_receipt(&receipt, &"00".repeat(32)).is_ok() {
        return Err("The receipt verified against a rule program it was not made by".to_string());
    }
    if let Some(path) = receipt_path {
        write_receipt(&receipt, path)?;
    }
    Ok(format!("proved and verified 3 events with 1 match in {}s against image {}", seconds, id))
}

const BENCH_WINDOW_EVENTS: usize = 1000;
const BENCH_COMMANDS: &[(&str, &[&str])] = &[
    ("/usr/bin/git", &["status", "--porcelain=v2", "--branch"]),
    ("/usr/bin/python3", &["-m", "pytest", "tests/unit", "-q", "--maxfail=1"]),
    ("/usr/lib/systemd/systemd-timesyncd", &[]),
    ("/usr/bin/node", &["/srv/app/node_modules/.bin/vite", "build", "--mode", "production"]),
    ("/usr/bin/sleep", &["30"]),
    ("/usr/bin/curl", &["-fsS", "--max-time", "10", "https://updates.example.com/v2/manifest.json"]),
    ("/usr/sbin/cron", &["-f"]),
    ("/usr/bin/make", &["--no-print-directory", "-j8", "-C", "/home/dev/src/service", "test"]),
];

/// A run of windows over what a busy workstation reports: mostly processes that start and end, some connections, nothing a rule fires on
fn bench_input(events: usize) -> Input {
    let mut windows = Vec::new();
    for (window, first_index) in (0..events).step_by(BENCH_WINDOW_EVENTS).enumerate() {
        let committed = (first_index..events.min(first_index + BENCH_WINDOW_EVENTS))
            .map(|index| {
                let (timestamp, pid) = (1_700_000_000 + index as u64, 1000 + (index / 3) as u32);
                let (path, arguments) = BENCH_COMMANDS[(index / 3) % BENCH_COMMANDS.len()];
                let mut command_line = vec![path.to_string()];
                command_line.extend(arguments.iter().map(|argument| argument.to_string()));
                let process = |action| SensorEvent::Process(ProcessEvent { timestamp, pid, ppid: 1, executable_path: path.to_string(), command_line: command_line.clone(), action, uid: 1000, hash: None });
                let event = match index % 3 {
                    0 => process(ProcessAction::Create),
                    1 => SensorEvent::Network(NetworkEvent {
                        timestamp,
                        pid,
                        process_path: path.to_string(),
                        protocol: "tcp".to_string(),
                        source_ip: "10.0.4.17".to_string(),
                        source_port: 40000 + (index % 20000) as u16,
                        dest_ip: format!("198.51.100.{}", index % 250),
                        dest_port: 443,
                        action: NetworkAction::Connect,
                        bytes_sent: 0,
                        bytes_received: 0,
                    }),
                    _ => process(ProcessAction::Terminate),
                };
                Committed { blind: [index as u8; 32], event: event.to_bytes() }
            })
            .collect();
        windows.push(WindowInput { window: window as u64, first_index: first_index as u64, gap: false, events: committed });
    }
    Input { agent: [7u8; 32], epoch: 1, fresh: true, head_in: [0u8; 32], state: State::default(), salt_in: [0u8; 32], salt_out: [9u8; 32], windows }
}

fn bench(events: &str) -> Result<String, String> {
    let events: usize = events.parse().ok().filter(|count| *count > 0).ok_or_else(|| "The number of events is a whole number above zero".to_string())?;
    let input = bench_input(events);
    let windows = input.windows.len();
    let (expected, _) = run(input.clone())?;
    if !expected.matches.is_empty() {
        return Err(format!("The made-up workload should fire no rule and fired {}", expected.matches.len()));
    }

    let started_at = std::time::Instant::now();
    let (receipt, _, stats) = prove_bytes(&input.to_bytes())?;
    let seconds = started_at.elapsed().as_secs_f64();
    verify_receipt(&receipt, &image_id()?)?;
    let receipt_bytes = bincode::serialize(&receipt).map_err(|e| format!("Failed to encode the receipt: {}", e))?.len();
    Ok(format!(
        "proved and verified {} events in {} windows in {:.0}s: {} cycles of the rules, {} cycles proven in {} segments, {} byte receipt",
        events, windows, seconds, stats.user_cycles, stats.total_cycles, stats.segments, receipt_bytes
    ))
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let arguments: Vec<&str> = args.iter().map(String::as_str).collect();
    let outcome = match arguments.as_slice() {
        ["image-id"] => image_id(),
        ["prove", input, receipt] => prove(Path::new(input), Path::new(receipt)),
        ["verify", receipt, image_id] => verify(Path::new(receipt), image_id),
        ["selftest"] => selftest(None),
        ["selftest", receipt] => selftest(Some(Path::new(receipt))),
        ["bench", events] => bench(events),
        _ => Err(USAGE.to_string()),
    };
    match outcome {
        Ok(line) => {
            println!("{}", line);
            ExitCode::SUCCESS
        }
        Err(message) => {
            eprintln!("{}", message);
            ExitCode::FAILURE
        }
    }
}
