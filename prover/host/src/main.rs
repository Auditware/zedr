use risc0_zkvm::{compute_image_id, default_prover, ExecutorEnv, ProverOpts, Receipt};
use std::path::Path;
use std::process::ExitCode;
use zedr_protocol::{ProcessAction, ProcessEvent, SensorEvent};
use zedr_rules::proof::{run, Committed, Input, Journal, WindowInput};
use zedr_rules::State;

static GUEST: &[u8] = include_bytes!(env!("ZEDR_GUEST_BIN"));

const USAGE: &str = "usage:
  zedr-prover image-id                     print the ID of the rule program this prover carries
  zedr-prover prove <input> <receipt>      prove a run of sealed windows
  zedr-prover verify <receipt> <image-id>  check a receipt against a rule program
  zedr-prover selftest [receipt]           prove and verify three built-in events, to see that proving works on this machine";

fn image_id() -> Result<String, String> {
    compute_image_id(GUEST).map(|digest| hex::encode(digest.as_bytes())).map_err(|e| format!("The embedded rule program has no image ID: {}", e))
}

fn prove_bytes(bytes: &[u8]) -> Result<(Receipt, Journal), String> {
    let (expected, _) = run(Input::from_bytes(bytes)?)?;

    let env = ExecutorEnv::builder().write_slice(bytes).build().map_err(|e| format!("Failed to prepare the proof: {}", e))?;
    let receipt = default_prover().prove_with_opts(env, GUEST, &ProverOpts::succinct()).map_err(|e| format!("Proving failed: {}", e))?.receipt;
    let journal = Journal::from_bytes(&receipt.journal.bytes)?;
    if journal != expected {
        return Err("The proof says something else than the rules do on this machine".to_string());
    }
    Ok((receipt, journal))
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
    let (receipt, journal) = prove_bytes(&bytes)?;
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
    let (receipt, journal) = prove_bytes(&input.to_bytes())?;
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

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let arguments: Vec<&str> = args.iter().map(String::as_str).collect();
    let outcome = match arguments.as_slice() {
        ["image-id"] => image_id(),
        ["prove", input, receipt] => prove(Path::new(input), Path::new(receipt)),
        ["verify", receipt, image_id] => verify(Path::new(receipt), image_id),
        ["selftest"] => selftest(None),
        ["selftest", receipt] => selftest(Some(Path::new(receipt))),
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
