/// zedr fleet simulator
///
/// A development tool: it plays a scenario against a control server as many endpoints at once, with the agent's own ledger and link,
/// so a demo shows what the product does. It is never built into an agent release
mod endpoint;
mod fleet;
mod scenario;
#[cfg(test)]
mod tests;

use std::io::Read;
use std::process::ExitCode;

const USAGE: &str = "usage:
  zedr-simulator <scenario.json>   play the scenario in this file
  zedr-simulator                   play the scenario read from standard input";

fn read_scenario() -> Result<String, String> {
    let arguments: Vec<String> = std::env::args().skip(1).collect();
    match arguments.as_slice() {
        [] => {
            let mut source = String::new();
            std::io::stdin().read_to_string(&mut source).map_err(|e| format!("Failed to read the scenario from standard input: {}", e))?;
            Ok(source)
        }
        [path] if !path.starts_with('-') => std::fs::read_to_string(path).map_err(|e| format!("Failed to read {}: {}", path, e)),
        _ => Err(USAGE.to_string()),
    }
}

fn main() -> ExitCode {
    let played = read_scenario().and_then(|source| scenario::Scenario::parse(&source)).and_then(|scenario| fleet::run(scenario, &mut std::io::stdout()));
    match played {
        Ok(()) => ExitCode::SUCCESS,
        Err(message) => {
            eprintln!("{}", message);
            ExitCode::FAILURE
        }
    }
}
