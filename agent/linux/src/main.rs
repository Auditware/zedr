mod collector;
mod files;
mod host;
mod packages;
mod persistence;
mod service;
mod systemd;
#[cfg(test)]
mod tests;

use std::process::ExitCode;
use zedr_shared::verify_self_signature;

fn main() -> ExitCode {
    if let Err(e) = verify_self_signature() {
        eprintln!("FATAL: Binary signature verification failed: {}", e);
        eprintln!("This agent has been tampered with and will not execute.");
        return ExitCode::FAILURE;
    }

    match service::run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("FATAL: {}", e);
            ExitCode::FAILURE
        }
    }
}
