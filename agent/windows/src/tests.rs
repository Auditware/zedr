use std::env;

use zedr_shared::sensor::Source;

use crate::collector::WindowsSource;

#[test]
fn test_agent_starts() {
    println!("\nzedr Windows Agent v{}", env!("CARGO_PKG_VERSION"));
    println!("Platform: {} {}", env::consts::OS, env::consts::ARCH);

    if let Some(version) = crate::get_windows_version() {
        println!("Windows Version: {}", version);
    }

    let mut source = WindowsSource::new();
    let processes = source.processes().unwrap();
    assert!(processes.iter().any(|key| key.pid == std::process::id()));

    let own = processes.iter().find(|key| key.pid == std::process::id()).unwrap();
    let details = source.describe(own).unwrap();
    assert!(!details.executable_path.is_empty());
    assert!(!details.command_line.is_empty());
}
