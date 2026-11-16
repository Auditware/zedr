#[cfg(test)]
mod tests {
    use std::env;

    #[test]
    fn test_agent_starts() {
        println!("\nzedr Windows Agent v{}", env!("CARGO_PKG_VERSION"));
        println!("Platform: {} {}", env::consts::OS, env::consts::ARCH);

        if let Some(version) = crate::get_windows_version() {
            println!("Windows Version: {}", version);
        }

        println!("\nRunning collector test...");
        crate::collector::run();

        assert!(true);
    }
}
