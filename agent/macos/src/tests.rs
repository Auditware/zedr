#[cfg(test)]
mod tests {
    use crate::get_macos_version;
    use std::env;

    #[test]
    fn test_agent_starts() {
        println!("\nzedr macOS Agent v{}", env!("CARGO_PKG_VERSION"));
        println!("Platform: {} {}", env::consts::OS, env::consts::ARCH);
        
        if let Some(version) = get_macos_version() {
            println!("macOS Version: {}", version);
        }
        
        println!("\nRunning collector test...");
        crate::collector::run();
        
        assert!(true);
    }

    #[test]
    fn test_get_macos_version() {
        let version = get_macos_version();
        assert!(version.is_some());
    }
}
