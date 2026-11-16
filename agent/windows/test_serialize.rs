
use zedr_shared::*;

fn main() {
    let install_event = InstallEvent {
        timestamp: 1234567890,
        version: "test".to_string(),
        hostname: "TEST-HOST".to_string(),
        platform: "windows".to_string(),
    };
    
    let json = serde_json::to_string(&install_event).unwrap();
    println!("Serialized: {}", json);
}

