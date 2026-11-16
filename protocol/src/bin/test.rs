use zedr_protocol::*;
fn main() {
    let event = InstallEvent {
        timestamp: 1234567890,
        version: "test".to_string(),
        hostname: "TEST-HOST".to_string(),
        platform: "windows".to_string(),
        os_version: "Windows 11".to_string(),
        architecture: "aarch64".to_string(),
    };
    
    let json = serde_json::to_string(&event).unwrap();
    println!("JSON: {}", json);
    
    let system_event = SystemEvent::Install(event);
    let json2 = serde_json::to_string(&system_event).unwrap(); 
    println!("SystemEvent JSON: {}", json2);
}
