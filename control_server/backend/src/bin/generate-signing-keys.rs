use ed25519_dalek::SigningKey;
use rand::rngs::OsRng;
use std::env;
use std::fs::{OpenOptions, read_to_string};
use std::io::Write;
use std::path::PathBuf;

fn main() {
    let project_root = env::var("CARGO_MANIFEST_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|_| env::current_dir().unwrap())
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .to_path_buf();
    
    let env_file = project_root.join("secrets/.env.local");
    
    if !env_file.exists() {
        eprintln!("Error: {} does not exist", env_file.display());
        std::process::exit(1);
    }
    
    let existing_content = read_to_string(&env_file)
        .expect("Failed to read .env.local");
    
    if existing_content.contains("ZEDR_SIGNING_KEY_HEX=") {
        eprintln!("Warning: ZEDR_SIGNING_KEY_HEX already exists in {}", env_file.display());
        eprint!("Overwrite existing keys? This will invalidate all signed binaries. (y/N): ");
        std::io::stderr().flush().unwrap();
        
        let mut input = String::new();
        std::io::stdin().read_line(&mut input).unwrap();
        
        if !input.trim().eq_ignore_ascii_case("y") {
            println!("Aborted.");
            return;
        }
    }
    
    println!("Generating ed25519 key pair...");
    
    let signing_key = SigningKey::generate(&mut OsRng);
    let verifying_key = signing_key.verifying_key();
    
    let private_key_hex = hex::encode(signing_key.to_bytes());
    let public_key_hex = hex::encode(verifying_key.to_bytes());
    
    let mut file = OpenOptions::new()
        .append(true)
        .open(&env_file)
        .expect("Failed to open .env.local");
    
    writeln!(file).unwrap();
    writeln!(file, "# Binary Signing Keys (ed25519)").unwrap();
    writeln!(file, "ZEDR_SIGNING_KEY_HEX={}", private_key_hex).unwrap();
    writeln!(file, "ZEDR_SIGNING_PUBLIC_KEY_HEX={}", public_key_hex).unwrap();
    
    println!();
    println!("✓ Generated ed25519 key pair");
    println!("✓ Private key: ZEDR_SIGNING_KEY_HEX (64 hex chars)");
    println!("✓ Public key:  ZEDR_SIGNING_PUBLIC_KEY_HEX (64 hex chars)");
    println!();
    println!("Keys added to: {}", env_file.display());
    println!();
    println!("Next steps:");
    println!("  1. Keep the env file out of git and back the private key up somewhere safe");
    println!("  2. Reinstall enrolled agents, they still trust the previous key");
    println!();
}
