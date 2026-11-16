mod collector;
#[cfg(test)]
mod tests;

use std::env;
use zedr_shared::verify_self_signature;

fn main() {
    if let Err(e) = verify_self_signature() {
        eprintln!("FATAL: Binary signature verification failed: {}", e);
        eprintln!("This agent has been tampered with and will not execute.");
        std::process::exit(1);
    }

    let server_url = zedr_shared::get_server_url();
    println!("zedr macOS Agent v{}", env!("CARGO_PKG_VERSION"));
    println!("Server: {}", server_url);
    println!("Platform: {} {}", env::consts::OS, env::consts::ARCH);

    if let Some(version) = get_macos_version() {
        println!("macOS Version: {}", version);
    }

    collector::run();
}

fn get_macos_version() -> Option<String> {
    // Use sysctl kern.osproductversion (available on modern macOS)
    use libc::size_t;
    let mut buf = [0u8; 256];
    let mut size = buf.len() as size_t;
    let name = c"kern.osproductversion";
    unsafe {
        if libc::sysctlbyname(name.as_ptr(), buf.as_mut_ptr() as *mut _, &mut size, std::ptr::null_mut(), 0) == 0 {
            // The size sysctl reports counts the terminating NUL
            if let Ok(s) = std::str::from_utf8(&buf[..size]) {
                return Some(s.trim_end_matches('\0').trim().to_string());
            }
        }
    }
    None
}
