mod collector;
mod service;
#[cfg(test)]
mod tests;

use std::env;
use zedr_shared::verify_self_signature;

windows_service::define_windows_service!(ffi_service_main, service_main);

fn service_main(arguments: Vec<std::ffi::OsString>) {
    if let Err(e) = verify_self_signature() {
        service::log(&format!("FATAL: Binary signature verification failed: {}", e));
        service::log("This agent has been tampered with and will not execute.");
        return;
    }

    service::log("Service main entry point reached");
    if let Err(e) = service::run_service_loop(arguments) {
        service::log(&format!("Service error: {:?}", e));
    }
}

windows_service::define_windows_service!(ffi_staging_service_main, staging_service_main);

fn staging_service_main(arguments: Vec<std::ffi::OsString>) {
    if let Err(e) = verify_self_signature() {
        service::log(&format!("FATAL: Staging binary signature verification failed: {}", e));
        service::log("This staging agent has been tampered with and will not execute.");
        return;
    }

    service::log("Staging service main entry point reached");
    if let Err(e) = service::run_staging_service(arguments) {
        service::log(&format!("Staging service error: {:?}", e));
    }
}

fn main() -> windows_service::Result<()> {
    if let Err(e) = verify_self_signature() {
        eprintln!("FATAL: Binary signature verification failed: {}", e);
        eprintln!("This agent has been tampered with and will not execute.");
        std::process::exit(1);
    }

    let args: Vec<String> = env::args().collect();

    if args.len() > 1 {
        match args[1].as_str() {
            "install-service" => {
                println!("Installing zedr agent service...");
                match service::install_service() {
                    Ok(_) => {
                        println!("Service installed successfully");
                        Ok(())
                    }
                    Err(e) => {
                        eprintln!("Failed to install service: {}", e);
                        std::process::exit(1);
                    }
                }
            }
            "uninstall-service" => {
                println!("Uninstalling zedr agent service...");
                match service::uninstall_service() {
                    Ok(_) => {
                        println!("Service uninstalled successfully");
                        Ok(())
                    }
                    Err(e) => {
                        eprintln!("Failed to uninstall service: {}", e);
                        std::process::exit(1);
                    }
                }
            }
            "staging-service" => windows_service::service_dispatcher::start("zedr-agent-staging", ffi_staging_service_main),
            "--console" => windows_service::service_dispatcher::start("zedr-agent-staging", ffi_staging_service_main),
            _ => {
                print_usage();
                Ok(())
            }
        }
    } else {
        windows_service::service_dispatcher::start(service::SERVICE_NAME, ffi_service_main)
    }
}

fn run_console_mode() {
    println!("zedr Windows Agent v{}", env!("CARGO_PKG_VERSION"));
    println!("Running in console mode (for testing)");
    println!("Platform: {} {}", env::consts::OS, env::consts::ARCH);

    if let Some(version) = get_windows_version() {
        println!("Windows Version: {}", version);
    }

    collector::run();
}

fn print_usage() {
    println!("zedr Windows Agent v{}", env!("CARGO_PKG_VERSION"));
    println!();
    println!("Usage:");
    println!("  zedr-agent.exe                  - Run as Windows service (normal operation)");
    println!("  zedr-agent.exe install-service - Install as Windows service");
    println!("  zedr-agent.exe uninstall-service - Uninstall Windows service");
    println!("  zedr-agent.exe staging-service - Run as staging service (upgrade process)");
    println!("  zedr-agent.exe --console        - Run in console mode (testing)");
}

pub fn get_windows_version() -> Option<String> {
    use std::mem::zeroed;
    use windows::Win32::System::SystemInformation::{GetVersionExW, OSVERSIONINFOEXW};

    unsafe {
        let mut info: OSVERSIONINFOEXW = zeroed();
        info.dwOSVersionInfoSize = std::mem::size_of::<OSVERSIONINFOEXW>() as u32;
        if GetVersionExW(&mut info as *mut _ as *mut _).is_ok() {
            let major = info.dwMajorVersion;
            let minor = info.dwMinorVersion;
            let build = info.dwBuildNumber;
            Some(format!("{}.{}.{}", major, minor, build))
        } else {
            None
        }
    }
}
