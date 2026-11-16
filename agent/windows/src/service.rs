use std::env;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{mpsc, Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use std::fs::OpenOptions;
use std::io::Write;
use std::path::PathBuf;
use std::process::Command;
use std::ffi::OsString;
use zedr_shared::link::{ControlLink, HostDescription};
use zedr_shared::runtime::{self, Platform, Runtime};
use zedr_shared::SystemEvent;
use zedr_protocol::{StopReason, UpgradeCommand, UpgradeEvent, UpgradeStatus};
use windows_service::{
    service::{
        ServiceControl, ServiceControlAccept, ServiceExitCode, ServiceState, ServiceStatus,
        ServiceType, ServiceAccess, ServiceStartType, ServiceErrorControl, ServiceInfo,
    },
    service_control_handler::{self, ServiceControlHandlerResult},
    service_manager::{ServiceManager, ServiceManagerAccess},
};
use winreg::enums::*;
use winreg::RegKey;

pub const SERVICE_NAME: &str = "zedr-agent";
const SERVICE_TYPE: ServiceType = ServiceType::OWN_PROCESS;
pub const STAGING_SERVICE_NAME: &str = "zedr-agent-staging";

static LINK: Mutex<Option<Arc<ControlLink>>> = Mutex::new(None);
static UPGRADE_HANDOFF: AtomicBool = AtomicBool::new(false);

fn data_dir() -> Result<PathBuf, String> {
    env::var("ProgramData")
        .map(|base| PathBuf::from(base).join("zedr"))
        .map_err(|_| "ProgramData is not set".to_string())
}

fn link() -> Result<Arc<ControlLink>, String> {
    let mut guard = LINK.lock()
        .map_err(|e| format!("Failed to lock control link: {}", e))?;

    if let Some(link) = guard.as_ref() {
        return Ok(Arc::clone(link));
    }

    let agent_id = get_machine_guid()
        .map_err(|e| format!("Failed to read machine GUID: {}", e))?;
    let link = Arc::new(ControlLink::open(zedr_shared::get_server_url(), &data_dir()?, agent_id)?);
    *guard = Some(Arc::clone(&link));

    Ok(link)
}

fn send_events(events: Vec<SystemEvent>, timeout_secs: u64) -> Result<minreq::Response, String> {
    link()?.send_events(events, timeout_secs)
}

fn notify_stopping(reason: StopReason) {
    match link().and_then(|link| link.notify_stopping(reason)) {
        Ok(status) => log(&format!("Stop notice response: {}", status)),
        Err(e) => log(&format!("Stop notice failed: {}", e)),
    }
}

struct WindowsPlatform;

impl Platform for WindowsPlatform {
    fn log(&self, message: &str) {
        log(message);
    }

    fn shell_invocation(&self, command_text: &str) -> Command {
        crate::shell::powershell(command_text)
    }

    fn upgrade(&self, command: UpgradeCommand) {
        handle_upgrade(command);
    }
}

fn get_log_path() -> String {
    std::env::var("TEMP").unwrap_or_else(|_| "C:\\Windows\\Temp".to_string()) + "\\zedr-agent.log"
}

pub fn log(msg: &str) {
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    
    if let Ok(mut file) = OpenOptions::new()
        .create(true)
        .append(true)
        .open(&get_log_path())
    {
        let _ = writeln!(file, "[{}] {}", timestamp, msg);
    }
}

pub fn run_service_loop(arguments: Vec<std::ffi::OsString>) -> Result<(), Box<dyn std::error::Error>> {
    log("Service loop starting");
    
    let mut from_version: Option<String> = None;
    let mut to_version: Option<String> = None;
    
    let mut i = 0;
    while i < arguments.len() {
        let arg = arguments[i].to_string_lossy();
        match arg.as_ref() {
            "--upgraded-from" if i + 1 < arguments.len() => {
                from_version = Some(arguments[i + 1].to_string_lossy().to_string());
                i += 2;
            }
            "--upgraded-to" if i + 1 < arguments.len() => {
                to_version = Some(arguments[i + 1].to_string_lossy().to_string());
                i += 2;
            }
            _ => i += 1,
        }
    }
    
    if let (Some(from), Some(to)) = (from_version, to_version) {
        log(&format!("Detected upgrade: {} -> {}", from, to));
        send_upgrade_event(&from, &to, UpgradeStatus::Completed, None);
        log("Upgrade completion event sent");
    }
    
    let (shutdown_tx, shutdown_rx) = mpsc::channel();

    let event_handler = move |control_event| -> ServiceControlHandlerResult {
        match control_event {
            ServiceControl::Stop => {
                let _ = shutdown_tx.send(StopReason::ServiceStop);
                ServiceControlHandlerResult::NoError
            }
            ServiceControl::Shutdown => {
                let _ = shutdown_tx.send(StopReason::SystemShutdown);
                ServiceControlHandlerResult::NoError
            }
            ServiceControl::Interrogate => ServiceControlHandlerResult::NoError,
            _ => ServiceControlHandlerResult::NotImplemented,
        }
    };

    let status_handle = service_control_handler::register(SERVICE_NAME, event_handler)?;

    status_handle.set_service_status(ServiceStatus {
        service_type: SERVICE_TYPE,
        current_state: ServiceState::Running,
        controls_accepted: ServiceControlAccept::STOP | ServiceControlAccept::SHUTDOWN,
        exit_code: ServiceExitCode::Win32(0),
        checkpoint: 0,
        wait_hint: Duration::default(),
        process_id: None,
    })?;

    log("Service status set to Running");
    
    let hostname = match env::var("COMPUTERNAME") {
        Ok(name) => name,
        Err(_) => "UNKNOWN".to_string(),
    };
    let runtime = Arc::new(Runtime::new(
        link()?,
        WindowsPlatform,
        HostDescription {
            hostname,
            os_version: get_windows_version(),
            agent_version: env!("CARGO_PKG_VERSION").to_string(),
        },
    ));

    match runtime.run_until_stopped(&shutdown_rx, runtime::heartbeat_interval()) {
        Some(reason) => {
            log(&format!("Stop signal received: {:?}", reason));
            if !UPGRADE_HANDOFF.load(Ordering::SeqCst) {
                notify_stopping(reason);
            }
        }
        None => log("Stop channel closed"),
    }

    status_handle.set_service_status(ServiceStatus {
        service_type: SERVICE_TYPE,
        current_state: ServiceState::Stopped,
        controls_accepted: ServiceControlAccept::empty(),
        exit_code: ServiceExitCode::Win32(0),
        checkpoint: 0,
        wait_hint: Duration::default(),
        process_id: None,
    })?;

    Ok(())
}

fn get_machine_guid() -> Result<String, Box<dyn std::error::Error>> {
    let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);
    let crypto_key = hklm.open_subkey("SOFTWARE\\Microsoft\\Cryptography")?;
    let guid: String = crypto_key.get_value("MachineGuid")?;
    Ok(guid)
}

fn get_windows_version() -> String {
    let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);
    
    if let Ok(key) = hklm.open_subkey("SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion") {
        let product_name: String = key.get_value("ProductName").unwrap_or_else(|_| "Windows".to_string());
        let display_version: String = key.get_value("DisplayVersion").unwrap_or_else(|_| String::new());
        let current_build: String = key.get_value("CurrentBuild").unwrap_or_else(|_| String::new());
        
        if !display_version.is_empty() {
            format!("{} {} (Build {})", product_name, display_version, current_build)
        } else if !current_build.is_empty() {
            format!("{} (Build {})", product_name, current_build)
        } else {
            product_name
        }
    } else {
        "Windows".to_string()
    }
}

pub fn install_service() -> windows_service::Result<()> {
    let manager = ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT | ServiceManagerAccess::CREATE_SERVICE)?;
    
    let exe_path = std::env::current_exe()
        .map_err(|e| windows_service::Error::Winapi(std::io::Error::new(std::io::ErrorKind::Other, format!("Failed to get exe path: {}", e))))?;
    
    let service_info = ServiceInfo {
        name: OsString::from(SERVICE_NAME),
        display_name: OsString::from("Zedr EDR Agent"),
        service_type: ServiceType::OWN_PROCESS,
        start_type: ServiceStartType::AutoStart,
        error_control: ServiceErrorControl::Normal,
        executable_path: exe_path.clone(),
        launch_arguments: vec![],
        dependencies: vec![],
        account_name: None,
        account_password: None,
    };
    
    let service = manager.create_service(&service_info, ServiceAccess::CHANGE_CONFIG | ServiceAccess::START)?;
    
    service.set_description("Zedr lightweight EDR agent for endpoint detection and response")?;
    
    service.start::<&str>(&[])?;
    
    Ok(())
}

pub fn uninstall_service() -> windows_service::Result<()> {
    let manager = ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT)?;
    
    let service = manager.open_service(SERVICE_NAME, ServiceAccess::QUERY_STATUS | ServiceAccess::STOP | ServiceAccess::DELETE)?;
    
    let service_status = service.query_status()?;
    if service_status.current_state != ServiceState::Stopped {
        service.stop()?;
        std::thread::sleep(std::time::Duration::from_secs(2));
    }
    
    service.delete()?;
    
    Ok(())
}

// ============================================================================
// UPGRADE SYSTEM
// ============================================================================

fn get_staging_binary_path() -> Result<PathBuf, String> {
    let current_exe = std::env::current_exe()
        .map_err(|e| format!("Failed to get current exe path: {}", e))?;
    let parent = current_exe.parent()
        .ok_or_else(|| "Failed to get parent directory".to_string())?;
    
    Ok(parent.join("zedr-agent-staging.exe"))
}

fn send_upgrade_event(from_version: &str, to_version: &str, status: UpgradeStatus, error: Option<String>) {
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    
    let upgrade_event = SystemEvent::Upgrade(UpgradeEvent {
        timestamp,
        from_version: from_version.to_string(),
        to_version: to_version.to_string(),
        status: status.clone(),
        error,
    });

    match send_events(vec![upgrade_event], 10) {
        Ok(response) => {
            if response.status_code == 200 {
                log(&format!("Upgrade event sent: {} -> {} ({:?})", from_version, to_version, status));
            } else {
                log(&format!("Failed to send upgrade event: HTTP {}", response.status_code));
            }
        }
        Err(e) => {
            log(&format!("Failed to send upgrade event: {}", e));
        }
    }
}

fn cleanup_staging_artifacts() {
    let _ = std::fs::remove_file(get_staging_binary_path().unwrap_or_default());
}

fn handle_upgrade(upgrade_cmd: UpgradeCommand) {
    let current_version = zedr_shared::AGENT_VERSION;
    log(&format!("Starting upgrade process: {} -> {}", current_version, upgrade_cmd.target_version));
    
    let agent_id = match get_machine_guid() {
        Ok(id) => id,
        Err(e) => {
            let error_msg = format!("Failed to get agent ID: {}", e);
            log(&error_msg);
            send_upgrade_event(current_version, &upgrade_cmd.target_version, UpgradeStatus::Failed, Some(error_msg));
            return;
        }
    };

    if let Err(e) = link().and_then(|link| link.verify_upgrade_command(&upgrade_cmd)) {
        let error_msg = format!("Upgrade command verification failed: {}", e);
        log(&error_msg);
        send_upgrade_event(current_version, &upgrade_cmd.target_version, UpgradeStatus::Failed, Some(error_msg));
        return;
    }
    
    log("Upgrade command signature verified successfully");
    
    send_upgrade_event(current_version, &upgrade_cmd.target_version, UpgradeStatus::Started, None);
    
    let server_url = zedr_shared::get_server_url();
    
    let binary_data = match zedr_shared::upgrade::download_upgrade_binary(&server_url, &agent_id, &upgrade_cmd.target_version) {
        Ok(data) => {
            log("UPGRADE: Binary downloaded and verified successfully");
            data
        }
        Err(e) => {
            let error_msg = format!("Failed to download binary: {}", e);
            log(&error_msg);
            send_upgrade_event(current_version, &upgrade_cmd.target_version, UpgradeStatus::Failed, Some(error_msg));
            return;
        }
    };
    
    let temp_path = match zedr_shared::upgrade::save_temp_binary(&binary_data) {
        Ok(path) => path,
        Err(e) => {
            let error_msg = format!("Failed to save binary: {}", e);
            log(&error_msg);
            send_upgrade_event(current_version, &upgrade_cmd.target_version, UpgradeStatus::Failed, Some(error_msg));
            return;
        }
    };
    
    if let Err(e) = staging_service_upgrade(&temp_path, &upgrade_cmd.target_version) {
        let error_msg = format!("Staging service upgrade failed: {}", e);
        log(&error_msg);
        let _ = std::fs::remove_file(&temp_path);
        send_upgrade_event(current_version, &upgrade_cmd.target_version, UpgradeStatus::Failed, Some(error_msg));
    }
}

fn staging_service_upgrade(binary_path: &PathBuf, to_version: &str) -> Result<(), String> {
    let current_exe = std::env::current_exe()
        .map_err(|e| format!("Failed to get current exe path: {}", e))?;
    
    let staging_binary = get_staging_binary_path()?;
    
    std::fs::copy(binary_path, &staging_binary)
        .map_err(|e| format!("Failed to copy binary to staging location: {}", e))?;
    
    log(&format!("STAGING: Binary copied to {:?}", staging_binary));
    log("UPGRADE: Creating or starting staging service");
    
    let manager = ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT | ServiceManagerAccess::CREATE_SERVICE)
        .map_err(|e| format!("Failed to open service manager: {}", e))?;
    
    let service = match manager.open_service(STAGING_SERVICE_NAME, ServiceAccess::START | ServiceAccess::QUERY_STATUS) {
        Ok(existing_service) => {
            log("STAGING: Using existing staging service");
            existing_service
        }
        Err(_) => {
            log("STAGING: Creating new staging service (first upgrade)");
            let service_info = ServiceInfo {
                name: OsString::from(STAGING_SERVICE_NAME),
                display_name: OsString::from("Zedr Agent Staging Service"),
                service_type: ServiceType::OWN_PROCESS,
                start_type: ServiceStartType::OnDemand,
                error_control: ServiceErrorControl::Normal,
                executable_path: staging_binary.clone(),
                launch_arguments: vec![
                    OsString::from("staging-service"),
                    OsString::from("--from-version"),
                    OsString::from(zedr_shared::AGENT_VERSION),
                    OsString::from("--to-version"),
                    OsString::from(to_version),
                    OsString::from("--old-service"),
                    OsString::from(SERVICE_NAME),
                    OsString::from("--primary-binary"),
                    OsString::from(current_exe.to_string_lossy().as_ref()),
                ],
                dependencies: vec![],
                account_name: None,
                account_password: None,
            };
            
            manager.create_service(
                &service_info,
                ServiceAccess::START | ServiceAccess::QUERY_STATUS,
            ).map_err(|e| {
                log(&format!("STAGING ERROR: Failed to create staging service: {:?}", e));
                format!("Failed to create staging service: {:?}", e)
            })?
        }
    };
    
    log("STAGING: Starting staging service");
    service.start(&[
        "--from-version",
        zedr_shared::AGENT_VERSION,
        "--to-version",
        to_version,
        "--old-service",
        SERVICE_NAME,
        "--primary-binary",
        &current_exe.to_string_lossy(),
    ])
        .map_err(|e| format!("Failed to start staging service: {}", e))?;
    
    log("STAGING: Staging service started, waiting for validation (service status query)");
    
    let start_time = std::time::Instant::now();
    let timeout = std::time::Duration::from_secs(60);
    
    loop {
        let status = service.query_status()
            .map_err(|e| format!("Failed to query staging service status: {}", e))?;
        
        if status.current_state == ServiceState::Running {
            let validation_time = start_time.elapsed().as_secs();
            log(&format!("STAGING: Staging service validated (Running) after {}s", validation_time));
            break;
        }
        
        if status.current_state == ServiceState::Stopped {
            cleanup_staging_artifacts();
            return Err("Staging service stopped unexpectedly during validation".to_string());
        }
        
        if start_time.elapsed() > timeout {
            cleanup_staging_artifacts();
            return Err("Staging service validation timed out after 60s".to_string());
        }
        
        std::thread::sleep(std::time::Duration::from_millis(200));
    }
    
    log("STAGING: Sending handoff event to server");
    send_upgrade_event(zedr_shared::AGENT_VERSION, to_version, UpgradeStatus::Handoff, None);
    
    log("STAGING: Stopping old service and exiting for takeover");
    UPGRADE_HANDOFF.store(true, Ordering::SeqCst);
    notify_stopping(StopReason::Upgrade);
    
    let manager = ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT)
        .map_err(|e| format!("Failed to open service manager: {}", e))?;
    
    let self_service = manager.open_service(SERVICE_NAME, ServiceAccess::STOP)
        .map_err(|e| format!("Failed to open self service: {}", e))?;
    
    self_service.stop()
        .map_err(|e| format!("Failed to stop self service: {}", e))?;
    
    std::process::exit(0);
}

fn staging_validation_and_takeover(
    from_version: &str,
    to_version: &str,
    old_service: &str,
    primary_binary: PathBuf,
) -> Result<(), String> {
    log("STAGING: Starting validation and takeover process");
    
    let current_exe = std::env::current_exe()
        .map_err(|e| format!("Failed to get current exe: {}", e))?;
    
    let binary_data = std::fs::read(&current_exe)
        .map_err(|e| format!("Failed to read staging binary: {}", e))?;
    
    if let Err(e) = zedr_shared::verify_binary_signature(&binary_data) {
        return Err(format!("Staging binary signature validation failed: {}", e));
    }
    
    log("STAGING: Binary signature valid");
    
    let server_url = zedr_shared::get_server_url();
    let test_url = format!("{}/api/ping", server_url);
    
    match minreq::get(&test_url).with_timeout(5).send() {
        Ok(_) => log("STAGING: Server connectivity confirmed"),
        Err(e) => return Err(format!("Server connectivity test failed: {}", e)),
    }
    
    log("STAGING: All validations passed, waiting for old service to stop");
    
    let manager = ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT)
        .map_err(|e| format!("Failed to open service manager: {}", e))?;
    
    let old_service_handle = manager.open_service(old_service, ServiceAccess::QUERY_STATUS | ServiceAccess::START)
        .map_err(|e| format!("Failed to open old service: {}", e))?;
    
    let start_time = std::time::Instant::now();
    let timeout = std::time::Duration::from_secs(30);
    
    loop {
        let status = old_service_handle.query_status()
            .map_err(|e| format!("Failed to query old service status: {}", e))?;
        
        if status.current_state == ServiceState::Stopped {
            log("STAGING: Old service stopped");
            break;
        }
        
        if start_time.elapsed() > timeout {
            let error_msg = "Timeout waiting for old service to stop";
            send_upgrade_event(from_version, to_version, UpgradeStatus::Failed, Some(error_msg.to_string()));
            return Err(error_msg.to_string());
        }
        
        std::thread::sleep(std::time::Duration::from_millis(200));
    }
    
    log("STAGING: Replacing binary in-place");
    std::thread::sleep(std::time::Duration::from_secs(1));
    
    std::fs::copy(&current_exe, &primary_binary)
        .map_err(|e| {
            let error_msg = format!("Failed to copy new binary to primary location: {}", e);
            send_upgrade_event(from_version, to_version, UpgradeStatus::Failed, Some(error_msg.clone()));
            error_msg
        })?;
    
    log("STAGING: Binary replacement complete, starting main service");
    
    old_service_handle.start::<&str>(&[])
        .map_err(|e| {
            let error_msg = format!("Failed to start main service: {}", e);
            send_upgrade_event(from_version, to_version, UpgradeStatus::Failed, Some(error_msg.clone()));
            error_msg
        })?;
    
    log("STAGING: Main service started");
    
    let start_time = std::time::Instant::now();
    let timeout = std::time::Duration::from_secs(30);
    
    loop {
        let status = old_service_handle.query_status()
            .map_err(|e| format!("Failed to query main service status: {}", e))?;
        
        if status.current_state == ServiceState::Running {
            log("STAGING: Main service running with new binary");
            break;
        }
        
        if start_time.elapsed() > timeout {
            let error_msg = "Timeout waiting for main service to start";
            send_upgrade_event(from_version, to_version, UpgradeStatus::Failed, Some(error_msg.to_string()));
            return Err(error_msg.to_string());
        }
        
        std::thread::sleep(std::time::Duration::from_millis(200));
    }
    
    send_upgrade_event(from_version, to_version, UpgradeStatus::Completed, None);
    log("STAGING: Upgrade complete, stopping staging service");
    
    Ok(())
}

pub fn run_staging_service(args: Vec<OsString>) -> windows_service::Result<()> {
    log("Staging service starting");
    
    let mut from_version: Option<String> = None;
    let mut to_version: Option<String> = None;
    let mut old_service: Option<String> = None;
    let mut primary_binary: Option<PathBuf> = None;
    
    let mut i = 0;
    while i < args.len() {
        let arg = args[i].to_string_lossy();
        match arg.as_ref() {
            "--from-version" if i + 1 < args.len() => {
                from_version = Some(args[i + 1].to_string_lossy().to_string());
                i += 2;
            }
            "--to-version" if i + 1 < args.len() => {
                to_version = Some(args[i + 1].to_string_lossy().to_string());
                i += 2;
            }
            "--old-service" if i + 1 < args.len() => {
                old_service = Some(args[i + 1].to_string_lossy().to_string());
                i += 2;
            }
            "--primary-binary" if i + 1 < args.len() => {
                primary_binary = Some(PathBuf::from(args[i + 1].to_string_lossy().to_string()));
                i += 2;
            }
            _ => i += 1,
        }
    }
    
    let from_version = from_version.ok_or_else(|| {
        windows_service::Error::Winapi(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "Missing --from-version argument"
        ))
    })?;
    let to_version = to_version.ok_or_else(|| {
        windows_service::Error::Winapi(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "Missing --to-version argument"
        ))
    })?;
    let old_service = old_service.ok_or_else(|| {
        windows_service::Error::Winapi(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "Missing --old-service argument"
        ))
    })?;
    let primary_binary = primary_binary.ok_or_else(|| {
        windows_service::Error::Winapi(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "Missing --primary-binary argument"
        ))
    })?;
    
    log(&format!("STAGING: Parsed args: {} -> {}, old_service={}, primary_binary={:?}", 
        from_version, to_version, old_service, primary_binary));
    
    let event_handler = move |control_event| -> ServiceControlHandlerResult {
        match control_event {
            ServiceControl::Stop | ServiceControl::Shutdown => {
                ServiceControlHandlerResult::NoError
            }
            ServiceControl::Interrogate => ServiceControlHandlerResult::NoError,
            _ => ServiceControlHandlerResult::NotImplemented,
        }
    };
    
    let status_handle = service_control_handler::register(STAGING_SERVICE_NAME, event_handler)?;
    
    status_handle.set_service_status(ServiceStatus {
        service_type: ServiceType::OWN_PROCESS,
        current_state: ServiceState::Running,
        controls_accepted: ServiceControlAccept::STOP | ServiceControlAccept::SHUTDOWN,
        exit_code: ServiceExitCode::Win32(0),
        checkpoint: 0,
        wait_hint: Duration::default(),
        process_id: None,
    })?;
    
    match staging_validation_and_takeover(&from_version, &to_version, &old_service, primary_binary) {
        Ok(_) => {
            log("Staging service completed successfully");
        }
        Err(e) => {
            log(&format!("Staging service failed: {}", e));
            send_upgrade_event(&from_version, &to_version, UpgradeStatus::Failed, Some(e.clone()));
            cleanup_staging_artifacts();
        }
    }
    
    status_handle.set_service_status(ServiceStatus {
        service_type: ServiceType::OWN_PROCESS,
        current_state: ServiceState::Stopped,
        controls_accepted: ServiceControlAccept::empty(),
        exit_code: ServiceExitCode::Win32(0),
        checkpoint: 0,
        wait_hint: Duration::default(),
        process_id: None,
    })?;
    
    let manager = ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT)?;
    if let Ok(staging_service) = manager.open_service(STAGING_SERVICE_NAME, ServiceAccess::DELETE) {
        let _ = staging_service.delete();
    }
    
    Ok(())
}