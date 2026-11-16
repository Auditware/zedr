use std::path::Path;
use std::sync::{mpsc, Arc};
use std::thread;

use signal_hook::consts::{SIGINT, SIGTERM};
use signal_hook::iterator::Signals;
use zedr_shared::link::{unix_now, ControlLink};
use zedr_shared::runtime::{self, Platform, Runtime};
use zedr_shared::{StopReason, SystemEvent, UpgradeCommand, UpgradeEvent, UpgradeStatus};

use crate::collector::ProcSource;
use crate::{host, systemd};

const UPGRADE_REPORT_TIMEOUT_SECS: u64 = 30;
const PROC_ROOT: &str = "/proc";

pub fn log(message: &str) {
    eprintln!("{}", message);
}

struct LinuxPlatform {
    link: Arc<ControlLink>,
}

impl Platform for LinuxPlatform {
    fn log(&self, message: &str) {
        log(message);
    }

    fn upgrade(&self, command: UpgradeCommand) {
        let error = match self.link.verify_upgrade_command(&command) {
            Ok(()) => "The Linux agent does not upgrade itself, run the installer again".to_string(),
            Err(e) => format!("Upgrade command verification failed: {}", e),
        };
        log(&error);

        let event = SystemEvent::Upgrade(UpgradeEvent {
            timestamp: unix_now(),
            from_version: env!("CARGO_PKG_VERSION").to_string(),
            to_version: command.target_version,
            status: UpgradeStatus::Failed,
            error: Some(error),
        });

        if let Err(e) = self.link.send_events(vec![event], UPGRADE_REPORT_TIMEOUT_SECS) {
            log(&format!("Failed to report the refused upgrade: {}", e));
        }
    }
}

pub fn stop_reason(signal: i32, system_is_stopping: Result<bool, String>) -> StopReason {
    if signal != SIGTERM {
        return StopReason::ServiceStop;
    }

    match system_is_stopping {
        Ok(true) => StopReason::SystemShutdown,
        Ok(false) => StopReason::ServiceStop,
        Err(e) => {
            log(&format!("Cannot tell a shutdown from a stop, reporting a stop: {}", e));
            StopReason::ServiceStop
        }
    }
}

fn watch_signals(stop: mpsc::Sender<StopReason>) -> Result<(), String> {
    let uid = host::own_uid()?;
    let mut signals = Signals::new([SIGTERM, SIGINT])
        .map_err(|e| format!("Failed to install signal handlers: {}", e))?;

    thread::spawn(move || {
        if let Some(signal) = signals.forever().next() {
            let system_is_stopping = systemd::system_is_stopping(Path::new(systemd::PRIVATE_SOCKET), uid);
            let _ = stop.send(stop_reason(signal, system_is_stopping));
        }
    });

    Ok(())
}

pub fn run() -> Result<(), String> {
    let state_dir = Path::new(host::STATE_DIR);
    host::ensure_private_dir(state_dir)?;

    let link = Arc::new(ControlLink::open_with_key_id(zedr_shared::get_server_url(), state_dir)?);
    let host = host::describe();

    log(&format!("zedr Linux agent v{} on {}", host.agent_version, host.os_version));
    log(&format!("Agent id {}, control server {}", link.agent_id(), link.server_url()));

    let (stop_tx, stop_rx) = mpsc::channel();
    watch_signals(stop_tx)?;

    let runtime = Arc::new(Runtime::new(Arc::clone(&link), LinuxPlatform { link }, host));
    runtime.start_sensor(ProcSource::new(Path::new(PROC_ROOT))?, runtime::sensor_intervals());

    match runtime.run_until_stopped(&stop_rx, runtime::heartbeat_interval()) {
        Some(reason) => {
            log(&format!("Stopping: {:?}", reason));
            runtime.notify_stopping(reason);
        }
        None => log("Signal watcher ended, stopping without a notice"),
    }

    Ok(())
}
