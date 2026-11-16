use std::fs;
use std::io::ErrorKind;
use std::os::unix::fs::{DirBuilderExt, MetadataExt, PermissionsExt};
use std::path::Path;

use zedr_shared::link::HostDescription;

pub const STATE_DIR: &str = "/var/lib/zedr";

const OWNER_ONLY: u32 = 0o700;

pub fn own_uid() -> Result<u32, String> {
    fs::metadata("/proc/self")
        .map(|metadata| metadata.uid())
        .map_err(|e| format!("Failed to read the agent's own user id: {}", e))
}

pub fn ensure_private_dir(path: &Path) -> Result<(), String> {
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(e) if e.kind() == ErrorKind::NotFound => {
            return fs::DirBuilder::new()
                .recursive(true)
                .mode(OWNER_ONLY)
                .create(path)
                .map_err(|e| format!("Failed to create {}: {}", path.display(), e));
        }
        Err(e) => return Err(format!("Failed to inspect {}: {}", path.display(), e)),
    };

    if !metadata.is_dir() {
        return Err(format!("{} is not a directory", path.display()));
    }

    let uid = own_uid()?;
    if metadata.uid() != uid {
        return Err(format!("{} belongs to user {}, the agent runs as user {}", path.display(), metadata.uid(), uid));
    }

    if metadata.mode() & 0o777 != OWNER_ONLY {
        fs::set_permissions(path, fs::Permissions::from_mode(OWNER_ONLY))
            .map_err(|e| format!("Failed to restrict {}: {}", path.display(), e))?;
    }

    Ok(())
}

pub fn kernel_version() -> Option<String> {
    fs::read_to_string("/proc/sys/kernel/osrelease")
        .ok()
        .map(|release| release.trim().to_string())
}

fn hostname() -> String {
    match fs::read_to_string("/proc/sys/kernel/hostname") {
        Ok(name) if !name.trim().is_empty() => name.trim().to_string(),
        _ => "unknown".to_string(),
    }
}

pub fn distribution_name(os_release: &str) -> Option<String> {
    os_release.lines().find_map(|line| {
        let value = line.strip_prefix("PRETTY_NAME=")?;
        let value = value.trim().trim_matches('"').trim_matches('\'');
        if value.is_empty() {
            None
        } else {
            Some(value.to_string())
        }
    })
}

fn os_version() -> String {
    let distribution = fs::read_to_string("/etc/os-release")
        .ok()
        .and_then(|contents| distribution_name(&contents));

    match (distribution, kernel_version()) {
        (Some(distribution), Some(kernel)) => format!("{} (kernel {})", distribution, kernel),
        (Some(distribution), None) => distribution,
        (None, Some(kernel)) => format!("Linux (kernel {})", kernel),
        (None, None) => "Linux".to_string(),
    }
}

pub fn describe() -> HostDescription {
    HostDescription {
        hostname: hostname(),
        os_version: os_version(),
        agent_version: env!("CARGO_PKG_VERSION").to_string(),
    }
}
