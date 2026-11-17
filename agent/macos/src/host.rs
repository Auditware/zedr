use std::fs;
use std::io::ErrorKind;
use std::os::unix::fs::{DirBuilderExt, MetadataExt, PermissionsExt};
use std::path::Path;

use zedr_shared::link::HostDescription;

use crate::kernel;

pub const STATE_DIR: &str = "/Library/Application Support/zedr";

const OWNER_ONLY: u32 = 0o700;

pub fn own_uid() -> u32 {
    kernel::effective_uid()
}

pub fn ensure_private_dir(path: &Path) -> Result<(), String> {
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(e) if e.kind() == ErrorKind::NotFound => {
            return fs::DirBuilder::new().recursive(true).mode(OWNER_ONLY).create(path).map_err(|e| format!("Failed to create {}: {}", path.display(), e));
        }
        Err(e) => return Err(format!("Failed to inspect {}: {}", path.display(), e)),
    };

    if !metadata.is_dir() {
        return Err(format!("{} is not a directory", path.display()));
    }

    let uid = own_uid();
    if metadata.uid() != uid {
        return Err(format!("{} belongs to user {}, the agent runs as user {}", path.display(), metadata.uid(), uid));
    }

    if metadata.mode() & 0o777 != OWNER_ONLY {
        fs::set_permissions(path, fs::Permissions::from_mode(OWNER_ONLY)).map_err(|e| format!("Failed to restrict {}: {}", path.display(), e))?;
    }

    Ok(())
}

pub fn os_version() -> String {
    match (kernel::system_text(c"kern.osproductversion"), kernel::system_text(c"kern.osversion")) {
        (Some(version), Some(build)) => format!("macOS {} ({})", version, build),
        (Some(version), None) => format!("macOS {}", version),
        (None, Some(build)) => format!("macOS ({})", build),
        (None, None) => "macOS".to_string(),
    }
}

pub fn describe() -> HostDescription {
    HostDescription {
        hostname: kernel::hostname().unwrap_or_else(|| "unknown".to_string()),
        os_version: os_version(),
        agent_version: env!("CARGO_PKG_VERSION").to_string(),
    }
}
