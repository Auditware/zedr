use winreg::RegKey;
use zedr_shared::sensor::PackageItem;
use zedr_shared::windows_text::clip;
use zedr_shared::PackageManager;

use crate::registry::{self, MAX_NAME_BYTES};

const MAX_PACKAGES: usize = 16_384;
const MAX_KEYS_PER_VIEW: usize = 8_192;

const UNINSTALL: &str = r"Microsoft\Windows\CurrentVersion\Uninstall";

const NATIVE: &str = if cfg!(target_arch = "aarch64") { "arm64" } else { "x64" };
const EMULATED: &str = "x86";

fn programs(root: &RegKey, base: &str, wow: bool, architecture: &str, found: &mut Vec<PackageItem>) {
    let relative = if wow { format!(r"{}\Wow6432Node\{}", base, UNINSTALL) } else { format!(r"{}\{}", base, UNINSTALL) };
    let Ok(Some(uninstall)) = registry::open(root, &relative) else {
        return;
    };

    for name in registry::subkeys(&uninstall, MAX_KEYS_PER_VIEW) {
        let Ok(Some(key)) = registry::open(&uninstall, &name) else {
            continue;
        };
        let Some(display_name) = registry::text(&key, "DisplayName").map(|text| text.trim().to_string()).filter(|text| !text.is_empty()) else {
            continue;
        };

        found.push(PackageItem {
            manager: PackageManager::WindowsInstalled,
            name: clip(&display_name, MAX_NAME_BYTES).to_string(),
            version: clip(registry::text(&key, "DisplayVersion").unwrap_or_default().trim(), MAX_NAME_BYTES).to_string(),
            architecture: architecture.to_string(),
        });
    }
}

/// The programs Windows lists as installed, for the machine in both registry views and for each signed in user. Two entries with one
/// name and architecture count as one, as the inventory knows a program by those, and the first in a fixed order is kept so that
/// the version reported does not flip between scans
pub fn scan() -> Result<Vec<PackageItem>, String> {
    let machine = registry::machine();
    if registry::open(&machine, &format!(r"SOFTWARE\{}", UNINSTALL)).map_err(|e| format!("Failed to read the installed programs: {}", e))?.is_none() {
        return Err("The list of installed programs is missing".to_string());
    }

    let mut found = Vec::new();
    programs(&machine, "SOFTWARE", false, NATIVE, &mut found);
    programs(&machine, "SOFTWARE", true, EMULATED, &mut found);
    for hive in registry::user_hives(&registry::profiles()) {
        programs(&hive.key, "Software", false, NATIVE, &mut found);
        programs(&hive.key, "Software", true, EMULATED, &mut found);
    }

    found.sort_by(|a, b| (&a.name, &a.architecture, &a.version).cmp(&(&b.name, &b.architecture, &b.version)));
    found.truncate(MAX_PACKAGES);
    Ok(found)
}
