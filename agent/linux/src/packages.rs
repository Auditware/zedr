use std::io::{BufRead, BufReader};
use std::path::Path;

use zedr_shared::sensor::PackageItem;
use zedr_shared::PackageManager;

use crate::files::{self, clip, Opened};

const DATABASES: [(PackageManager, &str); 2] = [(PackageManager::Dpkg, "/var/lib/dpkg/status"), (PackageManager::Apk, "/lib/apk/db/installed")];
const MAX_DATABASE_BYTES: u64 = 64 * 1024 * 1024;
const MAX_FIELD_BYTES: usize = 256;
const DPKG_STATES_WITHOUT_FILES: [&str; 2] = ["not-installed", "config-files"];

#[derive(Default)]
struct Entry {
    name: Option<String>,
    version: Option<String>,
    architecture: Option<String>,
    without_files: bool,
}

fn field(value: &str) -> Option<String> {
    Some(clip(value.trim(), MAX_FIELD_BYTES).to_string()).filter(|value| !value.is_empty())
}

impl Entry {
    fn read_dpkg(&mut self, line: &str) {
        if let Some(value) = line.strip_prefix("Package:") {
            self.name = field(value);
        } else if let Some(value) = line.strip_prefix("Version:") {
            self.version = field(value);
        } else if let Some(value) = line.strip_prefix("Architecture:") {
            self.architecture = field(value);
        } else if let Some(value) = line.strip_prefix("Status:") {
            self.without_files = value.split_whitespace().last().is_some_and(|state| DPKG_STATES_WITHOUT_FILES.contains(&state));
        }
    }

    fn read_apk(&mut self, line: &str) {
        if let Some(value) = line.strip_prefix("P:") {
            self.name = field(value);
        } else if let Some(value) = line.strip_prefix("V:") {
            self.version = field(value);
        } else if let Some(value) = line.strip_prefix("A:") {
            self.architecture = field(value);
        }
    }

    fn package(self, manager: PackageManager) -> Option<PackageItem> {
        if self.without_files {
            return None;
        }
        Some(PackageItem { manager, name: self.name?, version: self.version?, architecture: self.architecture.unwrap_or_default() })
    }
}

pub fn parse(mut database: impl BufRead, manager: PackageManager) -> Result<Vec<PackageItem>, String> {
    let mut packages = Vec::new();
    let mut entry = Entry::default();
    let mut line = Vec::new();

    loop {
        line.clear();
        let read = database.read_until(b'\n', &mut line).map_err(|e| e.to_string())?;
        let text = String::from_utf8_lossy(&line);
        let text = text.trim_end_matches(['\n', '\r']);

        if text.is_empty() {
            packages.extend(std::mem::take(&mut entry).package(manager));
            if read == 0 {
                return Ok(packages);
            }
            continue;
        }

        match manager {
            PackageManager::Dpkg => entry.read_dpkg(text),
            PackageManager::Apk => entry.read_apk(text),
        }
    }
}

pub fn scan(root: &Path) -> Result<Vec<PackageItem>, String> {
    let mut packages = Vec::new();

    for (manager, path) in DATABASES {
        match files::open(root, Path::new(path)) {
            Opened::File(file, metadata) if metadata.len() <= MAX_DATABASE_BYTES => {
                let listed = parse(BufReader::new(file), manager).map_err(|e| format!("Failed to read {}: {}", path, e))?;
                packages.extend(listed);
            }
            Opened::File(..) => return Err(format!("{} is larger than {} bytes and was not read", path, MAX_DATABASE_BYTES)),
            Opened::Unreadable => return Err(format!("{} cannot be read", path)),
            Opened::Missing => {}
        }
    }

    Ok(packages)
}
