use std::cmp::Ordering;
use std::ffi::OsString;
use std::io::Cursor;
use std::path::Path;

use plist::{Dictionary, Value};
use zedr_shared::sensor::PackageItem;
use zedr_shared::PackageManager;

use crate::files::{self, clip, Listing, Loaded, UserNames};

const MAX_PLIST_BYTES: u64 = 1024 * 1024;
const MAX_FIELD_BYTES: usize = 256;
const MACH_HEADER_BYTES: u64 = 4096;

/// Homebrew installs for the architecture of its prefix: /opt/homebrew on Apple silicon, /usr/local on Intel and under Rosetta
const HOMEBREW_PREFIXES: [(&str, &str); 2] = [("/opt/homebrew", "arm64"), ("/usr/local", "x86_64")];
const CASK_PREFIX: &str = "cask/";
const APPLICATION_FOLDERS: [&str; 2] = ["/Applications", "/Applications/Utilities"];
const APPLICATIONS_IN_HOME: &str = "Applications";
const BUNDLE_SUFFIX: &str = ".app";
const RECEIPTS: &str = "/var/db/receipts";
const RECEIPT_SUFFIX: &str = ".plist";

const MH_MAGIC: u32 = 0xfeed_face;
const MH_MAGIC_64: u32 = 0xfeed_facf;
const FAT_MAGIC: u32 = 0xcafe_babe;
const FAT_MAGIC_64: u32 = 0xcafe_babf;
const FAT_ARCH_BYTES: usize = 20;
const FAT_ARCH_64_BYTES: usize = 32;
const CPU_TYPES: [(u32, &str); 5] = [(0x0100_000c, "arm64"), (0x0100_0007, "x86_64"), (12, "arm"), (7, "i386"), (18, "ppc")];

pub fn machine_architecture() -> &'static str {
    match std::env::consts::ARCH {
        "aarch64" => "arm64",
        other => other,
    }
}

fn field(text: &str) -> String {
    clip(text.trim(), MAX_FIELD_BYTES).to_string()
}

/// Orders versions by their runs of digits as numbers and the rest as text, so 2.14.2 comes after 2.14.1_1 and 28.2 after 28.0.1
pub fn version_order(left: &str, right: &str) -> Ordering {
    fn runs(text: &str) -> Vec<&str> {
        let mut runs = Vec::new();
        let mut start = 0;
        let mut digits = None;
        for (index, character) in text.char_indices() {
            let digit = character.is_ascii_digit();
            if digits.is_some_and(|previous| previous != digit) {
                runs.push(&text[start..index]);
                start = index;
            }
            digits = Some(digit);
        }
        if start < text.len() {
            runs.push(&text[start..]);
        }
        runs
    }

    let (left, right) = (runs(left), runs(right));
    for (left, right) in left.iter().zip(&right) {
        let order = match (left.parse::<u128>(), right.parse::<u128>()) {
            (Ok(left), Ok(right)) => left.cmp(&right),
            _ => left.cmp(right),
        };
        if order != Ordering::Equal {
            return order;
        }
    }
    left.len().cmp(&right.len())
}

/// The architectures a Mach-O file holds code for, from the first bytes of it
pub fn mach_o_architectures(header: &[u8]) -> Vec<&'static str> {
    let word = |offset: usize, big_endian: bool| -> Option<u32> {
        let bytes: [u8; 4] = header.get(offset..offset + 4)?.try_into().ok()?;
        Some(if big_endian { u32::from_be_bytes(bytes) } else { u32::from_le_bytes(bytes) })
    };
    let name = |cpu_type: u32| CPU_TYPES.iter().find(|(known, _)| *known == cpu_type).map(|(_, name)| *name);

    let mut architectures: Vec<&'static str> = match (word(0, true), word(0, false)) {
        (Some(FAT_MAGIC | FAT_MAGIC_64), _) => {
            let entry_bytes = if word(0, true) == Some(FAT_MAGIC) { FAT_ARCH_BYTES } else { FAT_ARCH_64_BYTES };
            let count = word(4, true).unwrap_or(0) as usize;
            (0..count.min(header.len() / entry_bytes)).filter_map(|index| word(8 + index * entry_bytes, true)).filter_map(name).collect()
        }
        (Some(MH_MAGIC | MH_MAGIC_64), _) => word(4, true).and_then(name).into_iter().collect(),
        (_, Some(MH_MAGIC | MH_MAGIC_64)) => word(4, false).and_then(name).into_iter().collect(),
        _ => Vec::new(),
    };
    architectures.sort_unstable();
    architectures.dedup();
    architectures
}

fn dictionary(bytes: &[u8]) -> Option<Dictionary> {
    Value::from_reader(Cursor::new(bytes)).ok()?.into_dictionary()
}

fn text<'a>(dictionary: &'a Dictionary, key: &str) -> Option<&'a str> {
    dictionary.get(key).and_then(Value::as_string).filter(|value| !value.trim().is_empty())
}

/// Names in a folder of the system, an error when the folder exists and cannot be read, because what it lists would look removed
fn names(root: &Path, directory: &Path) -> Result<Vec<OsString>, String> {
    match files::list(root, directory) {
        Listing::Entries(names) => Ok(names),
        Listing::Missing => Ok(Vec::new()),
        Listing::Unreadable => Err(format!("{} cannot be read", directory.display())),
    }
}

fn homebrew(root: &Path, folder: &Path, prefix: &str, architecture: &str) -> Result<Vec<PackageItem>, String> {
    let mut packages = Vec::new();
    for name in names(root, folder)? {
        let installed = folder.join(&name);
        if !files::is_directory(root, &installed) {
            continue;
        }
        let versions = names(root, &installed).unwrap_or_default();
        let version = versions.iter().map(|version| version.to_string_lossy()).max_by(|left, right| version_order(left, right)).unwrap_or_default();

        packages.push(PackageItem {
            manager: PackageManager::Homebrew,
            name: field(&format!("{}{}", prefix, name.to_string_lossy())),
            version: field(&version),
            architecture: architecture.to_string(),
        });
    }
    Ok(packages)
}

fn bundle(root: &Path, path: &Path, name: &str) -> PackageItem {
    let info = match files::load(root, &path.join("Contents/Info.plist"), MAX_PLIST_BYTES) {
        Loaded::File(bytes) => dictionary(&bytes),
        Loaded::Missing | Loaded::Unreadable => None,
    };
    let version = info.as_ref().and_then(|info| text(info, "CFBundleShortVersionString").or_else(|| text(info, "CFBundleVersion"))).unwrap_or_default();

    let architectures = info
        .as_ref()
        .and_then(|info| text(info, "CFBundleExecutable"))
        .filter(|executable| !executable.contains('/'))
        .and_then(|executable| files::head(root, &path.join("Contents/MacOS").join(executable), MACH_HEADER_BYTES))
        .map(|header| mach_o_architectures(&header))
        .filter(|architectures| !architectures.is_empty());

    PackageItem {
        manager: PackageManager::MacApp,
        name: field(name),
        version: field(version),
        architecture: architectures.map_or_else(|| machine_architecture().to_string(), |architectures| architectures.join(" ")),
    }
}

fn applications(root: &Path, folder: &Path) -> Result<Vec<PackageItem>, String> {
    let mut packages = Vec::new();
    for entry in names(root, folder)? {
        let entry = entry.to_string_lossy();
        let Some(name) = entry.strip_suffix(BUNDLE_SUFFIX).filter(|name| !name.is_empty()) else {
            continue;
        };
        let path = folder.join(entry.as_ref());
        if files::is_directory(root, &path) {
            packages.push(bundle(root, &path, name));
        }
    }
    Ok(packages)
}

fn receipts(root: &Path) -> Result<Vec<PackageItem>, String> {
    let folder = Path::new(RECEIPTS);
    let mut packages = Vec::new();
    for entry in names(root, folder)? {
        let entry = entry.to_string_lossy();
        let Some(stem) = entry.strip_suffix(RECEIPT_SUFFIX) else {
            continue;
        };
        let receipt = match files::load(root, &folder.join(entry.as_ref()), MAX_PLIST_BYTES) {
            Loaded::File(bytes) => dictionary(&bytes),
            Loaded::Missing => continue,
            Loaded::Unreadable => None,
        };

        let name = receipt.as_ref().and_then(|receipt| text(receipt, "PackageIdentifier")).unwrap_or(stem);
        let version = receipt.as_ref().and_then(|receipt| text(receipt, "PackageVersion")).unwrap_or_default();
        packages.push(PackageItem {
            manager: PackageManager::MacPkg,
            name: field(name),
            version: field(version),
            architecture: machine_architecture().to_string(),
        });
    }
    Ok(packages)
}

pub fn scan(root: &Path, user_names: UserNames) -> Result<Vec<PackageItem>, String> {
    let mut packages = Vec::new();

    for (prefix, architecture) in HOMEBREW_PREFIXES {
        packages.extend(homebrew(root, &Path::new(prefix).join("Cellar"), "", architecture)?);
        packages.extend(homebrew(root, &Path::new(prefix).join("Caskroom"), CASK_PREFIX, architecture)?);
    }

    for folder in APPLICATION_FOLDERS {
        packages.extend(applications(root, Path::new(folder))?);
    }
    for account in files::accounts(root, user_names) {
        packages.extend(applications(root, &account.home.join(APPLICATIONS_IN_HOME))?);
    }

    packages.extend(receipts(root)?);
    Ok(packages)
}
