use std::ffi::OsString;
use std::fs;
use std::io::{self, ErrorKind, Read};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};

pub const USERS: &str = "/Users";
const SHARED_FOLDER: &str = "Shared";

pub type UserNames = fn(u32) -> Option<String>;

/// Where `path`, as the system names it, lies in the file system under `root`
pub fn inside(root: &Path, path: &Path) -> PathBuf {
    root.join(path.strip_prefix("/").unwrap_or(path))
}

pub fn clip(text: &str, limit: usize) -> &str {
    let mut end = text.len().min(limit);
    while !text.is_char_boundary(end) {
        end -= 1;
    }
    &text[..end]
}

pub fn file_name(path: &Path) -> String {
    match path.file_name() {
        Some(name) => name.to_string_lossy().into_owned(),
        None => path.to_string_lossy().into_owned(),
    }
}

fn is_absent(error: &io::Error) -> bool {
    matches!(error.kind(), ErrorKind::NotFound | ErrorKind::NotADirectory)
}

pub enum Loaded {
    Missing,
    Unreadable,
    File(Vec<u8>),
}

/// Opens a regular file only, without blocking, so a pipe or a device planted under a watched name cannot hold the agent up
fn open(location: &Path) -> Result<Option<fs::File>, io::Error> {
    match fs::metadata(location) {
        Ok(metadata) if metadata.is_file() => {}
        Ok(_) => return Ok(None),
        Err(e) if is_absent(&e) => return Ok(None),
        Err(e) => return Err(e),
    }

    let file = fs::OpenOptions::new().read(true).custom_flags(libc::O_NONBLOCK).open(location)?;
    Ok(file.metadata()?.is_file().then_some(file))
}

/// The whole file, or `Unreadable` when it is larger than `limit`
pub fn load(root: &Path, path: &Path, limit: u64) -> Loaded {
    let file = match open(&inside(root, path)) {
        Ok(Some(file)) => file,
        Ok(None) => return Loaded::Missing,
        Err(e) if is_absent(&e) => return Loaded::Missing,
        Err(_) => return Loaded::Unreadable,
    };

    let mut bytes = Vec::new();
    match file.take(limit + 1).read_to_end(&mut bytes) {
        Ok(read) if read as u64 <= limit => Loaded::File(bytes),
        _ => Loaded::Unreadable,
    }
}

/// The first `limit` bytes of a file
pub fn head(root: &Path, path: &Path, limit: u64) -> Option<Vec<u8>> {
    let file = open(&inside(root, path)).ok()??;
    let mut bytes = Vec::new();
    file.take(limit).read_to_end(&mut bytes).ok()?;
    Some(bytes)
}

pub enum Listing {
    Missing,
    Unreadable,
    Entries(Vec<OsString>),
}

/// The names in a directory, leaving out hidden ones, in order
pub fn list(root: &Path, directory: &Path) -> Listing {
    match fs::read_dir(inside(root, directory)) {
        Ok(entries) => {
            let mut names: Vec<OsString> = entries.flatten().map(|entry| entry.file_name()).filter(|name| !name.to_string_lossy().starts_with('.')).collect();
            names.sort();
            Listing::Entries(names)
        }
        Err(e) if is_absent(&e) => Listing::Missing,
        Err(_) => Listing::Unreadable,
    }
}

pub fn is_directory(root: &Path, path: &Path) -> bool {
    fs::metadata(inside(root, path)).is_ok_and(|metadata| metadata.is_dir())
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Account {
    pub name: String,
    pub home: PathBuf,
}

/// The accounts with a home folder in /Users, each named by the owner of its folder, or by the folder where that owner has no name
pub fn accounts(root: &Path, user_names: UserNames) -> Vec<Account> {
    let Listing::Entries(names) = list(root, Path::new(USERS)) else {
        return Vec::new();
    };

    names
        .into_iter()
        .filter(|name| name != SHARED_FOLDER)
        .filter_map(|name| {
            let home = Path::new(USERS).join(&name);
            let metadata = fs::metadata(inside(root, &home)).ok().filter(|metadata| metadata.is_dir())?;
            let name = user_names(metadata.uid()).unwrap_or_else(|| name.to_string_lossy().into_owned());
            Some(Account { name, home })
        })
        .collect()
}
