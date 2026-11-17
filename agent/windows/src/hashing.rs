use std::collections::HashMap;
use std::fs::{self, File};
use std::io::{self, Read};
use std::path::{Path, PathBuf};
use std::time::SystemTime;

use sha2::{Digest, Sha256};

/// Larger files are hashed by their first bytes, which keeps a scan of every driver and service from reading gigabytes
const MAX_HASHED_BYTES: u64 = 32 * 1024 * 1024;

struct Known {
    size: u64,
    modified: Option<SystemTime>,
    hash: String,
    scan: u64,
}

/// Hashes of the files an inventory scan names. Most of those files do not change between scans, so a file is read again only
/// when its size or modification time is not what it was
#[derive(Default)]
pub struct HashCache {
    known: HashMap<PathBuf, Known>,
    scan: u64,
}

impl HashCache {
    pub fn begin_scan(&mut self) {
        self.scan += 1;
    }

    /// Forgets the files the scan that just ended did not name, so that the cache does not outgrow the machine
    pub fn end_scan(&mut self) {
        let scan = self.scan;
        self.known.retain(|_, known| known.scan == scan);
    }

    pub fn is_file(path: &Path) -> bool {
        fs::metadata(path).is_ok_and(|metadata| metadata.is_file())
    }

    pub fn hash(&mut self, path: &Path) -> Option<String> {
        let metadata = fs::metadata(path).ok().filter(|metadata| metadata.is_file())?;
        let (size, modified) = (metadata.len(), metadata.modified().ok());

        if let Some(known) = self.known.get_mut(path) {
            if known.size == size && known.modified == modified {
                known.scan = self.scan;
                return Some(known.hash.clone());
            }
        }

        let hash = digest(path).ok()?;
        self.known.insert(path.to_path_buf(), Known { size, modified, hash: hash.clone(), scan: self.scan });
        Some(hash)
    }
}

fn digest(path: &Path) -> io::Result<String> {
    let mut hasher = Sha256::new();
    io::copy(&mut File::open(path)?.take(MAX_HASHED_BYTES), &mut hasher)?;
    Ok(hex::encode(hasher.finalize()))
}

pub fn sha256_hex(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}
