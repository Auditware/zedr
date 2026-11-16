use std::collections::VecDeque;
use std::ffi::OsString;
use std::fs;
use std::io::{self, ErrorKind};
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Component, Path, PathBuf};

const MAX_LINKS: usize = 40;

fn names(path: &Path) -> VecDeque<OsString> {
    path.components()
        .filter_map(|component| match component {
            Component::Normal(name) => Some(name.to_os_string()),
            Component::ParentDir => Some(OsString::from("..")),
            _ => None,
        })
        .collect()
}

pub fn locate(root: &Path, path: &Path) -> Option<PathBuf> {
    let mut pending = names(path);
    let mut located = PathBuf::new();
    let mut links = 0;

    while let Some(name) = pending.pop_front() {
        if name == ".." {
            located.pop();
            continue;
        }

        match fs::read_link(root.join(&located).join(&name)) {
            Ok(target) => {
                links += 1;
                if links > MAX_LINKS {
                    return None;
                }
                if target.is_absolute() {
                    located = PathBuf::new();
                }
                for name in names(&target).into_iter().rev() {
                    pending.push_front(name);
                }
            }
            Err(_) => located.push(name),
        }
    }

    Some(root.join(located))
}

pub fn clip(text: &str, limit: usize) -> &str {
    let mut end = text.len().min(limit);
    while !text.is_char_boundary(end) {
        end -= 1;
    }
    &text[..end]
}

pub enum Opened {
    Missing,
    Unreadable,
    File(fs::File, fs::Metadata),
}

pub fn is_absent(error: &io::Error) -> bool {
    matches!(error.kind(), ErrorKind::NotFound | ErrorKind::NotADirectory)
}

pub fn open(root: &Path, path: &Path) -> Opened {
    let Some(location) = locate(root, path) else {
        return Opened::Unreadable;
    };

    match fs::metadata(&location) {
        Ok(metadata) if metadata.is_file() => {}
        Ok(_) => return Opened::Missing,
        Err(e) if is_absent(&e) => return Opened::Missing,
        Err(_) => return Opened::Unreadable,
    }

    let opened = fs::OpenOptions::new().read(true).custom_flags(libc::O_NONBLOCK).open(&location);
    match opened.and_then(|file| file.metadata().map(|metadata| (file, metadata))) {
        Ok((file, metadata)) if metadata.is_file() => Opened::File(file, metadata),
        Ok(_) => Opened::Missing,
        Err(e) if is_absent(&e) => Opened::Missing,
        Err(_) => Opened::Unreadable,
    }
}
