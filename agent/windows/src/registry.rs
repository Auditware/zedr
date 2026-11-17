use std::env;
use std::io::{self, ErrorKind};

use winreg::enums::{HKEY_LOCAL_MACHINE, HKEY_USERS, KEY_READ};
use winreg::RegKey;
use zedr_shared::windows_text::{self, clip};

pub const MAX_NAME_BYTES: usize = 256;
pub const MAX_COMMAND_BYTES: usize = 4096;
const MAX_HIVES: usize = 256;
const PROFILE_LIST: &str = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList";

pub fn machine() -> RegKey {
    RegKey::predef(HKEY_LOCAL_MACHINE)
}

/// Opens a key for reading. A key that does not exist is `None`, as that is the normal state of most of the places looked at
pub fn open(root: &RegKey, path: &str) -> io::Result<Option<RegKey>> {
    match root.open_subkey_with_flags(path, KEY_READ) {
        Ok(key) => Ok(Some(key)),
        Err(e) if e.kind() == ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e),
    }
}

pub fn text(key: &RegKey, name: &str) -> Option<String> {
    key.get_value::<String, _>(name).ok()
}

pub fn number(key: &RegKey, name: &str) -> Option<u32> {
    key.get_value::<u32, _>(name).ok()
}

pub fn subkeys(key: &RegKey, limit: usize) -> Vec<String> {
    key.enum_keys().map_while(Result::ok).take(limit).collect()
}

pub fn is_absent(error: &io::Error) -> bool {
    error.kind() == ErrorKind::NotFound
}

/// The variables of a session. A service that reads another user's registry or folders has to expand that user's `%APPDATA%` and the
/// like to that user's profile, not to its own, so those are answered from the profile and the rest from the system
pub struct Environment {
    profile: Option<String>,
}

impl Environment {
    pub fn system() -> Self {
        Self { profile: None }
    }

    pub fn of_profile(directory: &str) -> Self {
        Self { profile: Some(directory.to_string()) }
    }

    pub fn get(&self, name: &str) -> Option<String> {
        self.profile.as_deref().and_then(|profile| windows_text::user_variable(profile, name)).or_else(|| env::var(name).ok())
    }

    pub fn expand(&self, text: &str) -> String {
        windows_text::expand_variables(text, &|name| self.get(name))
    }

    pub fn normalize(&self, command: &str) -> String {
        clip(&windows_text::normalize_command(command, &|name| self.get(name)), MAX_COMMAND_BYTES).to_string()
    }

    pub fn run_value(&self, command: &str) -> String {
        clip(&windows_text::run_value_command(command, &|name| self.get(name)), MAX_COMMAND_BYTES).to_string()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Profile {
    pub sid: String,
    pub name: String,
    pub directory: String,
}

/// The accounts that have a profile, from the list Windows keeps, whether their registry hive is loaded or not
pub fn profiles() -> Vec<Profile> {
    let Ok(Some(list)) = open(&machine(), PROFILE_LIST) else {
        return Vec::new();
    };
    let system = Environment::system();

    subkeys(&list, MAX_HIVES)
        .into_iter()
        .filter_map(|sid| {
            let directory = system.expand(&text(&open(&list, &sid).ok()??, "ProfileImagePath")?);
            let name = clip(&windows_text::account_name(&sid, Some(&directory)), MAX_NAME_BYTES).to_string();
            Some(Profile { sid, name, directory })
        })
        .collect()
}

impl Profile {
    pub fn environment(&self) -> Environment {
        if self.directory.is_empty() {
            Environment::system()
        } else {
            Environment::of_profile(&self.directory)
        }
    }
}

pub struct Hive {
    pub profile: Profile,
    pub key: RegKey,
}

/// The loaded user hives. `.DEFAULT` is the hive of SYSTEM again and `_Classes` is the part of a user's that holds file associations,
/// neither of which is read as a hive of its own. A user who is not signed in has no hive loaded, and is not read
pub fn user_hives(profiles: &[Profile]) -> Vec<Hive> {
    let users = RegKey::predef(HKEY_USERS);

    subkeys(&users, MAX_HIVES)
        .into_iter()
        .filter(|sid| sid != ".DEFAULT" && !sid.ends_with("_Classes"))
        .filter_map(|sid| {
            let key = users.open_subkey_with_flags(&sid, KEY_READ).ok()?;
            let profile = profiles.iter().find(|profile| profile.sid == sid).cloned().unwrap_or_else(|| Profile {
                name: clip(&windows_text::account_name(&sid, None), MAX_NAME_BYTES).to_string(),
                directory: String::new(),
                sid,
            });
            Some(Hive { profile, key })
        })
        .collect()
}
