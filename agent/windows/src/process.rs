use std::ffi::c_void;
use std::mem::size_of;
use std::slice;

use windows::core::{HRESULT, PWSTR};
use windows::Wdk::System::Threading::{NtQueryInformationProcess, ProcessCommandLineInformation};
use windows::Win32::Foundation::{
    CloseHandle, ERROR_NO_MORE_FILES, FILETIME, HANDLE, STATUS_BUFFER_OVERFLOW, STATUS_BUFFER_TOO_SMALL, STATUS_INFO_LENGTH_MISMATCH, UNICODE_STRING,
};
use windows::Win32::System::Diagnostics::ToolHelp::{CreateToolhelp32Snapshot, Process32FirstW, Process32NextW, PROCESSENTRY32W, TH32CS_SNAPPROCESS};
use windows::Win32::System::RemoteDesktop::ProcessIdToSessionId;
use windows::Win32::System::Threading::{GetProcessTimes, OpenProcess, QueryFullProcessImageNameW, PROCESS_NAME_WIN32, PROCESS_QUERY_LIMITED_INFORMATION};

const MAX_PROCESSES: usize = 65_536;
const SHORT_PATH_CHARS: usize = 1024;
/// The longest path Windows accepts, in UTF-16 units
const LONG_PATH_CHARS: usize = 32_768;
/// A command line holds at most 32,767 characters, so this holds the longest one with the header the kernel puts before it
const MAX_COMMAND_LINE_REPLY_BYTES: usize = 128 * 1024;

/// A handle that is closed when it goes out of scope
pub struct Handle(HANDLE);

impl Drop for Handle {
    fn drop(&mut self) {
        // SAFETY: the guard owns the handle and drops once, and a failed close leaves nothing to do in a destructor
        let _ = unsafe { CloseHandle(self.0) };
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entry {
    pub pid: u32,
    pub ppid: u32,
    pub name: String,
}

pub fn snapshot() -> Result<Vec<Entry>, String> {
    // SAFETY: the call takes no pointers, and its result is checked before the handle is wrapped
    let handle = Handle(unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) }.map_err(|e| format!("Failed to snapshot the processes: {}", e))?);

    let mut raw = PROCESSENTRY32W { dwSize: size_of::<PROCESSENTRY32W>() as u32, ..Default::default() };
    // SAFETY: the handle is a live snapshot and `raw` is a writable entry whose size field is set
    let mut step = unsafe { Process32FirstW(handle.0, &mut raw) };

    let mut entries = Vec::new();
    while step.is_ok() && entries.len() < MAX_PROCESSES {
        let length = raw.szExeFile.iter().position(|unit| *unit == 0).unwrap_or(raw.szExeFile.len());
        entries.push(Entry { pid: raw.th32ProcessID, ppid: raw.th32ParentProcessID, name: String::from_utf16_lossy(&raw.szExeFile[..length]) });
        // SAFETY: as for the first call
        step = unsafe { Process32NextW(handle.0, &mut raw) };
    }

    match step {
        Err(e) if e.code() != HRESULT::from_win32(ERROR_NO_MORE_FILES.0) => Err(format!("Failed to read the process snapshot: {}", e)),
        _ => Ok(entries),
    }
}

/// What can be read of a process once it is open. Opening needs only the limited query right, which protected and other users'
/// processes grant to a service running as SYSTEM but not to a user, so a field can be missing for a process that exists
pub struct Open {
    handle: Handle,
}

impl Open {
    pub fn pid(pid: u32) -> Option<Self> {
        // SAFETY: the call takes no pointers, and its result is checked before the handle is wrapped
        unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid) }.ok().map(|handle| Self { handle: Handle(handle) })
    }

    pub fn image_path(&self) -> Option<String> {
        for chars in [SHORT_PATH_CHARS, LONG_PATH_CHARS] {
            let mut buffer = vec![0u16; chars];
            let mut size = chars as u32;
            // SAFETY: the buffer holds `size` units, which the call is told, and it writes no more
            let result = unsafe { QueryFullProcessImageNameW(self.handle.0, PROCESS_NAME_WIN32, PWSTR(buffer.as_mut_ptr()), &mut size) };
            if result.is_ok() {
                return buffer.get(..size as usize).map(String::from_utf16_lossy);
            }
        }
        None
    }

    /// The creation time as a FILETIME, which with the pid names one process for as long as it runs, as a pid is reused
    pub fn started(&self) -> Option<u64> {
        let (mut created, mut exited, mut kernel, mut user) = (FILETIME::default(), FILETIME::default(), FILETIME::default(), FILETIME::default());
        // SAFETY: the four pointers are to writable FILETIME values that outlive the call
        unsafe { GetProcessTimes(self.handle.0, &mut created, &mut exited, &mut kernel, &mut user) }.ok()?;
        Some((u64::from(created.dwHighDateTime) << 32) | u64::from(created.dwLowDateTime))
    }

    pub fn command_line(&self) -> Option<String> {
        let mut needed = 0u32;
        // SAFETY: a null buffer of length zero is the documented way to ask for the size, and `needed` is writable
        let status = unsafe { NtQueryInformationProcess(self.handle.0, ProcessCommandLineInformation, std::ptr::null_mut(), 0, &mut needed) };
        if ![STATUS_INFO_LENGTH_MISMATCH, STATUS_BUFFER_OVERFLOW, STATUS_BUFFER_TOO_SMALL].contains(&status) {
            return None;
        }
        let bytes = needed as usize;
        if bytes < size_of::<UNICODE_STRING>() || bytes > MAX_COMMAND_LINE_REPLY_BYTES {
            return None;
        }

        // u64 units keep the buffer aligned for the pointer the header holds
        let mut buffer = vec![0u64; bytes.div_ceil(8)];
        let capacity = buffer.len() * 8;
        // SAFETY: the buffer has `capacity` writable bytes, which the call is told, and `needed` is writable
        let status = unsafe {
            NtQueryInformationProcess(self.handle.0, ProcessCommandLineInformation, buffer.as_mut_ptr().cast::<c_void>(), capacity as u32, &mut needed)
        };
        if status.is_err() {
            return None;
        }

        let base = buffer.as_ptr() as usize;
        // SAFETY: the buffer is aligned for and holds a full header, which the kernel filled in on success
        let header = unsafe { &*(buffer.as_ptr().cast::<UNICODE_STRING>()) };
        let text = header.Buffer.0 as usize;
        let length = usize::from(header.Length);

        // The kernel points the text into the same buffer, but a pointer it wrote is only used once it is shown to lie inside
        let inside = text >= base + size_of::<UNICODE_STRING>()
            && text.is_multiple_of(2)
            && length.is_multiple_of(2)
            && text.checked_add(length).is_some_and(|end| end <= base + capacity);
        if !inside {
            return None;
        }

        // SAFETY: the range was just shown to lie within the initialized buffer and to be aligned for u16
        let units = unsafe { slice::from_raw_parts(header.Buffer.0, length / 2) };
        Some(String::from_utf16_lossy(units))
    }
}

/// The terminal services session of a process. Services run in session 0, a user's programs in the session of that user
pub fn session_of(pid: u32) -> Option<u32> {
    let mut session = 0u32;
    // SAFETY: `session` is writable and outlives the call
    unsafe { ProcessIdToSessionId(pid, &mut session) }.ok()?;
    Some(session)
}
