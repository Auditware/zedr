use std::ffi::{c_char, c_int, c_void, CStr};
use std::io;
use std::mem::{size_of, MaybeUninit};
use std::ptr;

use libc::{proc_bsdinfo, proc_fdinfo};

const PIDS_GROWN_BETWEEN_CALLS: usize = 64;
const DESCRIPTORS_GROWN_BETWEEN_CALLS: usize = 16;
const LIST_ATTEMPTS: usize = 4;
const MAX_USER_RECORD_BYTES: usize = 16 * 1024;

/// `PROC_PIDFDSOCKETINFO` from <sys/proc_info.h>, which libc does not name
const PROC_PIDFDSOCKETINFO: c_int = 3;

/// Size of `struct socket_fdinfo` from <sys/proc_info.h>, measured with the SDK on arm64 and x86_64 alike
pub const SOCKET_FDINFO_BYTES: usize = 792;

const _: () = assert!(size_of::<proc_bsdinfo>() == 136, "struct proc_bsdinfo of the SDK is 136 bytes");
const _: () = assert!(size_of::<proc_fdinfo>() == 8, "struct proc_fdinfo of the SDK is 8 bytes");

/// The bytes of one `struct socket_fdinfo`, aligned as the kernel's 64-bit fields want them
#[repr(C, align(8))]
pub struct SocketFdInfo(pub [u8; SOCKET_FDINFO_BYTES]);

fn as_pid(pid: u32) -> Option<c_int> {
    c_int::try_from(pid).ok()
}

/// Every process id the kernel knows, the kernel task included
pub fn all_pids() -> io::Result<Vec<u32>> {
    // SAFETY: a null buffer of size zero only asks for the number of processes, nothing is written
    let counted = unsafe { libc::proc_listallpids(ptr::null_mut(), 0) };
    if counted <= 0 {
        return Err(io::Error::last_os_error());
    }

    let mut capacity = counted as usize + PIDS_GROWN_BETWEEN_CALLS;
    for _ in 0..LIST_ATTEMPTS {
        let mut pids: Vec<c_int> = vec![0; capacity];
        let bytes = c_int::try_from(capacity * size_of::<c_int>()).map_err(|_| io::Error::other("too many processes"))?;
        // SAFETY: the buffer holds `capacity` ints and its size in bytes is passed, the kernel writes no more than that
        let listed = unsafe { libc::proc_listallpids(pids.as_mut_ptr().cast(), bytes) };
        if listed < 0 {
            return Err(io::Error::last_os_error());
        }
        if (listed as usize) < capacity {
            pids.truncate(listed as usize);
            return Ok(pids.into_iter().filter_map(|pid| u32::try_from(pid).ok()).collect());
        }
        capacity *= 2;
    }

    Err(io::Error::other("the process list kept growing while it was read"))
}

pub fn bsd_info(pid: u32) -> Option<proc_bsdinfo> {
    let mut info = MaybeUninit::<proc_bsdinfo>::zeroed();
    // SAFETY: the buffer is one proc_bsdinfo and its exact size is passed, the kernel writes no more than that
    let written = unsafe { libc::proc_pidinfo(as_pid(pid)?, libc::PROC_PIDTBSDINFO, 0, info.as_mut_ptr().cast(), size_of::<proc_bsdinfo>() as c_int) };
    // SAFETY: proc_bsdinfo is plain integers, any bytes are a valid value, and the kernel filled all of them
    (written == size_of::<proc_bsdinfo>() as c_int).then(|| unsafe { info.assume_init() })
}

pub fn executable_path(pid: u32) -> Option<String> {
    let mut path = [0u8; libc::PROC_PIDPATHINFO_MAXSIZE as usize];
    // SAFETY: the buffer and the size passed are the same array, the kernel writes no more than that
    let length = unsafe { libc::proc_pidpath(as_pid(pid)?, path.as_mut_ptr().cast(), path.len() as u32) };
    if length <= 0 {
        return None;
    }
    let path = &path[..(length as usize).min(path.len())];
    let path = path.split(|byte| *byte == 0).next().unwrap_or(path);
    Some(String::from_utf8_lossy(path).into_owned())
}

fn sysctl(mib: &mut [c_int], buffer: &mut [u8]) -> Option<usize> {
    let mut size = buffer.len();
    // SAFETY: the name is the slice passed with its length, the buffer is written up to `size` bytes and `size` is set to what was written
    let status = unsafe { libc::sysctl(mib.as_mut_ptr(), mib.len() as u32, buffer.as_mut_ptr().cast(), &mut size, ptr::null_mut(), 0) };
    (status == 0).then_some(size.min(buffer.len()))
}

/// Largest argument area a process can have, a buffer of this size always holds `KERN_PROCARGS2` whole
pub fn argument_max() -> Option<usize> {
    let mut value = [0u8; size_of::<c_int>()];
    let written = sysctl(&mut [libc::CTL_KERN, libc::KERN_ARGMAX], &mut value)?;
    let max = c_int::from_ne_bytes(value);
    (written == value.len() && max > 0).then_some(max as usize)
}

/// The argument count, executable path, arguments and environment of a process, as `KERN_PROCARGS2` lays them out
pub fn process_arguments(pid: u32, buffer: &mut [u8]) -> Option<&[u8]> {
    let written = sysctl(&mut [libc::CTL_KERN, libc::KERN_PROCARGS2, as_pid(pid)?], buffer)?;
    Some(&buffer[..written])
}

pub fn system_text(name: &CStr) -> Option<String> {
    let mut buffer = [0u8; 256];
    let mut size = buffer.len();
    // SAFETY: the name is NUL terminated, the buffer is written up to `size` bytes and `size` is set to what was written
    let status = unsafe { libc::sysctlbyname(name.as_ptr(), buffer.as_mut_ptr().cast(), &mut size, ptr::null_mut(), 0) };
    if status != 0 {
        return None;
    }
    let text = &buffer[..size.min(buffer.len())];
    let text = text.split(|byte| *byte == 0).next().unwrap_or(text);
    let text = String::from_utf8_lossy(text).trim().to_string();
    (!text.is_empty()).then_some(text)
}

pub fn hostname() -> Option<String> {
    let mut name = [0 as c_char; 256];
    // SAFETY: the buffer and the length passed are the same array
    if unsafe { libc::gethostname(name.as_mut_ptr(), name.len()) } != 0 {
        return None;
    }
    // gethostname does not terminate a name that fills the buffer
    name[name.len() - 1] = 0;
    // SAFETY: the array is NUL terminated by the line above
    let name = unsafe { CStr::from_ptr(name.as_ptr()) }.to_string_lossy().trim().to_string();
    (!name.is_empty()).then_some(name)
}

pub fn effective_uid() -> u32 {
    // SAFETY: geteuid has no arguments and cannot fail
    unsafe { libc::geteuid() }
}

/// Short name of the account with this user id, from the directory service the system uses
pub fn user_name(uid: u32) -> Option<String> {
    let mut record = MaybeUninit::<libc::passwd>::zeroed();
    let mut strings = vec![0 as c_char; MAX_USER_RECORD_BYTES];
    let mut found: *mut libc::passwd = ptr::null_mut();
    // SAFETY: every pointer is to memory of this frame that outlives the call, and the length passed is that of `strings`
    let status = unsafe { libc::getpwuid_r(uid, record.as_mut_ptr(), strings.as_mut_ptr(), strings.len(), &mut found) };
    if status != 0 || found.is_null() {
        return None;
    }
    // SAFETY: on success `found` points at `record`, whose pw_name points into `strings` and is NUL terminated
    let name = unsafe { (*found).pw_name };
    if name.is_null() {
        return None;
    }
    // SAFETY: checked for null above, terminated as said above
    let name = unsafe { CStr::from_ptr(name) }.to_string_lossy().into_owned();
    (!name.is_empty()).then_some(name)
}

/// The open file descriptors of a process, which needs the same user or root
pub fn descriptors(pid: u32) -> Option<Vec<proc_fdinfo>> {
    let pid = as_pid(pid)?;
    // SAFETY: a null buffer of size zero only asks how many bytes the list takes, nothing is written
    let needed = unsafe { libc::proc_pidinfo(pid, libc::PROC_PIDLISTFDS, 0, ptr::null_mut(), 0) };
    if needed <= 0 {
        return None;
    }

    let capacity = needed as usize / size_of::<proc_fdinfo>() + DESCRIPTORS_GROWN_BETWEEN_CALLS;
    let mut list = vec![proc_fdinfo { proc_fd: 0, proc_fdtype: 0 }; capacity];
    let bytes = c_int::try_from(capacity * size_of::<proc_fdinfo>()).ok()?;
    // SAFETY: the buffer holds `capacity` entries and its size in bytes is passed, the kernel writes no more than that
    let written = unsafe { libc::proc_pidinfo(pid, libc::PROC_PIDLISTFDS, 0, list.as_mut_ptr().cast::<c_void>(), bytes) };
    if written < 0 {
        return None;
    }
    list.truncate(written as usize / size_of::<proc_fdinfo>());
    Some(list)
}

pub fn socket_info(pid: u32, fd: i32) -> Option<SocketFdInfo> {
    let mut info = SocketFdInfo([0; SOCKET_FDINFO_BYTES]);
    // SAFETY: the buffer is one socket_fdinfo of the size the SDK gives it, and that size is passed
    let written = unsafe { libc::proc_pidfdinfo(as_pid(pid)?, fd, PROC_PIDFDSOCKETINFO, info.0.as_mut_ptr().cast(), SOCKET_FDINFO_BYTES as c_int) };
    (written == SOCKET_FDINFO_BYTES as c_int).then_some(info)
}
