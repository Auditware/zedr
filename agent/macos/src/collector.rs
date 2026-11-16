use std::ffi::{c_char, CStr};
use std::ptr;

pub fn run() {
    println!("\n=== Userspace Process Monitor ===");
    
    match enumerate_processes() {
        Ok(processes) => {
            println!("Sample processes (top 10):");
            for (i, process) in processes.iter().take(10).enumerate() {
                println!("  {} - PID: {}, Name: {}", i + 1, process.pid, process.name);
            }
        }
        Err(e) => {
            println!("Error enumerating processes: {}", e);
        }
    }
    
    println!("\nAgent running successfully");
}

#[derive(Debug)]
struct ProcessInfo {
    pid: i32,
    name: String,
}

#[repr(C)]
struct KinfoProc {
    kp_proc: ExternProc,
    kp_eproc: Eproc,
}

#[repr(C)]
struct ExternProc {
    p_un: PUn,
    p_vmspace: *mut libc::c_void,
    p_sigacts: *mut libc::c_void,
    p_flag: i32,
    p_stat: c_char,
    p_pid: i32,
    p_oppid: i32,
    p_dupfd: i32,
    p_user: *mut libc::c_void,
    p_file: *mut libc::c_void,
    p_ucred: *mut libc::c_void,
    p_child: *mut libc::c_void,
    p_sibling: *mut libc::c_void,
    p_group: *mut libc::c_void,
    p_pptr: *mut libc::c_void,
    p_session: *mut libc::c_void,
    p_bgpgrp: *mut libc::c_void,
    p_jobc: i16,
    p_tdev: u32,
    p_tpgrp: i32,
    p_tsess: *mut libc::c_void,
    p_wmesg: *const c_char,
    p_swtime: u32,
    p_slptime: u32,
    p_realtimer: libc::itimerval,
    p_rtime: libc::timeval,
    p_uticks: u64,
    p_sticks: u64,
    p_iticks: u64,
    p_traceflag: i32,
    p_tracep: *mut libc::c_void,
    p_siglist: i32,
    p_textvp: *mut libc::c_void,
    p_holdcnt: i32,
    p_sigmask: u32,
    p_sigignore: u32,
    p_sigcatch: u32,
    p_priority: u8,
    p_usrpri: u8,
    p_nice: c_char,
    p_comm: [c_char; 17],
    p_pgrp: *mut libc::c_void,
    p_addr: *mut libc::c_void,
    p_xstat: u16,
    p_acflag: u16,
    p_ru: *mut libc::c_void,
}

#[repr(C)]
union PUn {
    p_st1: std::mem::ManuallyDrop<PrunSt1>,
}

#[repr(C)]
#[derive(Copy, Clone)]
struct PrunSt1 {
    p_forw: *mut libc::c_void,
    p_back: *mut libc::c_void,
}

#[repr(C)]
struct Eproc {
    e_paddr: *mut libc::c_void,
    e_sess: *mut libc::c_void,
    e_pcred: Pcred,
    e_ucred: Ucred,
    e_vm: Vmspace,
    e_ppid: i32,
    e_pgid: i32,
    e_jobc: i16,
    e_tdev: u32,
    e_tpgid: i32,
    e_tsess: *mut libc::c_void,
    e_wmesg: [c_char; 8],
    e_xsize: i32,
    e_xrssize: i16,
    e_xccount: i16,
    e_xswrss: i16,
    e_flag: i32,
    e_login: [c_char; 12],
    e_spare: [i32; 4],
}

#[repr(C)]
struct Pcred {
    pc_lock: [c_char; 72],
    pc_ucred: *mut libc::c_void,
    p_ruid: u32,
    p_svuid: u32,
    p_rgid: u32,
    p_svgid: u32,
    p_refcnt: i32,
}

#[repr(C)]
struct Ucred {
    cr_ref: i32,
    cr_uid: u32,
    cr_ngroups: i16,
    cr_groups: [u32; 16],
}

#[repr(C)]
struct Vmspace {
    dummy: i32,
}

const CTL_KERN: i32 = 1;
const KERN_PROC: i32 = 14;
const KERN_PROC_ALL: i32 = 0;

extern "C" {
    fn sysctl(
        name: *const i32,
        namelen: u32,
        oldp: *mut libc::c_void,
        oldlenp: *mut libc::size_t,
        newp: *mut libc::c_void,
        newlen: libc::size_t,
    ) -> i32;
}

fn enumerate_processes() -> Result<Vec<ProcessInfo>, String> {
    let mut processes = Vec::new();
    
    unsafe {
        let mib = [CTL_KERN, KERN_PROC, KERN_PROC_ALL, 0];
        let mut size: libc::size_t = 0;
        
        if sysctl(
            mib.as_ptr(),
            4,
            ptr::null_mut(),
            &mut size,
            ptr::null_mut(),
            0,
        ) != 0 {
            return Err("Failed to get process list size".to_string());
        }
        
        if size == 0 {
            return Err("No processes found".to_string());
        }
        
        let mut buffer = vec![0u8; size];
        
        if sysctl(
            mib.as_ptr(),
            4,
            buffer.as_mut_ptr() as *mut libc::c_void,
            &mut size,
            ptr::null_mut(),
            0,
        ) != 0 {
            return Err("Failed to get process list".to_string());
        }
        
        let kinfo_size = std::mem::size_of::<KinfoProc>();
        let num_processes = size / kinfo_size;
        
        for i in 0..num_processes {
            let offset = i * kinfo_size;
            if offset + kinfo_size <= buffer.len() {
                let proc_ptr = buffer.as_ptr().add(offset) as *const KinfoProc;
                let proc_info = &*proc_ptr;
                
                let pid = proc_info.kp_proc.p_pid;
                let comm_ptr = proc_info.kp_proc.p_comm.as_ptr();
                let name = if !comm_ptr.is_null() {
                    CStr::from_ptr(comm_ptr)
                        .to_string_lossy()
                        .to_string()
                } else {
                    "unknown".to_string()
                };
                
                if pid > 0 {
                    processes.push(ProcessInfo { pid, name });
                }
            }
        }
    }
    
    if processes.is_empty() {
        Err("No valid processes found".to_string())
    } else {
        processes.sort_by_key(|p| p.pid);
        Ok(processes)
    }
}
