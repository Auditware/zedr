use std::ffi::c_void;
use windows::{
    core::PCSTR,
    Win32::Foundation::{CloseHandle, HANDLE, MAX_PATH},
    Win32::System::Diagnostics::ToolHelp::{CreateToolhelp32Snapshot, Process32First, Process32Next, PROCESSENTRY32, TH32CS_SNAPPROCESS},
    Win32::System::ProcessStatus::{GetModuleBaseNameA, GetProcessImageFileNameA},
};

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
    pid: u32,
    name: String,
}

fn enumerate_processes() -> Result<Vec<ProcessInfo>, String> {
    let mut processes = Vec::new();

    unsafe {
        let snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0).map_err(|e| format!("Failed to create snapshot: {}", e))?;

        if snapshot.is_invalid() {
            return Err("Invalid snapshot handle".to_string());
        }

        let mut process_entry = PROCESSENTRY32 { dwSize: std::mem::size_of::<PROCESSENTRY32>() as u32, ..Default::default() };

        if Process32First(snapshot, &mut process_entry).is_ok() {
            loop {
                let name = String::from_utf8_lossy(&process_entry.szExeFile).trim_end_matches('\0').to_string();

                processes.push(ProcessInfo { pid: process_entry.th32ProcessID, name });

                if Process32Next(snapshot, &mut process_entry).is_err() {
                    break;
                }
            }
        }

        CloseHandle(snapshot).ok();
    }

    if processes.is_empty() {
        Err("No processes found".to_string())
    } else {
        Ok(processes)
    }
}
