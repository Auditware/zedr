use std::ffi::c_void;
use std::mem::{offset_of, size_of};
use std::slice;

use windows::Win32::NetworkManagement::IpHelper::{
    GetExtendedTcpTable, MIB_TCP6ROW_OWNER_PID, MIB_TCP6TABLE_OWNER_PID, MIB_TCPROW_OWNER_PID, MIB_TCPTABLE_OWNER_PID, MIB_TCP_STATE_ESTAB,
    MIB_TCP_STATE_LISTEN, TCP_TABLE_OWNER_PID_ALL,
};
use windows::Win32::Networking::WinSock::{AF_INET, AF_INET6};
use zedr_shared::windows_text::{self, TcpRow, TCP_ESTABLISHED, TCP_LISTEN};

const _: () = assert!(MIB_TCP_STATE_ESTAB.0 as u32 == TCP_ESTABLISHED);
const _: () = assert!(MIB_TCP_STATE_LISTEN.0 as u32 == TCP_LISTEN);

const NO_ERROR: u32 = 0;
const ERROR_INSUFFICIENT_BUFFER: u32 = 122;
/// The table can grow between the size query and the read, so the read is tried again with the size it then reports
const ATTEMPTS: usize = 5;
const SLACK_BYTES: usize = 4096;

/// The whole table is asked for, not only the connections, because a listening port is how an accepted connection is told from an
/// opened one
fn table(family: u32) -> Result<Vec<u64>, String> {
    let mut buffer: Vec<u64> = Vec::new();
    let mut size = 0u32;

    for _ in 0..ATTEMPTS {
        let target = if buffer.is_empty() { None } else { Some(buffer.as_mut_ptr().cast::<c_void>()) };
        // SAFETY: when a buffer is given, `size` is its length in bytes, which the call does not exceed, and `size` is writable
        let status = unsafe { GetExtendedTcpTable(target, &mut size, false, family, TCP_TABLE_OWNER_PID_ALL, 0) };
        match status {
            NO_ERROR => return Ok(buffer),
            ERROR_INSUFFICIENT_BUFFER => {
                buffer = vec![0u64; (size as usize + SLACK_BYTES).div_ceil(8)];
                size = (buffer.len() * 8) as u32;
            }
            other => return Err(format!("GetExtendedTcpTable failed with {}", other)),
        }
    }

    Err("The TCP table kept changing size".to_string())
}

/// # Safety
/// The buffer must hold a table the system filled in: a count of rows as a u32 at the start, and the rows from `offset` on
unsafe fn rows<T>(buffer: &[u64], offset: usize) -> Result<&[T], String> {
    let bytes = buffer.len() * 8;
    if bytes < size_of::<u32>() {
        return Err("The TCP table is empty".to_string());
    }

    let count = *buffer.as_ptr().cast::<u32>() as usize;
    match count.checked_mul(size_of::<T>()).and_then(|rows| rows.checked_add(offset)) {
        Some(end) if end <= bytes => Ok(slice::from_raw_parts(buffer.as_ptr().cast::<u8>().add(offset).cast::<T>(), count)),
        _ => Err("The TCP table reports more rows than it holds".to_string()),
    }
}

fn read_v4() -> Result<Vec<TcpRow>, String> {
    let buffer = table(u32::from(AF_INET.0))?;
    // SAFETY: the buffer was filled by GetExtendedTcpTable for the IPv4 owner table, and its alignment is that of the row
    let rows = unsafe { rows::<MIB_TCPROW_OWNER_PID>(&buffer, offset_of!(MIB_TCPTABLE_OWNER_PID, table)) }?;
    Ok(rows
        .iter()
        .map(|row| TcpRow {
            pid: row.dwOwningPid,
            state: row.dwState,
            local: windows_text::tcp4_address(row.dwLocalAddr, row.dwLocalPort),
            remote: windows_text::tcp4_address(row.dwRemoteAddr, row.dwRemotePort),
        })
        .collect())
}

fn read_v6() -> Result<Vec<TcpRow>, String> {
    let buffer = table(u32::from(AF_INET6.0))?;
    // SAFETY: the buffer was filled by GetExtendedTcpTable for the IPv6 owner table, and its alignment is that of the row
    let rows = unsafe { rows::<MIB_TCP6ROW_OWNER_PID>(&buffer, offset_of!(MIB_TCP6TABLE_OWNER_PID, table)) }?;
    Ok(rows
        .iter()
        .map(|row| TcpRow {
            pid: row.dwOwningPid,
            state: row.dwState,
            local: windows_text::tcp6_address(row.ucLocalAddr, row.dwLocalPort),
            remote: windows_text::tcp6_address(row.ucRemoteAddr, row.dwRemotePort),
        })
        .collect())
}

/// The outbound connections of both address families. One family failing leaves the other, and only both failing is an error
pub fn outbound() -> Result<Vec<TcpRow>, String> {
    let (v4, v6) = (read_v4(), read_v6());
    let rows = match (v4, v6) {
        (Ok(mut v4), Ok(v6)) => {
            v4.extend(v6);
            v4
        }
        (Ok(rows), Err(_)) | (Err(_), Ok(rows)) => rows,
        (Err(e4), Err(e6)) => return Err(format!("IPv4: {}; IPv6: {}", e4, e6)),
    };

    Ok(windows_text::outbound(rows))
}
