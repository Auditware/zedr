//! What the Windows agent has to parse or decide, kept free of any Windows call so that it is tested on every platform
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use quick_xml::events::Event;
use quick_xml::Reader;

const MAX_TASK_ACTIONS: usize = 64;
const MAX_TASK_DEPTH: usize = 64;
const MAX_ELEMENT_TEXT_BYTES: usize = 8192;

pub const TCP_LISTEN: u32 = 2;
pub const TCP_ESTABLISHED: u32 = 5;

const FILETIME_TICKS_PER_SECOND: u64 = 10_000_000;
const SECONDS_FROM_1601_TO_1970: u64 = 11_644_473_600;

pub fn clip(text: &str, limit: usize) -> &str {
    let mut end = text.len().min(limit);
    while !text.is_char_boundary(end) {
        end -= 1;
    }
    &text[..end]
}

/// FNV-1a, so that an identity derived from it means the same in every build, unlike the standard hasher whose algorithm may change
pub fn stable_hash(parts: &[&[u8]]) -> u64 {
    let mut hash: u64 = 0xcbf2_9ce4_8422_2325;
    for byte in parts.iter().flat_map(|part| part.iter()) {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
    }
    hash
}

/// Seconds since 1970 for a FILETIME, which counts 100 nanosecond ticks since 1601
pub fn filetime_to_unix(ticks: u64) -> Option<u64> {
    (ticks / FILETIME_TICKS_PER_SECOND).checked_sub(SECONDS_FROM_1601_TO_1970)
}

fn is_blank(character: char) -> bool {
    character == ' ' || character == '\t'
}

/// Splits a command line the way CommandLineToArgvW does. The program name follows its own rules: it ends at the closing quote,
/// or at the first blank when it is not quoted, and no backslash is special in it. In the arguments, backslashes only count before a quote,
/// where each pair gives one backslash and an odd one makes the quote literal, and inside quotes a doubled quote is one literal quote
pub fn split_command_line(line: &str) -> Vec<String> {
    let characters: Vec<char> = line.chars().collect();
    let length = characters.len();
    let mut at = 0;
    let mut arguments = Vec::new();

    while at < length && is_blank(characters[at]) {
        at += 1;
    }
    if at == length {
        return arguments;
    }

    let mut program = String::new();
    if characters[at] == '"' {
        at += 1;
        while at < length && characters[at] != '"' {
            program.push(characters[at]);
            at += 1;
        }
        at = (at + 1).min(length);
    } else {
        while at < length && !is_blank(characters[at]) {
            program.push(characters[at]);
            at += 1;
        }
    }
    arguments.push(program);

    loop {
        while at < length && is_blank(characters[at]) {
            at += 1;
        }
        if at == length {
            return arguments;
        }

        let mut argument = String::new();
        let mut quoted = false;
        while at < length {
            let character = characters[at];
            if character == '\\' {
                let mut backslashes = 0;
                while at < length && characters[at] == '\\' {
                    backslashes += 1;
                    at += 1;
                }
                if at < length && characters[at] == '"' {
                    argument.extend(std::iter::repeat_n('\\', backslashes / 2));
                    if backslashes % 2 == 1 {
                        argument.push('"');
                        at += 1;
                    }
                } else {
                    argument.extend(std::iter::repeat_n('\\', backslashes));
                }
            } else if character == '"' {
                if quoted && characters.get(at + 1) == Some(&'"') {
                    argument.push('"');
                    at += 2;
                } else {
                    quoted = !quoted;
                    at += 1;
                }
            } else if !quoted && is_blank(character) {
                break;
            } else {
                argument.push(character);
                at += 1;
            }
        }
        arguments.push(argument);
    }
}

fn strip_prefix_ignoring_case<'a>(text: &'a str, prefix: &str) -> Option<&'a str> {
    let head = text.get(..prefix.len())?;
    head.eq_ignore_ascii_case(prefix).then(|| &text[prefix.len()..])
}

/// Replaces `%NAME%` where the lookup knows the name. A name it does not know is left as written, as the shell leaves it
pub fn expand_variables(text: &str, lookup: &dyn Fn(&str) -> Option<String>) -> String {
    let mut expanded = String::with_capacity(text.len());
    let mut rest = text;

    while let Some(start) = rest.find('%') {
        expanded.push_str(&rest[..start]);
        let after = &rest[start + 1..];
        match after.find('%').and_then(|end| lookup(&after[..end]).filter(|_| end > 0).map(|value| (end, value))) {
            Some((end, value)) => {
                expanded.push_str(&value);
                rest = &after[end + 1..];
            }
            None => {
                expanded.push('%');
                rest = after;
            }
        }
    }

    expanded.push_str(rest);
    expanded
}

/// A command as the registry stores it, in the form the detection rules compare: no NT namespace prefix, the system root and the
/// variables written out. A driver can name its file as `\SystemRoot\...`, `\??\C:\...` or relative to the system root as `System32\...`
pub fn normalize_command(raw: &str, lookup: &dyn Fn(&str) -> Option<String>) -> String {
    let text = raw.trim();
    let text = strip_prefix_ignoring_case(text, r"\??\").unwrap_or(text);

    let rooted;
    let text = if let Some(rest) = strip_prefix_ignoring_case(text, r"\SystemRoot\") {
        rooted = format!(r"%SystemRoot%\{}", rest);
        rooted.as_str()
    } else if let Some(rest) = strip_prefix_ignoring_case(text, r"System32\") {
        rooted = format!(r"%SystemRoot%\System32\{}", rest);
        rooted.as_str()
    } else {
        text
    };

    expand_variables(text, lookup)
}

/// A Run or RunOnce value may start with `*` (also in safe mode) or `!` (delete the value only after the program has run)
pub fn run_value_command(raw: &str, lookup: &dyn Fn(&str) -> Option<String>) -> String {
    normalize_command(raw.trim_start().trim_start_matches(['*', '!']), lookup)
}

fn is_absolute_windows_path(path: &str) -> bool {
    let bytes = path.as_bytes();
    path.starts_with(r"\\") || (bytes.len() >= 3 && bytes[0].is_ascii_alphabetic() && bytes[1] == b':' && (bytes[2] == b'\\' || bytes[2] == b'/'))
}

fn existing_program(candidate: &str, is_file: &dyn Fn(&str) -> bool) -> Option<String> {
    if !is_absolute_windows_path(candidate) {
        return None;
    }
    if is_file(candidate) {
        return Some(candidate.to_string());
    }

    let name = candidate.rsplit(['\\', '/']).next().unwrap_or(candidate);
    if name.contains('.') {
        return None;
    }
    let with_extension = format!("{}.exe", candidate);
    is_file(&with_extension).then_some(with_extension)
}

/// The file a command line starts. An unquoted path may hold blanks, so, like CreateProcess, it is tried at each blank from the left,
/// with `.exe` added when the name has no extension. That is also how an unquoted service path ends up running a file nobody meant
pub fn command_target(command: &str, is_file: &dyn Fn(&str) -> bool) -> Option<String> {
    let command = command.trim();
    if let Some(quoted) = command.strip_prefix('"') {
        return existing_program(&quoted[..quoted.find('"')?], is_file);
    }

    command
        .char_indices()
        .filter(|(_, character)| is_blank(*character))
        .map(|(at, _)| at)
        .chain(std::iter::once(command.len()))
        .find_map(|end| existing_program(&command[..end], is_file))
}

/// The variables a user's own session defines that differ from the ones of the service that reads that user's registry hive
pub fn user_variable(profile: &str, name: &str) -> Option<String> {
    let profile = profile.trim_end_matches('\\');
    match name.to_ascii_uppercase().as_str() {
        "USERPROFILE" => Some(profile.to_string()),
        "APPDATA" => Some(format!(r"{}\AppData\Roaming", profile)),
        "LOCALAPPDATA" => Some(format!(r"{}\AppData\Local", profile)),
        "TEMP" | "TMP" => Some(format!(r"{}\AppData\Local\Temp", profile)),
        _ => None,
    }
}

/// A readable account name for a SID: the three built in service accounts by their SID, any other by the folder of its profile
pub fn account_name(sid: &str, profile: Option<&str>) -> String {
    match sid {
        "S-1-5-18" => "SYSTEM".to_string(),
        "S-1-5-19" => "LOCAL SERVICE".to_string(),
        "S-1-5-20" => "NETWORK SERVICE".to_string(),
        _ => match profile.and_then(|profile| profile.trim_end_matches('\\').rsplit('\\').next()).filter(|name| !name.is_empty()) {
            Some(name) => name.to_string(),
            None => sid.to_string(),
        },
    }
}

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct TaskAction {
    pub command: String,
    pub arguments: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Task {
    pub enabled: bool,
    pub principal: String,
    /// Only the actions that start a program. A task that shows a message or calls a COM handler has none
    pub actions: Vec<TaskAction>,
}

/// Task Scheduler writes its definitions as UTF-16 with a byte order mark, other tools leave them as UTF-8
fn decode_task(bytes: &[u8]) -> String {
    let utf16 = |bytes: &[u8], word: fn([u8; 2]) -> u16| {
        let units: Vec<u16> = bytes.chunks_exact(2).map(|pair| word([pair[0], pair[1]])).collect();
        String::from_utf16_lossy(&units)
    };

    match bytes {
        [0xFF, 0xFE, rest @ ..] => utf16(rest, u16::from_le_bytes),
        [0xFE, 0xFF, rest @ ..] => utf16(rest, u16::from_be_bytes),
        [0xEF, 0xBB, 0xBF, rest @ ..] => String::from_utf8_lossy(rest).into_owned(),
        _ => String::from_utf8_lossy(bytes).into_owned(),
    }
}

fn predefined_entity(name: &str) -> Option<char> {
    match name {
        "lt" => Some('<'),
        "gt" => Some('>'),
        "amp" => Some('&'),
        "quot" => Some('"'),
        "apos" => Some('\''),
        _ => None,
    }
}

fn append_text(text: &mut String, more: &str) {
    if text.len() < MAX_ELEMENT_TEXT_BYTES {
        text.push_str(clip(more, MAX_ELEMENT_TEXT_BYTES - text.len()));
    }
}

fn task_boolean(text: &str) -> bool {
    !matches!(text.trim().to_ascii_lowercase().as_str(), "false" | "0")
}

/// What a task definition runs and whether it is turned on. Only the element paths that mean something are read, so the Enabled of a
/// trigger does not count, and an entity that the document defines itself is never expanded
pub fn parse_task(bytes: &[u8]) -> Result<Task, String> {
    let text = decode_task(bytes);
    let mut reader = Reader::from_str(&text);
    let mut path: Vec<String> = Vec::new();
    let mut element_text = String::new();
    let mut task = Task { enabled: true, principal: String::new(), actions: Vec::new() };
    let mut is_task = false;

    let is_at = |path: &[String], expected: &[&str]| path.len() == expected.len() && path.iter().zip(expected).all(|(have, want)| have == want);

    loop {
        let event = reader.read_event().map_err(|e| format!("Not a readable task definition: {}", e))?;
        let closed = matches!(event, Event::Empty(_) | Event::End(_));

        match &event {
            Event::Start(tag) | Event::Empty(tag) => {
                if path.len() >= MAX_TASK_DEPTH {
                    return Err("The task definition is nested too deeply".to_string());
                }
                path.push(tag.local_name().as_ref().to_string());
                element_text.clear();
                is_task |= is_at(&path, &["Task"]);
                if is_at(&path, &["Task", "Actions", "Exec"]) && task.actions.len() < MAX_TASK_ACTIONS {
                    task.actions.push(TaskAction::default());
                }
            }
            Event::Text(content) => append_text(&mut element_text, &content.xml10_content()),
            Event::CData(content) => append_text(&mut element_text, &content.xml10_content()),
            Event::GeneralRef(reference) => {
                let resolved = match reference.resolve_char_ref() {
                    Ok(Some(character)) => Some(character),
                    Ok(None) => predefined_entity(&reference.xml10_content()),
                    Err(_) => None,
                };
                if let Some(character) = resolved {
                    append_text(&mut element_text, character.encode_utf8(&mut [0; 4]));
                }
            }
            Event::Eof => break,
            _ => {}
        }

        if closed {
            let value = element_text.trim().to_string();
            if is_at(&path, &["Task", "Settings", "Enabled"]) {
                task.enabled = task_boolean(&value);
            } else if (is_at(&path, &["Task", "Principals", "Principal", "UserId"]) || is_at(&path, &["Task", "Principals", "Principal", "GroupId"]))
                && task.principal.is_empty()
            {
                task.principal = value;
            } else if is_at(&path, &["Task", "Actions", "Exec", "Command"]) {
                if let Some(action) = task.actions.last_mut() {
                    action.command = value;
                }
            } else if is_at(&path, &["Task", "Actions", "Exec", "Arguments"]) {
                if let Some(action) = task.actions.last_mut() {
                    action.arguments = value;
                }
            }
            path.pop();
            element_text.clear();
        }
    }

    if is_task {
        Ok(task)
    } else {
        Err("The file is not a task definition".to_string())
    }
}

/// The command line of one action. A task stores the program and its arguments apart and does not quote the program, so a path with
/// blanks is quoted here to read as the one program it is
pub fn task_command(action: &TaskAction, lookup: &dyn Fn(&str) -> Option<String>) -> String {
    let program = expand_variables(&action.command, lookup);
    let program = if program.contains(is_blank) && !program.starts_with('"') { format!("\"{}\"", program) } else { program };
    let arguments = expand_variables(&action.arguments, lookup);

    match (program.is_empty(), arguments.is_empty()) {
        (_, true) => program,
        (true, false) => arguments,
        (false, false) => format!("{} {}", program, arguments),
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TcpRow {
    pub pid: u32,
    pub state: u32,
    pub local: SocketAddr,
    pub remote: SocketAddr,
}

/// The table stores the address bytes as they are on the wire, so reading them in memory order gives the address on any host
pub fn tcp4_address(address: u32, port: u32) -> SocketAddr {
    SocketAddr::new(IpAddr::V4(Ipv4Addr::from(address.to_ne_bytes())), tcp_port(port))
}

pub fn tcp6_address(address: [u8; 16], port: u32) -> SocketAddr {
    let v6 = Ipv6Addr::from(address);
    SocketAddr::new(v6.to_ipv4_mapped().map_or(IpAddr::V6(v6), IpAddr::V4), tcp_port(port))
}

/// The port sits in the low 16 bits of a 32 bit field, in network byte order
fn tcp_port(port: u32) -> u16 {
    u16::from_be((port & 0xFFFF) as u16)
}

/// The connections a process opened toward another host. The table has no inbound flag, so a connection whose local port some process
/// listens on counts as accepted, not opened, as in the Linux sensor. A connection to the machine itself is not reported either
pub fn outbound(rows: Vec<TcpRow>) -> Vec<TcpRow> {
    let listening: std::collections::HashSet<u16> = rows.iter().filter(|row| row.state == TCP_LISTEN).map(|row| row.local.port()).collect();

    rows.into_iter()
        .filter(|row| row.state == TCP_ESTABLISHED)
        .filter(|row| !listening.contains(&row.local.port()))
        .filter(|row| !row.remote.ip().is_loopback() && !row.remote.ip().is_unspecified())
        .collect()
}

/// Windows has no socket number to tell connections apart, so the identity is the owner and both ends. Two connections cannot share
/// them while both are open, and one that closes and is opened again by another process has another owner
pub fn socket_identity(row: &TcpRow) -> u64 {
    let end = |address: &SocketAddr| {
        let mut bytes = match address.ip() {
            IpAddr::V4(ip) => ip.octets().to_vec(),
            IpAddr::V6(ip) => ip.octets().to_vec(),
        };
        bytes.extend_from_slice(&address.port().to_be_bytes());
        bytes
    };

    stable_hash(&[&row.pid.to_be_bytes(), &end(&row.local), &end(&row.remote)]).max(1)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn environment(name: &str) -> Option<String> {
        match name.to_ascii_lowercase().as_str() {
            "systemroot" => Some(r"C:\Windows".to_string()),
            "programfiles" => Some(r"C:\Program Files".to_string()),
            "programdata" => Some(r"C:\ProgramData".to_string()),
            _ => None,
        }
    }

    fn arguments(line: &str) -> Vec<String> {
        split_command_line(line)
    }

    #[test]
    fn splits_the_documented_examples() {
        assert_eq!(arguments(r#"prog "abc" d e"#), ["prog", "abc", "d", "e"]);
        assert_eq!(arguments(r#"prog a\\\b d"e f"g h"#), [r"prog", r"a\\\b", "de fg", "h"]);
        assert_eq!(arguments(r#"prog a\\\"b c d"#), ["prog", r#"a\"b"#, "c", "d"]);
        assert_eq!(arguments(r#"prog a\\\\"b c" d e"#), ["prog", r"a\\b c", "d", "e"]);
    }

    #[test]
    fn keeps_an_empty_argument() {
        assert_eq!(arguments(r#"prog "" x "#), ["prog", "", "x"]);
        assert_eq!(arguments(r#"prog a "" """#), ["prog", "a", "", ""]);
    }

    #[test]
    fn a_doubled_quote_inside_quotes_is_one_quote() {
        assert_eq!(arguments(r#"prog "say ""hi"" now" end"#), ["prog", r#"say "hi" now"#, "end"]);
    }

    #[test]
    fn the_program_name_follows_its_own_rules() {
        assert_eq!(arguments(r#""C:\Program Files\app.exe" -x"#), [r"C:\Program Files\app.exe", "-x"]);
        assert_eq!(arguments(r"C:\tools\app.exe\ -x"), [r"C:\tools\app.exe\", "-x"]);
        assert_eq!(arguments(r#""C:\dir\" arg"#), [r"C:\dir\", "arg"]);
        assert_eq!(arguments("  prog\targ  "), ["prog", "arg"]);
    }

    #[test]
    fn a_blank_line_has_no_arguments() {
        assert!(arguments("").is_empty());
        assert!(arguments(" \t ").is_empty());
        assert_eq!(arguments(r#""""#), [""]);
    }

    #[test]
    fn clips_on_a_character_boundary() {
        assert_eq!(clip("abcdef", 3), "abc");
        assert_eq!(clip("aéb", 2), "a");
        assert_eq!(clip("ab", 10), "ab");
    }

    #[test]
    fn expands_known_variables_in_any_case() {
        assert_eq!(expand_variables(r"%SystemRoot%\System32\cmd.exe", &environment), r"C:\Windows\System32\cmd.exe");
        assert_eq!(expand_variables(r"%PROGRAMFILES%\a;%programdata%", &environment), r"C:\Program Files\a;C:\ProgramData");
    }

    #[test]
    fn leaves_unknown_variables_and_stray_percent_signs() {
        assert_eq!(expand_variables(r"%Nothing%\x", &environment), r"%Nothing%\x");
        assert_eq!(expand_variables(r"50% of %SystemRoot%", &environment), r"50% of C:\Windows");
        assert_eq!(expand_variables("100%", &environment), "100%");
        assert_eq!(expand_variables("%%", &environment), "%%");
    }

    #[test]
    fn normalizes_what_services_and_drivers_store() {
        assert_eq!(normalize_command(r#""C:\Program Files\svc\svc.exe" -k run"#, &environment), r#""C:\Program Files\svc\svc.exe" -k run"#);
        assert_eq!(normalize_command(r"\SystemRoot\System32\drivers\x.sys", &environment), r"C:\Windows\System32\drivers\x.sys");
        assert_eq!(normalize_command(r"\systemroot\system32\drivers\x.sys", &environment), r"C:\Windows\system32\drivers\x.sys");
        assert_eq!(normalize_command(r"\??\C:\Windows\system32\drivers\x.sys", &environment), r"C:\Windows\system32\drivers\x.sys");
        assert_eq!(normalize_command(r"System32\DRIVERS\x.sys", &environment), r"C:\Windows\System32\DRIVERS\x.sys");
        assert_eq!(normalize_command(r"%SystemRoot%\system32\svchost.exe -k netsvcs -p", &environment), r"C:\Windows\system32\svchost.exe -k netsvcs -p");
        assert_eq!(normalize_command("  C:\\a.exe  ", &environment), r"C:\a.exe");
    }

    #[test]
    fn a_run_value_may_carry_a_flag() {
        assert_eq!(run_value_command(r"*!%ProgramFiles%\a\a.exe /s", &environment), r"C:\Program Files\a\a.exe /s");
        assert_eq!(run_value_command(r#""C:\a b\a.exe""#, &environment), r#""C:\a b\a.exe""#);
    }

    fn files(existing: &'static [&'static str]) -> impl Fn(&str) -> bool {
        move |path| existing.contains(&path)
    }

    #[test]
    fn finds_the_program_of_a_quoted_command() {
        let is_file = files(&[r"C:\Program Files\a\a.exe"]);
        assert_eq!(command_target(r#""C:\Program Files\a\a.exe" /x"#, &is_file).as_deref(), Some(r"C:\Program Files\a\a.exe"));
        assert_eq!(command_target(r#""C:\Program Files\gone.exe" /x"#, &is_file), None);
        assert_eq!(command_target(r#""C:\unterminated"#, &is_file), None);
    }

    #[test]
    fn finds_the_program_of_an_unquoted_command_the_way_createprocess_does() {
        let is_file = files(&[r"C:\Program Files\a\a.exe", r"C:\Windows\system32\svchost.exe", r"C:\tools\run.exe"]);
        assert_eq!(command_target(r"C:\Program Files\a\a.exe /x", &is_file).as_deref(), Some(r"C:\Program Files\a\a.exe"));
        assert_eq!(command_target(r"C:\Windows\system32\svchost.exe -k netsvcs -p", &is_file).as_deref(), Some(r"C:\Windows\system32\svchost.exe"));
        assert_eq!(command_target(r"C:\tools\run /q", &is_file).as_deref(), Some(r"C:\tools\run.exe"));
        assert_eq!(command_target(r"C:\tools\run.cmd /q", &is_file), None);
    }

    #[test]
    fn a_program_that_is_not_an_absolute_path_has_no_target() {
        let is_file = files(&["cmd.exe", r"C:\Windows\cmd.exe"]);
        assert_eq!(command_target("cmd.exe /c dir", &is_file), None);
        assert_eq!(command_target("", &is_file), None);
    }

    #[test]
    fn an_unquoted_path_takes_the_shortest_file_that_exists() {
        let is_file = files(&[r"C:\Program.exe", r"C:\Program Files\a\a.exe"]);
        assert_eq!(command_target(r"C:\Program Files\a\a.exe", &is_file).as_deref(), Some(r"C:\Program.exe"));
    }

    #[test]
    fn names_an_account() {
        assert_eq!(account_name("S-1-5-18", Some(r"C:\Windows\system32\config\systemprofile")), "SYSTEM");
        assert_eq!(account_name("S-1-5-20", None), "NETWORK SERVICE");
        assert_eq!(account_name("S-1-5-21-1-2-3-1001", Some(r"C:\Users\Dana")), "Dana");
        assert_eq!(account_name("S-1-5-21-1-2-3-1001", Some(r"C:\Users\Dana\")), "Dana");
        assert_eq!(account_name("S-1-5-21-1-2-3-1001", None), "S-1-5-21-1-2-3-1001");
    }

    #[test]
    fn a_user_hive_gets_the_variables_of_its_own_profile() {
        assert_eq!(user_variable(r"C:\Users\Dana", "AppData").as_deref(), Some(r"C:\Users\Dana\AppData\Roaming"));
        assert_eq!(user_variable(r"C:\Users\Dana\", "LOCALAPPDATA").as_deref(), Some(r"C:\Users\Dana\AppData\Local"));
        assert_eq!(user_variable(r"C:\Users\Dana", "temp").as_deref(), Some(r"C:\Users\Dana\AppData\Local\Temp"));
        assert_eq!(user_variable(r"C:\Users\Dana", "USERPROFILE").as_deref(), Some(r"C:\Users\Dana"));
        assert_eq!(user_variable(r"C:\Users\Dana", "SystemRoot"), None);
    }

    #[test]
    fn converts_a_filetime_to_unix_seconds() {
        assert_eq!(filetime_to_unix(116_444_736_000_000_000), Some(0));
        assert_eq!(filetime_to_unix(116_444_736_000_000_000 + 25_000_000), Some(2));
        assert_eq!(filetime_to_unix(0), None);
    }

    const TASK: &str = r#"<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo><Author>Someone</Author></RegistrationInfo>
  <Triggers><LogonTrigger><Enabled>false</Enabled></LogonTrigger></Triggers>
  <Principals><Principal id="Author"><UserId>S-1-5-18</UserId><RunLevel>HighestAvailable</RunLevel></Principal></Principals>
  <Settings><Enabled>true</Enabled></Settings>
  <Actions Context="Author">
    <Exec><Command>%SystemRoot%\system32\cmd.exe</Command><Arguments>/c "echo a &amp; b" &#38;&#x26; &lt;x&gt;</Arguments></Exec>
    <Exec><Command>C:\Program Files\tool\tool.exe</Command></Exec>
    <ComHandler><ClassId>{00000000-0000-0000-0000-000000000000}</ClassId></ComHandler>
  </Actions>
</Task>"#;

    fn utf16_with_mark(text: &str) -> Vec<u8> {
        let mut bytes = vec![0xFF, 0xFE];
        bytes.extend(text.encode_utf16().flat_map(u16::to_le_bytes));
        bytes
    }

    #[test]
    fn reads_every_exec_action_of_a_task() {
        let task = parse_task(TASK.as_bytes()).unwrap();
        assert!(task.enabled);
        assert_eq!(task.principal, "S-1-5-18");
        assert_eq!(
            task.actions,
            [
                TaskAction { command: r"%SystemRoot%\system32\cmd.exe".to_string(), arguments: r#"/c "echo a & b" && <x>"#.to_string() },
                TaskAction { command: r"C:\Program Files\tool\tool.exe".to_string(), arguments: String::new() },
            ]
        );
    }

    #[test]
    fn reads_a_task_in_utf16_with_a_byte_order_mark() {
        let little = parse_task(&utf16_with_mark(TASK)).unwrap();
        assert_eq!(little, parse_task(TASK.as_bytes()).unwrap());

        let mut big = vec![0xFE, 0xFF];
        big.extend(TASK.encode_utf16().flat_map(u16::to_be_bytes));
        assert_eq!(parse_task(&big).unwrap(), little);

        let mut utf8 = vec![0xEF, 0xBB, 0xBF];
        utf8.extend_from_slice(TASK.as_bytes());
        assert_eq!(parse_task(&utf8).unwrap(), little);
    }

    #[test]
    fn a_disabled_task_is_disabled_and_a_disabled_trigger_is_not() {
        let task = parse_task(TASK.replace("<Settings><Enabled>true", "<Settings><Enabled>false").as_bytes()).unwrap();
        assert!(!task.enabled);

        let task = parse_task(TASK.replace("<Settings><Enabled>true</Enabled></Settings>", "").as_bytes()).unwrap();
        assert!(task.enabled);
    }

    #[test]
    fn a_task_without_an_exec_action_has_none() {
        let task = parse_task(
            br#"<Task xmlns="x"><Principals><Principal><GroupId>S-1-5-32-544</GroupId></Principal></Principals>
            <Actions><ComHandler><ClassId>{1}</ClassId></ComHandler></Actions></Task>"#,
        )
        .unwrap();
        assert!(task.actions.is_empty());
        assert_eq!(task.principal, "S-1-5-32-544");
    }

    #[test]
    fn an_exec_in_the_wrong_place_is_not_an_action() {
        let task = parse_task(br#"<Task><Triggers><Exec><Command>C:\x.exe</Command></Exec></Triggers></Task>"#).unwrap();
        assert!(task.actions.is_empty());
    }

    #[test]
    fn an_entity_the_document_defines_is_not_expanded() {
        let task = parse_task(
            br#"<?xml version="1.0"?><!DOCTYPE Task [<!ENTITY evil "C:\evil.exe">]>
            <Task><Actions><Exec><Command>&evil;</Command></Exec></Actions></Task>"#,
        )
        .unwrap();
        assert_eq!(task.actions[0].command, "");
    }

    #[test]
    fn what_is_not_a_task_is_refused() {
        assert!(parse_task(b"not xml at all").is_err());
        assert!(parse_task(b"<Other><Actions/></Other>").is_err());
        assert!(parse_task(b"<Task><Actions></Task>").is_err());
        assert!(parse_task(b"").is_err());
    }

    #[test]
    fn a_task_command_reads_as_one_program_and_its_arguments() {
        let action = |command: &str, arguments: &str| TaskAction { command: command.to_string(), arguments: arguments.to_string() };
        assert_eq!(task_command(&action(r"%SystemRoot%\system32\cmd.exe", "/c dir"), &environment), r"C:\Windows\system32\cmd.exe /c dir");
        assert_eq!(task_command(&action(r"%ProgramFiles%\a\a.exe", ""), &environment), r#""C:\Program Files\a\a.exe""#);
        assert_eq!(task_command(&action(r#""C:\a b\a.exe""#, "-x"), &environment), r#""C:\a b\a.exe" -x"#);
        assert_eq!(task_command(&action("", ""), &environment), "");
    }

    fn address(text: &str) -> SocketAddr {
        text.parse().unwrap()
    }

    fn row(pid: u32, state: u32, local: &str, remote: &str) -> TcpRow {
        TcpRow { pid, state, local: address(local), remote: address(remote) }
    }

    #[test]
    fn reads_the_addresses_of_the_table() {
        assert_eq!(tcp4_address(u32::from_ne_bytes([93, 184, 216, 34]), u32::from(443u16.to_be())), address("93.184.216.34:443"));
        assert_eq!(tcp4_address(u32::from_ne_bytes([10, 0, 0, 5]), 0xABCD_0000 | u32::from(8080u16.to_be())), address("10.0.0.5:8080"));

        let v6 = "2001:db8::1".parse::<Ipv6Addr>().unwrap().octets();
        assert_eq!(tcp6_address(v6, u32::from(22u16.to_be())), address("[2001:db8::1]:22"));

        let mapped = "::ffff:192.0.2.7".parse::<Ipv6Addr>().unwrap().octets();
        assert_eq!(tcp6_address(mapped, u32::from(80u16.to_be())), address("192.0.2.7:80"));
    }

    #[test]
    fn keeps_the_established_connections_toward_other_hosts() {
        let rows = vec![
            row(10, TCP_ESTABLISHED, "10.0.0.5:50000", "93.184.216.34:443"),
            row(11, TCP_ESTABLISHED, "[2001:db8::5]:50001", "[2001:db8::1]:443"),
            row(12, 1, "10.0.0.5:50002", "93.184.216.34:443"),
            row(13, 8, "10.0.0.5:50003", "93.184.216.34:443"),
            row(14, TCP_ESTABLISHED, "127.0.0.1:50004", "127.0.0.1:5432"),
            row(15, TCP_ESTABLISHED, "[::1]:50005", "[::1]:5432"),
            row(16, TCP_ESTABLISHED, "10.0.0.5:50006", "0.0.0.0:0"),
        ];

        let kept: Vec<u32> = outbound(rows).iter().map(|row| row.pid).collect();
        assert_eq!(kept, [10, 11]);
    }

    #[test]
    fn a_connection_accepted_on_a_listening_port_is_not_outbound() {
        let rows = vec![
            row(4, TCP_LISTEN, "0.0.0.0:3389", "0.0.0.0:0"),
            row(4, TCP_ESTABLISHED, "10.0.0.5:3389", "203.0.113.9:51000"),
            row(20, TCP_ESTABLISHED, "10.0.0.5:51234", "203.0.113.9:3389"),
        ];

        let kept: Vec<u32> = outbound(rows).iter().map(|row| row.pid).collect();
        assert_eq!(kept, [20]);
    }

    #[test]
    fn a_socket_keeps_its_identity_and_tells_others_apart() {
        let first = row(10, TCP_ESTABLISHED, "10.0.0.5:50000", "93.184.216.34:443");
        assert_eq!(socket_identity(&first), socket_identity(&first));
        assert_ne!(socket_identity(&first), 0);

        let other_process = TcpRow { pid: 11, ..first };
        let other_port = row(10, TCP_ESTABLISHED, "10.0.0.5:50001", "93.184.216.34:443");
        let other_host = row(10, TCP_ESTABLISHED, "10.0.0.5:50000", "93.184.216.35:443");
        let v6 = row(10, TCP_ESTABLISHED, "[2001:db8::5]:50000", "[2001:db8::1]:443");
        let identities: std::collections::HashSet<u64> = [first, other_process, other_port, other_host, v6].iter().map(socket_identity).collect();
        assert_eq!(identities.len(), 5);
    }

    #[test]
    fn the_hash_is_the_same_in_every_build() {
        assert_eq!(stable_hash(&[b"a"]), 0xaf63_dc4c_8601_ec8c);
        assert_eq!(stable_hash(&[b"a", b"b"]), stable_hash(&[b"ab"]));
        assert_eq!(stable_hash(&[]), 0xcbf2_9ce4_8422_2325);
    }
}
