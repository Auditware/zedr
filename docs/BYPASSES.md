This file documents the known agent bypassing or tampering techniques per operating system

## Shared

- Kill the agent process instead of stopping the service. No stop notice is sent, so the control server only reacts after the silence window of 15 minutes ([ADR 014](./adr/014-liveness-and-tamper-incidents.md)).
- Block the agent's network egress. The agent keeps running and the control server sees the same silence as a kill, after the same window.
- Silence the whole fleet at once. The fleet differential holds every agent at `suspect` and opens no incident, because it cannot tell this from a server or network outage.
- Read the identity seed as a local administrator and send signed heartbeats from elsewhere while the agent is dead. The pinned key proves possession of the seed and nothing more. A second sender is only exposed when both it and the real agent are active, through a `replay` incident.
- Answer a shell command before the agent does, from elsewhere with the identity seed. The control server keeps the first result it stores for a command, so the forged answer stays and the agent's own is left out, with a line in the server log ([ADR 029](./adr/029-signed-commands-run-once-across-agent-restarts.md)).
- Tamper with the control server database. Agent state, incidents and the audit log live there. The audit hash chain makes edits evident but an attacker with write access can rewrite the chain ([ADR 015](./adr/015-console-access-hardening.md)).
- Compromise the control server. Its signing key signs agent binaries, upgrades and shell commands, so a compromised server can run commands as SYSTEM on every agent of that deployment.
- Delete `accepted-commands.json` from the agent's state directory as root and restart the agent. A shell or upgrade command that is less than five minutes old is then accepted again, and the control server hands it out again after two minutes if it has no answer yet ([ADR 029](./adr/029-signed-commands-run-once-across-agent-restarts.md)).
- Damage `accepted-commands.json` as root. The agent refuses every shell and upgrade command until the file is repaired or removed, so the endpoint can neither be investigated through the remote shell nor upgraded.
- Replace the signing public key inside the agent binary and sign the result with the matching private key. The key is covered by the binary signature, so this needs write access to the binary on disk, and with that access the self check passes again ([ADR 017](./adr/017-per-deployment-signing-key.md)).
- Steal a fleet enrollment token from a launch template, from user data through the instance metadata service, from a Kubernetes Secret or from the process list of a host that is installing. Until the token expires, runs out or is revoked, the thief can enroll machines that are not part of the fleet. They report as real agents and can feed false telemetry. They cannot take over an enrolled agent or read its commands ([ADR 019](./adr/019-fleet-enrollment-tokens.md)).
- Let a fleet token expire. New machines stop enrolling and nothing alarms, the only trace is `enrollment_rejected` events.
- Enroll, then never report again. An agent of a terminated instance and an agent that was removed look the same, both stay listed.
- Answer the first download in place of the control server. The agent trusts the key that arrives in the binary it was installed from, so whoever serves that binary chooses the key. TLS to the control server is the only protection at install time.
- Put what an investigator should not read behind output that is mostly escapes. The result of a remote shell command has to fit in one request of 2 MiB, so a file that starts with 350 KB of control characters is shown up to there and no further. The output says where it was cut, and the rest takes a second command ([ADR 027](./adr/027-shell-results-cut-to-one-event-batch.md)).
- Cut the agent off from the control server once a remote shell command has run, and restart the agent before the server is reachable again. The result waits in memory and is lost with the process, so the command stays without an answer ([ADR 028](./adr/028-shell-results-kept-until-the-control-server-takes-them.md)).

## MacOS

## Windows

- Any administrator can stop or delete the service and delete the binary. The stop is reported, the removal is not prevented.
- Suspend the agent's threads instead of killing it. The process stays alive and silent, detected only by the silence window.
- Patch the binary on disk. The self signature check runs inside the binary it protects, so it can be patched out with the rest.

## Linux

- Root can stop, disable or mask the service and delete the binary. The stop is reported, the removal is not prevented.
- Kill the agent with `SIGKILL`. No stop notice is sent, systemd restarts it after five seconds and the new process registers with the same key. Nothing is recorded but a new session number, so repeated kills are invisible as long as each gap stays under the silence window.
- Freeze the agent with `SIGSTOP` or the cgroup freezer. The process stays alive and silent, detected only by the silence window.
- Fake a shutdown. The agent believes the answer on `/run/systemd/private`. Root can mount a socket of its own over that path, or read the identity seed and send a `SystemShutdown` notice by hand, then stop the agent. The machine is shown as `stopped` and no incident opens.
- Replace the binary or the unit file as root. The self signature check runs inside the binary it protects, and systemd starts whatever the unit names.
- Read `/var/lib/zedr/identity.json` as root and report from elsewhere, as on Windows.
- Wipe `/var/lib/zedr` and install again with a fleet token. The machine enrolls as a new agent and the old agent only goes silent, so its history is cut in two.
- Run in a container without the host's `/run/systemd`. Every stop is reported as a service stop, so real stops hide among the incidents of ordinary restarts.
- Delete the DaemonSet or the pod. The agent reports a service stop and is gone until something schedules it again. Anyone who can edit the DaemonSet can also change the image or the control server address.
- Stop the pods through kubelet graceful node shutdown. They are stopped before systemd reports that it is stopping, so a shutdown is reported as a service stop. Not verified on a cluster.
- A remote shell command that outlives its time limit is killed, processes it started in the background are not.
- Run and finish between two sensor polls. A process or a connection that lives shorter than five seconds is usually never reported ([ADR 020](./adr/020-polling-sensor-for-process-and-connection-telemetry.md)).
- Start a shell and let it `exec` the next program at once. The sensor reports the program it finds at the poll, not the shell that came before it.
- Rewrite the process name and command line from inside the process. The sensor reports what `/proc` shows. The executable path is harder to fake, but a deleted or replaced file leaves only a path.
- Hide from `/proc`, with a kernel module, a mount over `/proc/<pid>`, or `hidepid` when the agent is not root. What `/proc` does not list, the agent does not see.
- Talk over UDP, a raw socket, a Unix socket or loopback, or through a process that already has a connection open. Only new outbound TCP connections are reported, and one destination per process once in five minutes.
- Connect from a network namespace the agent cannot see, for example a container when the agent runs in its own process namespace.
- Hold the agent's events back by cutting its network. Events wait in memory, the oldest are dropped after 20,000, and all are lost when the agent restarts.
- Pass a socket to another process and exit. The connection is attributed to the oldest process that holds it when the sensor first sees it, which may not be the one that opened it.
- Add a persistence item and remove it again between two reads of the inventory, which are a minute apart. A cron entry that has fired once and deleted itself is never listed ([ADR 022](./adr/022-persistence-inventory.md)).
- Persist somewhere the inventory does not read: a socket or path unit, a generator, an `at` job, a udev rule, a kernel module, XDG autostart, `.bash_login`, `.zshenv`, `/etc/environment`, a PAM module, or keys that `sshd_config` reads from another file or command.
- Leave the item alone and replace what it runs. The hash covers the unit file, the cron entry or the key, not the program behind `ExecStart` or behind a cron command. Only a preloaded library is hashed itself.
- Add a command to a unit through `ExecStartPre`, `ExecStartPost` or `ExecStop`. The unit is reported as changed with a new hash, the command is not shown.
- Add a line to a shell profile, `rc.local` or an init script. The change is reported with the new hash, the line is not, so someone has to read the file.
- Change the inventory while the agent is stopped. After the restart the change is part of the baseline and is not reported as a change.
- Pad a crontab or an `authorized_keys` file beyond 1 MiB. The file is listed without a hash and its entries are not read.
- Keep the account out of `/etc/passwd`. Homes of directory accounts are not read.
- Show the agent other files than the system uses, with a mount over the path or a rootkit, or persist inside a mount namespace the agent does not read. It reads the file system of the first process it can see.
- Put the key or the profile behind a link to a file system that refuses root, such as NFS with root squash. The item is listed as unread, with no hash.
- Install without the package manager: copy a binary, unpack an archive, `pip install`, `curl | sh`, or run it from a container image. The package inventory lists only what dpkg and apk recorded, and nothing at all on an rpm host ([ADR 023](./adr/023-package-inventory.md)).
- Edit the package database as root. An entry that is deleted from `/var/lib/dpkg/status` is reported as a removal while its files stay, and a version written into it is reported as an upgrade that never happened.
- Replace the files of an installed package. The inventory reports the version the database names, not what is on disk.
- Install and remove a package between two reads of the package database, which are five minutes apart.
- Flood the inventory. Any user can write thousands of unit files into their own home. Each one becomes an event, and when the queue of 20,000 is full the oldest events are dropped, process and network events included.
- Get the event about yourself refused on its way to the control server. An event that is answered with 400, 413 or 422 when it is sent on its own is discarded, and only the agent's log says so ([ADR 024](./adr/024-event-batches-sized-by-encoding-and-narrowed-on-refusal.md)). The control server refuses nothing its own agents send, so this needs something in front of it that answers by content, such as a web application firewall and a command line it blocks.
- Get it refused with another answer. A filter in front of the control server that answers 403 to a chosen command line holds back that batch and everything queued behind it, until the queue is full and the oldest events are dropped.
