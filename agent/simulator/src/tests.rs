/// Scenarios played against a stand-in control server that takes what it is sent and acknowledges windows the way the real one does
use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpListener;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::thread;

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use zedr_protocol::{hash_from_hex, hash_to_hex, window_ack_signing_bytes, SealedWindow, SealedWindowAck, SIGNATURE_HEADER};

use crate::fleet;
use crate::scenario::Scenario;

const T0: u64 = 1_700_000_000;

fn deployment_key() -> SigningKey {
    SigningKey::from_bytes(&[9u8; 32])
}

pub fn deployment_key_hex() -> String {
    hash_to_hex(&deployment_key().verifying_key().to_bytes())
}

struct Received {
    path: String,
    signature: String,
    body: String,
}

struct StubServer {
    url: String,
    received: Arc<Mutex<Vec<Received>>>,
}

impl StubServer {
    fn start(registration_answer: u16) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let received = Arc::new(Mutex::new(Vec::new()));
        let sink = Arc::clone(&received);

        thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(mut stream) = stream else { break };
                let request = read_request(&mut stream);
                let (status, body) = match request.path.as_str() {
                    "/api/agents/register" => (registration_answer, "{}".to_string()),
                    "/api/windows" => acknowledge(&request),
                    _ => (200, "{}".to_string()),
                };
                sink.lock().unwrap().push(request);
                let _ = write!(stream, "HTTP/1.1 {} Stub\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}", status, body.len(), body);
            }
        });

        Self { url, received }
    }

    fn sent_to(&self, path: &str) -> Vec<serde_json::Value> {
        self.received.lock().unwrap().iter().filter(|request| request.path == path).map(|request| serde_json::from_str(&request.body).unwrap()).collect()
    }

    fn windows_of(&self, agent_id: &str) -> Vec<SealedWindow> {
        self.sent_to("/api/windows").into_iter().map(|window| serde_json::from_value::<SealedWindow>(window).unwrap()).filter(|window| window.agent_id == agent_id).collect()
    }
}

fn read_request(stream: &mut std::net::TcpStream) -> Received {
    let mut reader = BufReader::new(stream);
    let mut request_line = String::new();
    reader.read_line(&mut request_line).unwrap();
    let path = request_line.split_whitespace().nth(1).unwrap().to_string();

    let mut signature = String::new();
    let mut content_length = 0;
    loop {
        let mut line = String::new();
        reader.read_line(&mut line).unwrap();
        let line = line.trim_end();
        if line.is_empty() {
            break;
        }
        if let Some((name, value)) = line.split_once(':') {
            match name.to_ascii_lowercase().as_str() {
                SIGNATURE_HEADER => signature = value.trim().to_string(),
                "content-length" => content_length = value.trim().parse().unwrap(),
                _ => {}
            }
        }
    }

    let mut body = vec![0u8; content_length];
    reader.read_exact(&mut body).unwrap();
    Received { path, signature, body: String::from_utf8(body).unwrap() }
}

fn acknowledge(request: &Received) -> (u16, String) {
    let window: SealedWindow = serde_json::from_str(&request.body).unwrap();
    let next_index = window.header.first_index + u64::from(window.header.count);
    let signed = window_ack_signing_bytes(&window.agent_id, window.header.window, next_index, &window.header.head).unwrap();
    let ack = SealedWindowAck { window: window.header.window, next_index, head: window.header.head, signature: deployment_key().sign(&signed).to_bytes().to_vec() };
    (200, serde_json::to_string(&ack).unwrap())
}

fn state_dir(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("zedr-simulator-{}-{}", std::process::id(), name));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn process(at: u64, pid: u32, ppid: u32, path: &str, arguments: &[&str]) -> serde_json::Value {
    let mut command_line = vec![path];
    command_line.extend(arguments);
    serde_json::json!({ "Process": { "timestamp": at, "pid": pid, "ppid": ppid, "executable_path": path, "command_line": command_line, "action": "Create", "uid": 33, "hash": null } })
}

fn heartbeat(at: u64) -> serde_json::Value {
    serde_json::json!({ "Heartbeat": { "timestamp": at } })
}

/// A web server whose worker starts a shell three minutes in, which the rules flag
fn web_server() -> serde_json::Value {
    serde_json::json!({
        "hostname": "WEB-SRV-04", "platform": "linux", "os_version": "Ubuntu 24.04.1 LTS", "architecture": "x86_64", "version": "0.1.0",
        "ip_address": "10.30.1.14", "enrollment_key": "install-key-1",
        "timeline": [heartbeat(T0), process(T0 + 1, 20, 1, "/usr/sbin/nginx", &[]), heartbeat(T0 + 30), process(T0 + 200, 21, 20, "/bin/sh", &["-c", "id"]), heartbeat(T0 + 210)],
    })
}

fn scenario(server: &StubServer, dir: &std::path::Path, endpoints: Vec<serde_json::Value>) -> Scenario {
    let written = serde_json::json!({ "server": server.url, "deployment_key": deployment_key_hex(), "state_dir": dir, "endpoints": endpoints });
    Scenario::parse(&written.to_string()).unwrap()
}

fn agent_id(server: &StubServer, hostname: &str) -> String {
    let registration = server.sent_to("/api/agents/register").into_iter().find(|registration| registration["hostname"] == hostname).unwrap();
    registration["agent_id"].as_str().unwrap().to_string()
}

#[test]
fn test_endpoints_enroll_as_the_scenario_describes_them_and_what_their_sensors_saw_arrives_only_sealed() {
    let server = StubServer::start(200);
    let dir = state_dir("honest");
    let quiet = serde_json::json!({
        "hostname": "WEB-SRV-05", "platform": "linux", "os_version": "Ubuntu 24.04.1 LTS", "architecture": "aarch64", "version": "0.1.0",
        "timeline": [heartbeat(T0), heartbeat(T0 + 130)],
    });

    let mut said = Vec::new();
    fleet::run(scenario(&server, &dir, vec![web_server(), quiet]), &mut said).unwrap();
    assert_eq!(String::from_utf8(said).unwrap(), "READY 2 endpoints\nPROVEN 0 endpoints\n");

    let registrations = server.received.lock().unwrap().iter().filter(|request| request.path == "/api/agents/register").map(|request| (request.body.clone(), request.signature.clone())).collect::<Vec<_>>();
    assert_eq!(registrations.len(), 2);
    for (body, signature) in &registrations {
        let registration: serde_json::Value = serde_json::from_str(body).unwrap();
        let key = VerifyingKey::from_bytes(&hash_from_hex(registration["public_key"].as_str().unwrap()).unwrap()).unwrap();
        let mut signed = [0u8; 64];
        for (byte, pair) in signed.iter_mut().zip(signature.as_bytes().chunks(2)) {
            *byte = u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap();
        }
        key.verify(body.as_bytes(), &Signature::from_bytes(&signed)).expect("a registration is signed by the identity it enrolls");
    }
    let enrolled = server.sent_to("/api/agents/register").into_iter().find(|registration| registration["hostname"] == "WEB-SRV-04").unwrap();
    assert_eq!(
        (enrolled["platform"].as_str(), enrolled["os_version"].as_str(), enrolled["architecture"].as_str(), enrolled["ip_address"].as_str(), enrolled["enrollment_key"].as_str()),
        (Some("linux"), Some("Ubuntu 24.04.1 LTS"), Some("x86_64"), Some("10.30.1.14"), Some("install-key-1"))
    );

    let web = agent_id(&server, "WEB-SRV-04");
    let reported: Vec<serde_json::Value> = server.sent_to("/api/events").into_iter().filter(|batch| batch["agent_id"] == web.as_str()).flat_map(|batch| batch["events"].as_array().unwrap().clone()).collect();
    assert_eq!(reported, vec![heartbeat(T0), heartbeat(T0 + 30), heartbeat(T0 + 210)], "only what the agent says about itself travels unsealed");

    let windows = server.windows_of(&web);
    assert_eq!(windows.iter().map(|window| (window.header.window, window.header.count, window.header.fresh)).collect::<Vec<_>>(), vec![(0, 1, true), (1, 0, false), (2, 0, false), (3, 1, false)], "a window a minute, and one at once when a rule fires");
    assert!(windows.windows(2).all(|pair| pair[1].header.prev_head == pair[0].header.head && pair[1].header.first_index == pair[0].header.first_index + u64::from(pair[0].header.count)));
    assert!(windows.iter().all(|window| !window.proving && window.header.epoch == 1 && window.events.len() == window.header.count as usize));
    assert!(windows[..3].iter().all(|window| window.releases.is_empty()));
    let release = &windows[3].releases[0];
    assert_eq!((windows[3].releases.len(), release.rule.as_str(), release.trigger, release.context.as_slice(), release.pid), (1, "server-child", 1, [0].as_slice(), 21));
    assert_eq!(release.openings.iter().map(|opening| opening.index).collect::<Vec<_>>(), vec![1, 0]);

    let silent = server.windows_of(&agent_id(&server, "WEB-SRV-05"));
    assert_eq!(silent.iter().map(|window| (window.header.window, window.header.count)).collect::<Vec<_>>(), vec![(0, 0), (1, 0)], "a sensor that sees nothing still seals");
    assert!(server.sent_to("/api/proofs").is_empty());

    std::fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn test_an_agent_that_stops_delivers_what_its_sensor_saw_and_then_says_so_in_a_request_of_its_own() {
    let server = StubServer::start(200);
    let dir = state_dir("stopping");
    let stopped = serde_json::json!({
        "hostname": "HR-DESKTOP-03", "platform": "windows", "os_version": "Windows 10 Pro 22H2", "architecture": "x86_64", "version": "0.1.0",
        "timeline": [heartbeat(T0), process(T0 + 10, 4, 0, "System", &[]), heartbeat(T0 + 30), { "AgentStopping": { "timestamp": T0 + 30, "reason": "ServiceStop" } }],
    });
    fleet::run(scenario(&server, &dir, vec![stopped]), &mut Vec::new()).unwrap();

    let after_registration: Vec<(String, serde_json::Value)> =
        server.received.lock().unwrap().iter().skip(1).map(|request| (request.path.clone(), serde_json::from_str(&request.body).unwrap())).collect();
    assert_eq!(after_registration.iter().map(|(path, _)| path.as_str()).collect::<Vec<_>>(), vec!["/api/events", "/api/windows", "/api/events"]);
    assert_eq!(after_registration[0].1["events"], serde_json::json!([heartbeat(T0), heartbeat(T0 + 30)]));
    assert_eq!(after_registration[1].1["header"]["count"], 1, "the window is sealed at the stop, well before its minute is over");
    assert_eq!(after_registration[2].1["events"], serde_json::json!([{ "AgentStopping": { "timestamp": T0 + 30, "reason": "ServiceStop" } }]), "a stop notice in a batch with a heartbeat would be read as an agent that is back");

    std::fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn test_an_endpoint_the_server_does_not_enroll_stops_the_run_and_is_named() {
    let server = StubServer::start(401);
    let dir = state_dir("rejected");

    let refused = fleet::run(scenario(&server, &dir, vec![web_server()]), &mut Vec::new()).unwrap_err();
    assert_eq!(refused, "WEB-SRV-04: Registration rejected: HTTP 401");
    assert!(server.sent_to("/api/windows").is_empty());

    std::fs::remove_dir_all(&dir).unwrap();
}

#[cfg(unix)]
#[test]
fn test_the_dishonest_endpoint_seals_its_window_without_the_match_and_its_proof_still_tells_it() {
    use std::os::unix::fs::PermissionsExt;
    use zedr_protocol::bytes_from_base64;
    use zedr_rules::proof::{self, Input};
    use zedr_rules::RuleId;

    let server = StubServer::start(200);
    let dir = state_dir("dishonest");
    let prover = dir.join("stand-in-prover");
    std::fs::write(&prover, "#!/bin/sh\ncp \"$2\" \"$3\"\n").unwrap();
    std::fs::set_permissions(&prover, std::fs::Permissions::from_mode(0o755)).unwrap();

    let mut endpoint = web_server();
    endpoint["proving"] = serde_json::json!(true);
    endpoint["withhold"] = serde_json::json!(["server-child"]);
    let mut played = scenario(&server, &dir.join("agents"), vec![endpoint]);
    played.prover = Some(prover);

    let mut said = Vec::new();
    fleet::run(played, &mut said).unwrap();
    assert_eq!(String::from_utf8(said).unwrap(), "READY 1 endpoints\nPROVEN 1 endpoints\n");

    let windows = server.windows_of(&agent_id(&server, "WEB-SRV-04"));
    assert_eq!(windows.iter().map(|window| window.header.count).collect::<Vec<_>>(), vec![1, 0, 0, 1]);
    assert!(windows.iter().all(|window| window.proving && window.releases.is_empty()), "the match is not reported");

    let proofs = server.sent_to("/api/proofs");
    assert_eq!(proofs.len(), 1);
    let input = Input::from_bytes(&bytes_from_base64(proofs[0]["receipt"].as_str().unwrap()).unwrap()).expect("the stand-in prover hands back what it was given to prove");
    let (journal, _) = proof::run(input).unwrap();
    assert_eq!((journal.first_window, journal.last_window, journal.next_index), (0, 3, 2));
    assert_eq!(journal.matches.iter().map(|found| (found.rule, found.trigger, found.pid)).collect::<Vec<_>>(), vec![(RuleId::ServerChild, 1, 21)], "the proof is about the committed events, so it tells the match");

    std::fs::remove_dir_all(&dir).unwrap();
}
