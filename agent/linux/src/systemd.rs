use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::time::{Duration, Instant};

pub const PRIVATE_SOCKET: &str = "/run/systemd/private";

const IO_TIMEOUT: Duration = Duration::from_secs(2);
const REPLY_DEADLINE: Duration = Duration::from_secs(4);
const MAX_AUTH_REPLY: usize = 256;
const MAX_MESSAGE_PART: usize = 64 * 1024;

const METHOD_CALL: u8 = 1;
const METHOD_RETURN: u8 = 2;
const ERROR: u8 = 3;

const FIELD_PATH: u8 = 1;
const FIELD_INTERFACE: u8 = 2;
const FIELD_MEMBER: u8 = 3;
const FIELD_DESTINATION: u8 = 6;
const FIELD_SIGNATURE: u8 = 8;

pub fn system_is_stopping(socket: &Path, uid: u32) -> Result<bool, String> {
    Ok(system_state(socket, uid)? == "stopping")
}

fn system_state(socket: &Path, uid: u32) -> Result<String, String> {
    let mut stream = UnixStream::connect(socket)
        .map_err(|e| format!("Failed to connect to {}: {}", socket.display(), e))?;
    stream.set_read_timeout(Some(IO_TIMEOUT))
        .and_then(|_| stream.set_write_timeout(Some(IO_TIMEOUT)))
        .map_err(|e| format!("Failed to set socket timeouts: {}", e))?;

    authenticate(&mut stream, uid)?;

    stream.write_all(&system_state_request())
        .map_err(|e| format!("Failed to ask systemd for its state: {}", e))?;

    read_string_reply(&mut stream, Instant::now() + REPLY_DEADLINE)
}

fn authenticate(stream: &mut UnixStream, uid: u32) -> Result<(), String> {
    let request = format!("\0AUTH EXTERNAL {}\r\nBEGIN\r\n", hex::encode(uid.to_string()));
    stream.write_all(request.as_bytes())
        .map_err(|e| format!("Failed to authenticate to systemd: {}", e))?;

    let mut reply = Vec::new();
    let mut byte = [0u8; 1];
    while !reply.ends_with(b"\r\n") {
        if reply.len() >= MAX_AUTH_REPLY {
            return Err("systemd sent an oversized authentication reply".to_string());
        }
        stream.read_exact(&mut byte)
            .map_err(|e| format!("Failed to read the authentication reply: {}", e))?;
        reply.push(byte[0]);
    }

    if !reply.starts_with(b"OK ") {
        return Err(format!("systemd refused authentication: {}", String::from_utf8_lossy(&reply).trim()));
    }

    Ok(())
}

#[derive(Default)]
struct Encoder {
    bytes: Vec<u8>,
}

impl Encoder {
    fn align(&mut self, boundary: usize) {
        while !self.bytes.len().is_multiple_of(boundary) {
            self.bytes.push(0);
        }
    }

    fn u32(&mut self, value: u32) {
        self.align(4);
        self.bytes.extend_from_slice(&value.to_le_bytes());
    }

    fn string(&mut self, value: &str) {
        self.u32(value.len() as u32);
        self.bytes.extend_from_slice(value.as_bytes());
        self.bytes.push(0);
    }

    fn signature(&mut self, value: &str) {
        self.bytes.push(value.len() as u8);
        self.bytes.extend_from_slice(value.as_bytes());
        self.bytes.push(0);
    }

    fn header_field(&mut self, code: u8, value_type: &str, value: &str) {
        self.align(8);
        self.bytes.push(code);
        self.signature(value_type);
        if value_type == "g" {
            self.signature(value);
        } else {
            self.string(value);
        }
    }
}

fn system_state_request() -> Vec<u8> {
    let mut body = Encoder::default();
    body.string("org.freedesktop.systemd1.Manager");
    body.string("SystemState");

    let mut fields = Encoder::default();
    fields.header_field(FIELD_PATH, "o", "/org/freedesktop/systemd1");
    fields.header_field(FIELD_INTERFACE, "s", "org.freedesktop.DBus.Properties");
    fields.header_field(FIELD_MEMBER, "s", "Get");
    fields.header_field(FIELD_DESTINATION, "s", "org.freedesktop.systemd1");
    fields.header_field(FIELD_SIGNATURE, "g", "ss");

    let mut message = Encoder::default();
    message.bytes.extend_from_slice(&[b'l', METHOD_CALL, 0, 1]);
    message.u32(body.bytes.len() as u32);
    message.u32(1);
    message.u32(fields.bytes.len() as u32);
    message.bytes.extend_from_slice(&fields.bytes);
    message.align(8);
    message.bytes.extend_from_slice(&body.bytes);
    message.bytes
}

fn read_u32(bytes: &[u8], offset: usize, endianness: u8) -> Result<u32, String> {
    let raw: [u8; 4] = bytes.get(offset..offset + 4)
        .and_then(|slice| slice.try_into().ok())
        .ok_or_else(|| "systemd sent a truncated message".to_string())?;

    match endianness {
        b'l' => Ok(u32::from_le_bytes(raw)),
        b'B' => Ok(u32::from_be_bytes(raw)),
        other => Err(format!("systemd sent an unknown byte order: {}", other)),
    }
}

fn read_part(stream: &mut impl Read, length: usize) -> Result<Vec<u8>, String> {
    if length > MAX_MESSAGE_PART {
        return Err("systemd sent an oversized message".to_string());
    }
    let mut part = vec![0u8; length];
    stream.read_exact(&mut part)
        .map_err(|e| format!("Failed to read the systemd reply: {}", e))?;
    Ok(part)
}

fn read_string_reply(stream: &mut impl Read, deadline: Instant) -> Result<String, String> {
    while Instant::now() < deadline {
        let fixed = read_part(stream, 16)?;
        let endianness = fixed[0];
        let body_length = read_u32(&fixed, 4, endianness)? as usize;
        let fields_length = read_u32(&fixed, 12, endianness)? as usize;

        read_part(stream, fields_length.div_ceil(8) * 8)?;
        let body = read_part(stream, body_length)?;

        match fixed[1] {
            METHOD_RETURN => return variant_string(&body, endianness),
            ERROR => return Err("systemd answered the state request with an error".to_string()),
            _ => continue,
        }
    }

    Err("systemd did not answer the state request".to_string())
}

fn variant_string(body: &[u8], endianness: u8) -> Result<String, String> {
    if body.get(..3) != Some(&[1, b's', 0]) {
        return Err("systemd answered with a value that is not a string".to_string());
    }

    let length = read_u32(body, 4, endianness)? as usize;
    let text = body.get(8..8 + length)
        .ok_or_else(|| "systemd sent a truncated string".to_string())?;

    String::from_utf8(text.to_vec()).map_err(|_| "systemd sent a string that is not UTF-8".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::net::UnixListener;
    use std::path::PathBuf;

    const STOPPING_REPLY: &[u8] = &[
        b'l', 2, 1, 1, 17, 0, 0, 0, 9, 0, 0, 0, 15, 0, 0, 0,
        5, 1, b'u', 0, 1, 0, 0, 0,
        8, 1, b'g', 0, 1, b'v', 0, 0,
        1, b's', 0, 0, 8, 0, 0, 0, b's', b't', b'o', b'p', b'p', b'i', b'n', b'g', 0,
    ];

    fn state_reply(state: &str) -> Vec<u8> {
        let mut body = Encoder::default();
        body.signature("s");
        body.string(state);

        let mut reply = vec![b'l', METHOD_RETURN, 1, 1];
        reply.extend_from_slice(&(body.bytes.len() as u32).to_le_bytes());
        reply.extend_from_slice(&7u32.to_le_bytes());
        reply.extend_from_slice(&0u32.to_le_bytes());
        reply.extend_from_slice(&body.bytes);
        reply
    }

    fn soon() -> Instant {
        Instant::now() + Duration::from_secs(5)
    }

    #[test]
    fn test_a_stream_of_signals_ends_at_the_deadline() {
        let mut signal = state_reply("ignored");
        signal[1] = 4;
        let endless = signal.repeat(64);

        let err = read_string_reply(&mut &endless[..], Instant::now()).unwrap_err();
        assert!(err.contains("did not answer"), "unexpected error: {}", err);
    }

    fn socket_path(name: &str) -> PathBuf {
        let path = std::env::temp_dir().join(format!("zedr-systemd-{}-{}.sock", std::process::id(), name));
        let _ = std::fs::remove_file(&path);
        path
    }

    fn serve_once(path: &Path, auth_reply: &'static str, replies: Vec<Vec<u8>>) -> std::thread::JoinHandle<(String, Vec<u8>)> {
        let listener = UnixListener::bind(path).unwrap();
        std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();

            let mut handshake = [0u8; 128];
            let received = stream.read(&mut handshake).unwrap();
            let handshake = &handshake[..received];
            assert!(handshake.ends_with(b"\r\nBEGIN\r\n"), "systemd drops a call that is not preceded by a complete handshake");
            let auth = handshake[..handshake.len() - 7].to_vec();
            stream.write_all(auth_reply.as_bytes()).unwrap();

            let mut fixed = [0u8; 16];
            let mut request = Vec::new();
            if stream.read_exact(&mut fixed).is_ok() {
                let body_length = u32::from_le_bytes(fixed[4..8].try_into().unwrap()) as usize;
                let fields_length = u32::from_le_bytes(fixed[12..16].try_into().unwrap()) as usize;
                let mut rest = vec![0u8; fields_length.div_ceil(8) * 8 + body_length];
                stream.read_exact(&mut rest).unwrap();
                request.extend_from_slice(&fixed);
                request.extend_from_slice(&rest);

                for reply in replies {
                    stream.write_all(&reply).unwrap();
                }
            }

            (String::from_utf8_lossy(&auth).to_string(), request)
        })
    }

    #[test]
    fn test_reply_written_out_byte_by_byte_is_understood() {
        assert_eq!(read_string_reply(&mut &STOPPING_REPLY[..], soon()).unwrap(), "stopping");
    }

    #[test]
    fn test_big_endian_reply_is_understood() {
        let reply: &[u8] = &[
            b'B', 2, 1, 1, 0, 0, 0, 16, 0, 0, 0, 9, 0, 0, 0, 0,
            1, b's', 0, 0, 0, 0, 0, 7, b'r', b'u', b'n', b'n', b'i', b'n', b'g', 0,
        ];
        assert_eq!(read_string_reply(&mut &reply[..], soon()).unwrap(), "running");
    }

    #[test]
    fn test_request_is_a_well_formed_property_get() {
        let request = system_state_request();

        assert_eq!(&request[..4], &[b'l', METHOD_CALL, 0, 1]);
        let body_length = u32::from_le_bytes(request[4..8].try_into().unwrap()) as usize;
        let fields_length = u32::from_le_bytes(request[12..16].try_into().unwrap()) as usize;
        let body_start = 16 + fields_length.div_ceil(8) * 8;
        assert_eq!(request.len(), body_start + body_length);
        assert_eq!(body_start % 8, 0);

        let fields = &request[16..16 + fields_length];
        assert_eq!(&fields[..8], &[FIELD_PATH, 1, b'o', 0, 25, 0, 0, 0]);
        assert_eq!(&fields[8..33], b"/org/freedesktop/systemd1");
        assert_eq!(&fields[fields_length - 8..], &[FIELD_SIGNATURE, 1, b'g', 0, 2, b's', b's', 0]);

        let body = &request[body_start..];
        assert_eq!(&body[..4], &32u32.to_le_bytes());
        assert_eq!(&body[4..36], b"org.freedesktop.systemd1.Manager");
        assert_eq!(&body[36..40], &[0, 0, 0, 0]);
        assert_eq!(&body[40..44], &11u32.to_le_bytes());
        assert_eq!(&body[44..], b"SystemState\0");
    }

    #[test]
    fn test_shutdown_is_told_apart_from_a_running_system() {
        for (state, stopping) in [("stopping", true), ("running", false), ("degraded", false), ("starting", false)] {
            let path = socket_path(state);
            let server = serve_once(&path, "OK 0123456789abcdef0123456789abcdef\r\n", vec![state_reply(state)]);

            assert_eq!(system_is_stopping(&path, 0).unwrap(), stopping, "state {}", state);

            let (auth, request) = server.join().unwrap();
            assert_eq!(auth, "\0AUTH EXTERNAL 30\r\n");
            assert_eq!(request, system_state_request());
            std::fs::remove_file(&path).unwrap();
        }
    }

    #[test]
    fn test_uid_is_sent_as_hex_of_its_decimal_form() {
        let path = socket_path("uid");
        let server = serve_once(&path, "OK 0123456789abcdef0123456789abcdef\r\n", vec![state_reply("running")]);
        system_is_stopping(&path, 1000).unwrap();
        assert_eq!(server.join().unwrap().0, "\0AUTH EXTERNAL 31303030\r\n");
        std::fs::remove_file(&path).unwrap();
    }

    #[test]
    fn test_signals_before_the_reply_are_skipped() {
        let path = socket_path("signal-first");
        let mut signal = state_reply("ignored");
        signal[1] = 4;
        let server = serve_once(&path, "OK 0123456789abcdef0123456789abcdef\r\n", vec![signal, STOPPING_REPLY.to_vec()]);

        assert!(system_is_stopping(&path, 0).unwrap());

        server.join().unwrap();
        std::fs::remove_file(&path).unwrap();
    }

    #[test]
    fn test_refused_authentication_is_an_error() {
        let path = socket_path("rejected");
        let server = serve_once(&path, "REJECTED EXTERNAL\r\n", Vec::new());

        let err = system_is_stopping(&path, 0).unwrap_err();
        assert!(err.contains("refused authentication"), "unexpected error: {}", err);

        drop(server);
        std::fs::remove_file(&path).unwrap();
    }

    #[test]
    fn test_error_reply_and_garbage_are_errors() {
        let mut error = state_reply("org.freedesktop.DBus.Error.UnknownProperty");
        error[1] = ERROR;
        assert!(read_string_reply(&mut &error[..], soon()).is_err());

        let not_a_string: &[u8] = &[b'l', 2, 1, 1, 8, 0, 0, 0, 9, 0, 0, 0, 0, 0, 0, 0, 1, b'u', 0, 0, 5, 0, 0, 0];
        assert!(read_string_reply(&mut &not_a_string[..], soon()).is_err());

        let truncated = &STOPPING_REPLY[..STOPPING_REPLY.len() - 4];
        assert!(read_string_reply(&mut &truncated[..], soon()).is_err());

        let oversized: &[u8] = &[b'l', 2, 1, 1, 0xff, 0xff, 0xff, 0x7f, 9, 0, 0, 0, 0, 0, 0, 0];
        assert!(read_string_reply(&mut &oversized[..], soon()).is_err());

        let unknown_order: &[u8] = &[b'x', 2, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        assert!(read_string_reply(&mut &unknown_order[..], soon()).is_err());
    }

    #[test]
    fn test_missing_socket_is_an_error() {
        assert!(system_is_stopping(Path::new("/nonexistent/zedr/systemd/private"), 0).is_err());
    }
}
