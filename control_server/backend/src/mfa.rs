use hmac::{Hmac, Mac};
use rand::RngCore;
use sha1::Sha1;
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

const TIME_STEP_SECS: u64 = 30;
const CODE_DIGITS: u32 = 6;
const ALLOWED_DRIFT_STEPS: u64 = 1;
const SECRET_BYTES: usize = 20;
const RECOVERY_CODE_COUNT: usize = 10;
const BASE32_ALPHABET: &[u8; 32] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

pub fn new_secret() -> Vec<u8> {
    let mut secret = vec![0u8; SECRET_BYTES];
    rand::rngs::OsRng.fill_bytes(&mut secret);
    secret
}

pub fn base32_encode(bytes: &[u8]) -> String {
    let mut encoded = String::with_capacity((bytes.len() * 8).div_ceil(5));
    let mut buffer: u32 = 0;
    let mut bits: u32 = 0;

    for byte in bytes {
        buffer = (buffer << 8) | u32::from(*byte);
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            encoded.push(BASE32_ALPHABET[((buffer >> bits) & 0x1f) as usize] as char);
        }
    }

    if bits > 0 {
        encoded.push(BASE32_ALPHABET[((buffer << (5 - bits)) & 0x1f) as usize] as char);
    }

    encoded
}

pub fn provisioning_uri(issuer: &str, account: &str, secret: &[u8]) -> String {
    format!(
        "otpauth://totp/{}:{}?secret={}&issuer={}&algorithm=SHA1&digits={}&period={}",
        issuer,
        account,
        base32_encode(secret),
        issuer,
        CODE_DIGITS,
        TIME_STEP_SECS
    )
}

pub fn code_at_step(secret: &[u8], step: u64) -> String {
    let mut mac = <Hmac<Sha1> as Mac>::new_from_slice(secret).expect("HMAC accepts keys of any length");
    mac.update(&step.to_be_bytes());
    let digest = mac.finalize().into_bytes();

    let offset = (digest[digest.len() - 1] & 0x0f) as usize;
    let truncated = u32::from_be_bytes([
        digest[offset] & 0x7f,
        digest[offset + 1],
        digest[offset + 2],
        digest[offset + 3],
    ]);

    format!("{:0width$}", truncated % 10u32.pow(CODE_DIGITS), width = CODE_DIGITS as usize)
}

pub fn matching_step(secret: &[u8], code: &str, now_secs: u64, last_used_step: u64) -> Option<u64> {
    let code = code.trim();
    if code.len() != CODE_DIGITS as usize || !code.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }

    let current = now_secs / TIME_STEP_SECS;
    let earliest = current.saturating_sub(ALLOWED_DRIFT_STEPS);

    (earliest..=current + ALLOWED_DRIFT_STEPS)
        .filter(|step| *step > last_used_step)
        .find(|step| bool::from(code_at_step(secret, *step).as_bytes().ct_eq(code.as_bytes())))
}

pub fn new_recovery_codes() -> Vec<String> {
    (0..RECOVERY_CODE_COUNT)
        .map(|_| {
            let mut bytes = [0u8; 10];
            rand::rngs::OsRng.fill_bytes(&mut bytes);
            let encoded = base32_encode(&bytes).to_lowercase();
            format!("{}-{}", &encoded[..8], &encoded[8..])
        })
        .collect()
}

pub fn recovery_code_hash(code: &str) -> String {
    hex::encode(Sha256::digest(code.trim().to_lowercase().as_bytes()))
}

#[cfg(test)]
mod tests {
    use super::*;

    const RFC_SECRET: &[u8] = b"12345678901234567890";

    #[test]
    fn test_rfc6238_vectors() {
        assert_eq!(code_at_step(RFC_SECRET, 59 / 30), "287082");
        assert_eq!(code_at_step(RFC_SECRET, 1111111109 / 30), "081804");
        assert_eq!(code_at_step(RFC_SECRET, 1234567890 / 30), "005924");
        assert_eq!(code_at_step(RFC_SECRET, 2000000000 / 30), "279037");
    }

    #[test]
    fn test_rfc4648_base32_vectors() {
        assert_eq!(base32_encode(b""), "");
        assert_eq!(base32_encode(b"f"), "MY");
        assert_eq!(base32_encode(b"fo"), "MZXQ");
        assert_eq!(base32_encode(b"foo"), "MZXW6");
        assert_eq!(base32_encode(b"foob"), "MZXW6YQ");
        assert_eq!(base32_encode(b"fooba"), "MZXW6YTB");
        assert_eq!(base32_encode(b"foobar"), "MZXW6YTBOI");
    }

    #[test]
    fn test_current_code_accepted_with_one_step_of_drift() {
        let now = 1_700_000_000;
        let step = now / 30;
        for candidate in [step - 1, step, step + 1] {
            let code = code_at_step(RFC_SECRET, candidate);
            assert_eq!(matching_step(RFC_SECRET, &code, now, 0), Some(candidate));
        }
    }

    #[test]
    fn test_stale_and_malformed_codes_rejected() {
        let now = 1_700_000_000;
        let old = code_at_step(RFC_SECRET, now / 30 - 2);
        assert_eq!(matching_step(RFC_SECRET, &old, now, 0), None);
        assert_eq!(matching_step(RFC_SECRET, "12345", now, 0), None);
        assert_eq!(matching_step(RFC_SECRET, "abcdef", now, 0), None);
        assert_eq!(matching_step(RFC_SECRET, "", now, 0), None);
    }

    #[test]
    fn test_code_cannot_be_used_twice() {
        let now = 1_700_000_000;
        let code = code_at_step(RFC_SECRET, now / 30);
        let used = matching_step(RFC_SECRET, &code, now, 0).unwrap();
        assert_eq!(matching_step(RFC_SECRET, &code, now, used), None);
    }

    #[test]
    fn test_code_for_another_secret_rejected() {
        let now = 1_700_000_000;
        let code = code_at_step(b"another-secret-entirely", now / 30);
        assert_eq!(matching_step(RFC_SECRET, &code, now, 0), None);
    }

    #[test]
    fn test_recovery_codes_are_unique_and_hash_stably() {
        let codes = new_recovery_codes();
        assert_eq!(codes.len(), 10);
        let unique: std::collections::HashSet<_> = codes.iter().collect();
        assert_eq!(unique.len(), codes.len());
        assert_eq!(recovery_code_hash(&codes[0]), recovery_code_hash(&format!("  {}  ", codes[0].to_uppercase())));
    }

    #[test]
    fn test_secrets_are_random_and_long_enough() {
        let a = new_secret();
        let b = new_secret();
        assert_eq!(a.len(), 20);
        assert_ne!(a, b);
    }
}
