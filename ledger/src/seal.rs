/// Sealing: every event gets its own secret, the blind in its leaf and the key it is encrypted under both come from it
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};

use crate::Hash;

const SEED_DOMAIN: &[u8] = b"zedr/seed/v1";
const BLIND_DOMAIN: &[u8] = b"zedr/blind/v1";
const KEY_DOMAIN: &[u8] = b"zedr/key/v1";
const SALT_DOMAIN: &[u8] = b"zedr/salt/v1";

const LENGTH_BYTES: usize = 4;
const TAG_BYTES: usize = 16;

/// Sizes a padded event can take, so a ciphertext tells its size class and nothing finer
pub const BUCKETS: [usize; 8] = [256, 1024, 4096, 16384, 65536, 262144, 1048576, 4194304];

/// Largest event that fits the largest bucket
pub const MAX_EVENT_BYTES: usize = BUCKETS[BUCKETS.len() - 1] - LENGTH_BYTES;

fn prf(key: &[u8], parts: &[&[u8]]) -> Hash {
    let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(key).expect("HMAC takes a key of any length");
    for part in parts {
        mac.update(part);
    }
    mac.finalize().into_bytes().into()
}

/// The one secret of an event. It depends on the event itself, so a rolled back agent never reuses a key for other content
pub fn seed(master: &Hash, agent: &Hash, epoch: u64, index: u64, event: &[u8]) -> Hash {
    let digest: Hash = Sha256::digest(event).into();
    prf(master, &[SEED_DOMAIN, agent, &epoch.to_le_bytes(), &index.to_le_bytes(), &digest])
}

/// Blind that goes into the event's leaf
pub fn blind(seed: &Hash) -> Hash {
    prf(seed, &[BLIND_DOMAIN])
}

fn key(seed: &Hash) -> Hash {
    prf(seed, &[KEY_DOMAIN])
}

/// Salt of the state commitment at the boundary before `window`
pub fn salt(master: &Hash, agent: &Hash, window: u64) -> Hash {
    prf(master, &[SALT_DOMAIN, agent, &window.to_le_bytes()])
}

fn bound(agent: &Hash, epoch: u64, index: u64) -> Vec<u8> {
    let mut aad = Vec::with_capacity(48);
    aad.extend_from_slice(agent);
    aad.extend_from_slice(&epoch.to_le_bytes());
    aad.extend_from_slice(&index.to_le_bytes());
    aad
}

fn pad(event: &[u8]) -> Result<Vec<u8>, String> {
    let needed = event.len() + LENGTH_BYTES;
    let bucket = BUCKETS.iter().copied().find(|bucket| *bucket >= needed).ok_or_else(|| format!("An event of {} bytes is larger than any bucket", event.len()))?;
    let mut padded = Vec::with_capacity(bucket);
    padded.extend_from_slice(&(event.len() as u32).to_le_bytes());
    padded.extend_from_slice(event);
    padded.resize(bucket, 0);
    Ok(padded)
}

fn unpad(mut padded: Vec<u8>) -> Result<Vec<u8>, String> {
    if !BUCKETS.contains(&padded.len()) {
        return Err(format!("{} bytes is not a bucket size", padded.len()));
    }
    let length = u32::from_le_bytes(padded[..LENGTH_BYTES].try_into().expect("a bucket is longer than its length field")) as usize;
    let end = LENGTH_BYTES.checked_add(length).filter(|end| *end <= padded.len()).ok_or_else(|| "Padded event claims more bytes than it holds".to_string())?;
    if padded[end..].iter().any(|byte| *byte != 0) {
        return Err("Padding is not zero".to_string());
    }
    padded.truncate(end);
    padded.drain(..LENGTH_BYTES);
    Ok(padded)
}

/// Encrypts one event under its own key. The same event at the same place always seals to the same bytes
pub fn seal(seed: &Hash, agent: &Hash, epoch: u64, index: u64, event: &[u8]) -> Result<Vec<u8>, String> {
    let padded = pad(event)?;
    let cipher = ChaCha20Poly1305::new(Key::from_slice(&key(seed)));
    cipher
        .encrypt(Nonce::from_slice(&[0u8; 12]), Payload { msg: &padded, aad: &bound(agent, epoch, index) })
        .map_err(|_| "Sealing failed".to_string())
}

/// Opens a sealed event with its seed, and fails for any other seed, place or ciphertext
pub fn open(seed: &Hash, agent: &Hash, epoch: u64, index: u64, sealed: &[u8]) -> Result<Vec<u8>, String> {
    let cipher = ChaCha20Poly1305::new(Key::from_slice(&key(seed)));
    let padded = cipher
        .decrypt(Nonce::from_slice(&[0u8; 12]), Payload { msg: sealed, aad: &bound(agent, epoch, index) })
        .map_err(|_| "The seed does not open this event".to_string())?;
    unpad(padded)
}

/// Length a sealed event of this plaintext length takes
pub fn sealed_len(event_len: usize) -> Option<usize> {
    BUCKETS.iter().copied().find(|bucket| *bucket >= event_len + LENGTH_BYTES).map(|bucket| bucket + TAG_BYTES)
}

#[cfg(test)]
mod tests {
    use super::*;

    const MASTER: Hash = [1u8; 32];
    const AGENT: Hash = [2u8; 32];

    #[test]
    fn test_a_sealed_event_opens_with_its_seed_and_nothing_else() {
        let event = b"process /bin/sh -c id";
        let seed = seed(&MASTER, &AGENT, 3, 40, event);
        let sealed = seal(&seed, &AGENT, 3, 40, event).unwrap();
        assert_eq!(open(&seed, &AGENT, 3, 40, &sealed).unwrap(), event);

        let other = super::seed(&MASTER, &AGENT, 3, 41, event);
        assert!(open(&other, &AGENT, 3, 40, &sealed).is_err(), "another event's seed");
        assert!(open(&seed, &AGENT, 3, 41, &sealed).is_err(), "another index");
        assert!(open(&seed, &AGENT, 4, 40, &sealed).is_err(), "another epoch");
        assert!(open(&seed, &[9u8; 32], 3, 40, &sealed).is_err(), "another agent");
        let mut flipped = sealed.clone();
        flipped[10] ^= 1;
        assert!(open(&seed, &AGENT, 3, 40, &flipped).is_err(), "a changed ciphertext");
    }

    #[test]
    fn test_sealing_is_repeatable_so_a_resend_is_byte_identical() {
        let event = b"network 203.0.113.9:443";
        let seed = seed(&MASTER, &AGENT, 1, 7, event);
        assert_eq!(seal(&seed, &AGENT, 1, 7, event).unwrap(), seal(&seed, &AGENT, 1, 7, event).unwrap());
    }

    #[test]
    fn test_a_rolled_back_agent_that_sees_other_content_gets_another_key() {
        let before = seed(&MASTER, &AGENT, 1, 7, b"first run");
        let after = seed(&MASTER, &AGENT, 1, 7, b"second run");
        assert_ne!(before, after);
        assert_ne!(key(&before), key(&after));
        assert_ne!(blind(&before), key(&before), "the blind is public once opened, the key derives separately");
    }

    #[test]
    fn test_sealed_sizes_come_only_from_the_bucket_list() {
        for length in [0usize, 1, 251, 252, 253, 1020, 1021, 4092, 4093, 60000, 70000] {
            let event = vec![0xabu8; length];
            let seed = seed(&MASTER, &AGENT, 1, length as u64, &event);
            let sealed = seal(&seed, &AGENT, 1, length as u64, &event).unwrap();
            assert!(BUCKETS.contains(&(sealed.len() - TAG_BYTES)), "{} bytes sealed to {}", length, sealed.len());
            assert_eq!(Some(sealed.len()), sealed_len(length));
            assert_eq!(open(&seed, &AGENT, 1, length as u64, &sealed).unwrap(), event);
        }
        assert_eq!(sealed_len(252), Some(256 + TAG_BYTES));
        assert_eq!(sealed_len(253), Some(1024 + TAG_BYTES));
    }

    #[test]
    fn test_an_event_larger_than_the_largest_bucket_is_refused() {
        let event = vec![0u8; MAX_EVENT_BYTES + 1];
        let seed = seed(&MASTER, &AGENT, 1, 1, &event);
        assert!(seal(&seed, &AGENT, 1, 1, &event).is_err());
        assert_eq!(sealed_len(MAX_EVENT_BYTES + 1), None);
        assert!(sealed_len(MAX_EVENT_BYTES).is_some());
    }

    #[test]
    fn test_padding_that_is_not_what_pad_wrote_is_refused() {
        let mut padded = pad(b"abc").unwrap();
        assert_eq!(unpad(padded.clone()).unwrap(), b"abc");
        padded[200] = 1;
        assert!(unpad(padded.clone()).is_err(), "non-zero padding");
        padded[200] = 0;
        padded[..4].copy_from_slice(&(1000u32).to_le_bytes());
        assert!(unpad(padded).is_err(), "a length past the bucket");
        assert!(unpad(vec![0u8; 100]).is_err(), "not a bucket size");
    }

    #[test]
    fn test_salts_differ_per_window_and_agent() {
        assert_ne!(salt(&MASTER, &AGENT, 1), salt(&MASTER, &AGENT, 2));
        assert_ne!(salt(&MASTER, &AGENT, 1), salt(&MASTER, &[9u8; 32], 1));
    }
}
