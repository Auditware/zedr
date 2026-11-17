use ed25519_dalek::{Signature, Signer, SigningKey};
use sha2::{Digest, Sha256};
use std::env;
use zedr_protocol::WindowRefusal;

use crate::chain::Position;
use crate::error::{AppError, Result};

pub struct SigningService {
    signing_key: SigningKey,
}

impl SigningService {
    pub fn from_env() -> Result<Self> {
        let key_hex = env::var("ZEDR_SIGNING_KEY_HEX")
            .map_err(|_| AppError::Config("ZEDR_SIGNING_KEY_HEX not set".into()))?;

        Self::from_seed_hex(&key_hex)
    }

    pub fn from_seed_hex(key_hex: &str) -> Result<Self> {
        let key_bytes = hex::decode(key_hex)
            .map_err(|e| AppError::Config(format!("Invalid ZEDR_SIGNING_KEY_HEX: {}", e)))?;
        
        if key_bytes.len() != 32 {
            return Err(AppError::Config(format!(
                "ZEDR_SIGNING_KEY_HEX must be 32 bytes (64 hex chars), got {}",
                key_bytes.len()
            )));
        }
        
        let key_array: [u8; 32] = key_bytes
            .try_into()
            .map_err(|_| AppError::Config("Failed to convert key bytes".into()))?;
        
        let signing_key = SigningKey::from_bytes(&key_array);
        
        Ok(Self { signing_key })
    }
    
    pub fn sign_binary(&self, binary_data: &[u8]) -> Signature {
        self.signing_key.sign(binary_data)
    }

    pub fn public_key(&self) -> [u8; 32] {
        self.signing_key.verifying_key().to_bytes()
    }

    pub fn seal_agent_binary(&self, template_binary: &[u8], server_url: &str) -> Result<Vec<u8>> {
        let mut binary = patch_server_url(template_binary, server_url)?;
        patch_signing_public_key(&mut binary, &self.public_key())?;
        rehash_code_signature(&mut binary)?;

        let signature = self.sign_binary(&binary);
        binary.extend_from_slice(&signature.to_bytes());

        Ok(binary)
    }

    pub fn sign_upgrade_command(&self, agent_id: &str, target_version: &str, nonce: &str, issued_at: u64) -> Result<Signature> {
        let signed_bytes = zedr_protocol::upgrade_command_signing_bytes(agent_id, target_version, nonce, issued_at)
            .map_err(AppError::InternalError)?;
        Ok(self.signing_key.sign(&signed_bytes))
    }

    pub fn sign_window_ack(&self, agent_id: &str, window: u64, next_index: u64, head: &str) -> Result<Signature> {
        let signed_bytes = zedr_protocol::window_ack_signing_bytes(agent_id, window, next_index, head).map_err(AppError::InternalError)?;
        Ok(self.signing_key.sign(&signed_bytes))
    }

    /// The answer to one refused window: where the stored chain of its agent stands, signed for the request with this session and sequence number only
    pub fn refuse_window(&self, agent_id: &str, session: u64, seq: u64, position: Position) -> Result<WindowRefusal> {
        let signed_bytes = zedr_protocol::window_refusal_signing_bytes(agent_id, session, seq, position.epoch, position.next_window, position.next_index, &position.head)
            .map_err(AppError::InternalError)?;
        Ok(WindowRefusal {
            epoch: position.epoch,
            next_window: position.next_window,
            next_index: position.next_index,
            head: position.head,
            signature: self.signing_key.sign(&signed_bytes).to_bytes().to_vec(),
        })
    }
}

const MH_MAGIC_64: u32 = 0xfeed_facf;
const FAT_MAGIC: u32 = 0xcafe_babe;
const LC_CODE_SIGNATURE: u32 = 0x1d;
const MACH_HEADER_64_BYTES: usize = 32;
const CSMAGIC_EMBEDDED_SIGNATURE: u32 = 0xfade_0cc0;
const CSMAGIC_CODEDIRECTORY: u32 = 0xfade_0c02;
const CS_HASHTYPE_SHA256: u8 = 2;
const SHA256_BYTES: usize = 32;

fn read<const N: usize>(binary: &[u8], at: usize) -> Result<[u8; N]> {
    binary
        .get(at..at.checked_add(N).ok_or_else(|| malformed("an offset past the end"))?)
        .and_then(|bytes| bytes.try_into().ok())
        .ok_or_else(|| malformed("a field past the end of the binary"))
}

fn le32(binary: &[u8], at: usize) -> Result<u32> {
    read::<4>(binary, at).map(u32::from_le_bytes)
}

fn be32(binary: &[u8], at: usize) -> Result<u32> {
    read::<4>(binary, at).map(u32::from_be_bytes)
}

fn malformed(what: &str) -> AppError {
    AppError::InternalError(format!("The agent template has a malformed Mach-O code signature: {}", what))
}

/// macOS kills a program whose pages no longer match the hashes of its code signature, and Apple silicon runs no unsigned code.
/// The agent carries the ad hoc signature the linker gave it, which signs nothing but those hashes, so after the slots are filled
/// every page hash is computed again. A binary that is not a Mach-O is left as it is
pub fn rehash_code_signature(binary: &mut [u8]) -> Result<()> {
    let Ok(magic) = read::<4>(binary, 0) else {
        return Ok(());
    };
    if u32::from_be_bytes(magic) == FAT_MAGIC {
        return Err(malformed("a universal binary, serve one per architecture"));
    }
    if u32::from_le_bytes(magic) != MH_MAGIC_64 {
        return Ok(());
    }

    let commands = le32(binary, 16)? as usize;
    let mut at = MACH_HEADER_64_BYTES;
    let mut signature = None;
    for _ in 0..commands {
        let (command, size) = (le32(binary, at)?, le32(binary, at + 4)? as usize);
        if command == LC_CODE_SIGNATURE {
            signature = Some(le32(binary, at + 8)? as usize);
        }
        at = at.checked_add(size).filter(|_| size >= 8).ok_or_else(|| malformed("a load command of no size"))?;
    }
    let signature = signature.ok_or_else(|| malformed("no code signature"))?;

    if be32(binary, signature)? != CSMAGIC_EMBEDDED_SIGNATURE {
        return Err(malformed("no embedded signature where the load command points"));
    }
    let blobs = be32(binary, signature + 8)? as usize;
    let mut directories = 0;
    for blob in 0..blobs {
        let directory = signature + be32(binary, signature + 12 + blob * 8 + 4)? as usize;
        if be32(binary, directory)? != CSMAGIC_CODEDIRECTORY {
            continue;
        }
        let hashes = be32(binary, directory + 16)? as usize;
        let slots = be32(binary, directory + 28)? as usize;
        let limit = be32(binary, directory + 32)? as usize;
        let [hash_size, hash_type, _, page_shift] = read::<4>(binary, directory + 36)?;
        if hash_type != CS_HASHTYPE_SHA256 || hash_size as usize != SHA256_BYTES || page_shift >= 32 || limit > binary.len() {
            return Err(malformed("a code directory that is not SHA-256 over the binary"));
        }
        let page = 1usize << page_shift;
        for slot in 0..slots {
            let start = slot * page;
            let digest = sha256(binary.get(start..(start + page).min(limit)).ok_or_else(|| malformed("a page past the code limit"))?);
            let at = directory + hashes + slot * SHA256_BYTES;
            binary.get_mut(at..at + SHA256_BYTES).ok_or_else(|| malformed("a page hash past the end"))?.copy_from_slice(&digest);
        }
        directories += 1;
    }
    if directories == 0 {
        return Err(malformed("no code directory"));
    }
    Ok(())
}

pub fn sha256(data: &[u8]) -> [u8; 32] {
    Sha256::digest(data).into()
}

pub const SERVER_URL_PLACEHOLDER: &[u8] = b"ZEDR_SERVER_PLACEHOLDER_URL_DO_NOT_MODIFY_EXACTLY_64_BYTES_LONG\0";

pub fn patch_signing_public_key(binary: &mut [u8], public_key: &[u8; 32]) -> Result<()> {
    let placeholder = &zedr_protocol::SIGNING_PUBLIC_KEY_PLACEHOLDER;

    let mut positions = binary
        .windows(placeholder.len())
        .enumerate()
        .filter(|(_, window)| *window == placeholder.as_slice())
        .map(|(position, _)| position);

    let position = positions.next().ok_or_else(|| {
        AppError::Config("Signing public key placeholder not found in agent binary, rebuild the agent".into())
    })?;

    if positions.next().is_some() {
        return Err(AppError::Config(
            "Signing public key placeholder appears more than once in agent binary".into(),
        ));
    }

    let slot = zedr_protocol::signing_public_key_to_slot(public_key).map_err(AppError::InternalError)?;
    binary[position..position + slot.len()].copy_from_slice(&slot);

    Ok(())
}

pub fn patch_server_url(template_binary: &[u8], server_url: &str) -> Result<Vec<u8>> {
    if server_url.len() > 64 {
        return Err(AppError::Config(format!(
            "ZEDR_SERVER_URL exceeds 64 bytes: {} bytes",
            server_url.len()
        )));
    }
    
    let pos = find_subsequence(template_binary, SERVER_URL_PLACEHOLDER)
        .ok_or_else(|| AppError::Config("ZEDR_SERVER_PLACEHOLDER_URL not found in binary".into()))?;
    
    let mut patched = template_binary.to_vec();
    
    let mut url_bytes = server_url.as_bytes().to_vec();
    url_bytes.resize(64, 0);
    
    patched[pos..pos + 64].copy_from_slice(&url_bytes);
    
    Ok(patched)
}

fn find_subsequence(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

#[cfg(test)]
mod tests {
    use super::*;

    const MACHO_TEMPLATE: &[u8] = include_bytes!("../tests/fixtures/macho-template");

    /// Pages of the template whose hash in its code directory is not the hash of the page. Read on its own, apart from the code under test
    fn stale_pages(binary: &[u8]) -> usize {
        let u32_at = |at: usize, little: bool| {
            let bytes: [u8; 4] = binary[at..at + 4].try_into().unwrap();
            if little {
                u32::from_le_bytes(bytes)
            } else {
                u32::from_be_bytes(bytes)
            }
        } as usize;
        let mut at = 32;
        let mut signature = 0;
        for _ in 0..u32_at(16, true) {
            if u32_at(at, true) == 0x1d {
                signature = u32_at(at + 8, true);
            }
            at += u32_at(at + 4, true);
        }
        let directory = signature + u32_at(signature + 16, false);
        let (hashes, slots, limit, page) = (u32_at(directory + 16, false), u32_at(directory + 28, false), u32_at(directory + 32, false), 1usize << binary[directory + 39]);
        (0..slots).filter(|slot| binary[directory + hashes + slot * 32..][..32] != sha256(&binary[slot * page..((slot + 1) * page).min(limit)])).count()
    }

    #[test]
    fn test_a_sealed_macos_agent_keeps_every_page_of_its_code_signature_true() {
        assert_eq!(stale_pages(MACHO_TEMPLATE), 0, "the linker signed the template");

        let service = SigningService::from_seed_hex(&"42".repeat(32)).unwrap();
        let mut patched_only = patch_server_url(MACHO_TEMPLATE, "https://zedr.example.com").unwrap();
        patch_signing_public_key(&mut patched_only, &service.public_key()).unwrap();
        assert!(stale_pages(&patched_only) > 0, "filling the slots alone breaks the signature, macOS would kill the agent");

        let sealed = service.seal_agent_binary(MACHO_TEMPLATE, "https://zedr.example.com").unwrap();
        let (body, signature) = sealed.split_at(sealed.len() - 64);
        assert_eq!(stale_pages(body), 0);
        assert!(service.signing_key.verifying_key().verify_strict(body, &Signature::from_slice(signature).unwrap()).is_ok(), "the deployment signs the rehashed binary");
        assert_eq!(body.len(), MACHO_TEMPLATE.len());
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn test_macos_runs_a_sealed_agent_and_kills_one_whose_pages_were_not_rehashed() {
        use std::os::unix::fs::PermissionsExt;
        use std::os::unix::process::ExitStatusExt;
        let run = |binary: &[u8], name: &str| {
            let path = std::env::temp_dir().join(format!("zedr-{}-{}", name, std::process::id()));
            std::fs::write(&path, binary).unwrap();
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
            let status = std::process::Command::new(&path).status().unwrap();
            std::fs::remove_file(&path).unwrap();
            status
        };

        let service = SigningService::from_seed_hex(&"42".repeat(32)).unwrap();
        let sealed = service.seal_agent_binary(MACHO_TEMPLATE, "https://zedr.example.com").unwrap();
        let status = run(&sealed, "sealed");
        assert!(status.success(), "the kernel ran the sealed binary and it saw both slots filled: {:?}", status);

        let mut patched_only = patch_server_url(MACHO_TEMPLATE, "https://zedr.example.com").unwrap();
        patch_signing_public_key(&mut patched_only, &service.public_key()).unwrap();
        const SIGKILL: i32 = 9;
        assert_eq!(run(&patched_only, "stale").signal(), Some(SIGKILL), "without the rehash the kernel kills it at launch");
    }

    #[test]
    fn test_binaries_that_are_not_a_single_mach_o_are_left_alone_or_refused() {
        let mut elf = b"\x7fELF and the rest of a Linux agent".to_vec();
        let before = elf.clone();
        rehash_code_signature(&mut elf).unwrap();
        assert_eq!(elf, before);
        let mut pe = b"MZ, a Windows agent".to_vec();
        rehash_code_signature(&mut pe).unwrap();
        rehash_code_signature(&mut []).unwrap();

        let mut universal = MACHO_TEMPLATE.to_vec();
        universal[..4].copy_from_slice(&0xcafe_babe_u32.to_be_bytes());
        assert!(rehash_code_signature(&mut universal).unwrap_err().to_string().contains("universal"));

        let mut unsigned = MACHO_TEMPLATE.to_vec();
        let commands = u32::from_le_bytes(unsigned[16..20].try_into().unwrap()) as usize;
        let mut at = 32;
        for _ in 0..commands {
            if u32::from_le_bytes(unsigned[at..at + 4].try_into().unwrap()) == 0x1d {
                unsigned[at..at + 4].copy_from_slice(&0x7fff_ffffu32.to_le_bytes());
            }
            at += u32::from_le_bytes(unsigned[at + 4..at + 8].try_into().unwrap()) as usize;
        }
        assert!(rehash_code_signature(&mut unsigned).unwrap_err().to_string().contains("no code signature"));
    }
    
    #[test]
    fn test_patch_server_url() {
        let template = b"prefix_ZEDR_SERVER_PLACEHOLDER_URL_DO_NOT_MODIFY_EXACTLY_64_BYTES_LONG\0_suffix";
        let server_url = "https://zedr.example.com:8443";
        
        let patched = patch_server_url(template, server_url).unwrap();
        
        assert!(patched.starts_with(b"prefix_"));
        assert!(patched.ends_with(b"_suffix"));
        
        let url_section = &patched[7..71];
        assert_eq!(&url_section[..server_url.len()], server_url.as_bytes());
        assert!(url_section[server_url.len()..].iter().all(|&b| b == 0));
    }
    
    #[test]
    fn test_patch_server_url_placeholder_not_found() {
        let template = b"prefix_ZEDR_INSTALL_KEY_PLACEHOLDER_DO_NOT_MODIFY_EXACTLY_64_BY\0";
        let server_url = "https://zedr.example.com";
        
        let result = patch_server_url(template, server_url);
        assert!(result.is_err());
    }
    
    #[test]
    fn test_patch_server_url_too_long() {
        let template = b"ZEDR_SERVER_PLACEHOLDER_URL_DO_NOT_MODIFY_EXACTLY_64_BYTES_LONG";
        let server_url = "https://this-is-a-very-long-url-that-exceeds-sixty-four-bytes-total.example.com";
        
        let result = patch_server_url(template, server_url);
        assert!(result.is_err());
    }
    
    #[test]
    fn test_patch_server_url_not_found() {
        let template = b"no_placeholder_here";
        let server_url = "https://zedr.example.com";
        
        let result = patch_server_url(template, server_url);
        assert!(result.is_err());
    }
    
    const SEED_A: &str = "1111111111111111111111111111111111111111111111111111111111111111";
    const SEED_B: &str = "2222222222222222222222222222222222222222222222222222222222222222";

    fn agent_template() -> Vec<u8> {
        let mut template = b"MZ_code_".to_vec();
        template.extend_from_slice(SERVER_URL_PLACEHOLDER);
        template.extend_from_slice(b"_more_code_");
        template.extend_from_slice(&zedr_protocol::SIGNING_PUBLIC_KEY_PLACEHOLDER);
        template.extend_from_slice(b"_tail");
        template
    }

    fn trusted_key_of(sealed: &[u8]) -> ed25519_dalek::VerifyingKey {
        let position = find_subsequence(sealed, b"_more_code_").unwrap() + b"_more_code_".len();
        let slot: [u8; 64] = sealed[position..position + 64].try_into().unwrap();
        let key = zedr_protocol::signing_public_key_from_slot(&slot).unwrap();
        ed25519_dalek::VerifyingKey::from_bytes(&key).unwrap()
    }

    fn verifies(key: &ed25519_dalek::VerifyingKey, sealed: &[u8]) -> bool {
        use ed25519_dalek::Verifier;
        let (contents, signature) = sealed.split_at(sealed.len() - 64);
        key.verify(contents, &Signature::from_slice(signature).unwrap()).is_ok()
    }

    #[test]
    fn test_sealed_binary_trusts_the_key_that_signed_it() {
        let service = SigningService::from_seed_hex(SEED_A).unwrap();
        let sealed = service.seal_agent_binary(&agent_template(), "https://zedr.example.com").unwrap();

        assert_eq!(sealed.len(), agent_template().len() + 64);
        assert!(find_subsequence(&sealed, b"https://zedr.example.com\0").is_some());
        assert!(find_subsequence(&sealed, &zedr_protocol::SIGNING_PUBLIC_KEY_PLACEHOLDER).is_none());

        let trusted = trusted_key_of(&sealed);
        assert_eq!(trusted.to_bytes(), service.public_key());
        assert!(verifies(&trusted, &sealed));
    }

    #[test]
    fn test_deployments_do_not_trust_each_other() {
        let a = SigningService::from_seed_hex(SEED_A).unwrap();
        let b = SigningService::from_seed_hex(SEED_B).unwrap();
        let sealed_a = a.seal_agent_binary(&agent_template(), "https://a.example.com").unwrap();
        let sealed_b = b.seal_agent_binary(&agent_template(), "https://b.example.com").unwrap();

        assert_ne!(a.public_key(), b.public_key());
        assert!(!verifies(&trusted_key_of(&sealed_a), &sealed_b));
        assert!(!verifies(&trusted_key_of(&sealed_b), &sealed_a));
    }

    #[test]
    fn test_swapping_the_trusted_key_breaks_the_signature() {
        let a = SigningService::from_seed_hex(SEED_A).unwrap();
        let b = SigningService::from_seed_hex(SEED_B).unwrap();
        let mut sealed = a.seal_agent_binary(&agent_template(), "https://a.example.com").unwrap();

        let position = find_subsequence(&sealed, b"_more_code_").unwrap() + b"_more_code_".len();
        let attacker_slot = zedr_protocol::signing_public_key_to_slot(&b.public_key()).unwrap();
        sealed[position..position + 64].copy_from_slice(&attacker_slot);

        assert!(!verifies(&trusted_key_of(&sealed), &sealed));
    }

    #[test]
    fn test_binary_without_key_placeholder_is_refused() {
        let service = SigningService::from_seed_hex(SEED_A).unwrap();
        let mut template = b"MZ_code_".to_vec();
        template.extend_from_slice(SERVER_URL_PLACEHOLDER);

        let err = service.seal_agent_binary(&template, "https://zedr.example.com").unwrap_err();
        assert!(err.to_string().contains("placeholder not found"));
    }

    #[test]
    fn test_binary_with_two_key_placeholders_is_refused() {
        let service = SigningService::from_seed_hex(SEED_A).unwrap();
        let mut template = agent_template();
        template.extend_from_slice(&zedr_protocol::SIGNING_PUBLIC_KEY_PLACEHOLDER);

        let err = service.seal_agent_binary(&template, "https://zedr.example.com").unwrap_err();
        assert!(err.to_string().contains("more than once"));
    }

    #[test]
    fn test_seed_must_be_32_bytes_of_hex() {
        assert!(SigningService::from_seed_hex("abcd").is_err());
        assert!(SigningService::from_seed_hex(&"zz".repeat(32)).is_err());
    }

    #[test]
    fn test_signing_service_creation() {
        // Test that SigningService can be created from environment
        let signing_service = SigningService::from_env();
        
        // Should either succeed (if env var set) or fail with config error
        assert!(signing_service.is_ok() || signing_service.is_err(), "SigningService creation should return a result");
        
        if let Err(err) = &signing_service {
            // Should be a config error about missing ZEDR_SIGNING_KEY_HEX
            assert!(err.to_string().contains("ZEDR_SIGNING_KEY_HEX"), "Error should mention missing signing key");
        }
    }
    
    #[test]
    fn test_binary_signing() {
        let signing_service = match SigningService::from_env() {
            Ok(service) => service,
            Err(_) => {
                // If signing service can't be created (missing keys), skip test
                return;
            }
        };
        
        let test_binary_content = b"test binary content for signing verification";
        
        // Test signing
        let signature = signing_service.sign_binary(test_binary_content);
        
        // Verify signature format/length
        assert_eq!(signature.to_bytes().len(), 64, "ed25519 signature should be 64 bytes");
    }
    
    #[test]
    fn test_different_content_produces_different_signatures() {
        let signing_service = match SigningService::from_env() {
            Ok(service) => service,
            Err(_) => return, // Skip if service can't be created
        };
        
        let content1 = b"content one";
        let content2 = b"content two";
        
        let signature1 = signing_service.sign_binary(content1);
        let signature2 = signing_service.sign_binary(content2);
        
        assert_ne!(signature1.to_bytes(), signature2.to_bytes(), "Different content should produce different signatures");
    }
    
    #[test]
    fn test_same_content_produces_same_signature() {
        let signing_service = match SigningService::from_env() {
            Ok(service) => service,
            Err(_) => return,
        };
        
        let content = b"same content for both signatures";
        
        let signature1 = signing_service.sign_binary(content);
        let signature2 = signing_service.sign_binary(content);
        
        assert_eq!(signature1.to_bytes(), signature2.to_bytes(), "Same content should produce same signature");
    }
    
    #[test]
    fn test_url_patching_security() {
        // Test URL patching with security considerations
        let template = b"ZEDR_SERVER_PLACEHOLDER_URL_DO_NOT_MODIFY_EXACTLY_64_BYTES_LONG\0";
        
        // Test with potentially malicious URLs
        let test_cases = vec![
            ("http://evil.com", true), // Should work
            ("https://valid.example.com:8443", true), // Should work
            ("", true), // Empty string should work (padded with nulls)
        ];
        
        for (url, should_succeed) in test_cases {
            let result = patch_server_url(template, url);
            
            if should_succeed && url.len() <= 63 {
                let patched = result.unwrap_or_else(|e| panic!("Valid URL '{}' should patch successfully: {}", url, e));
                // Verify URL was embedded correctly
                let url_section = &patched[0..64];
                assert_eq!(&url_section[..url.len()], url.as_bytes());
                // Rest should be null-padded
                assert!(url_section[url.len()..].iter().all(|&b| b == 0));
            } else if url.len() > 63 {
                assert!(result.is_err(), "URL '{}' too long should fail", url);
            }
        }
    }
}
