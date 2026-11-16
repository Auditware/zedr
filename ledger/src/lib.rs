/// zedr Ledger
///
/// Commitments over sealed telemetry: one blinded leaf per event, one root per window, and a head that chains the windows
use borsh::{BorshDeserialize, BorshSerialize};
use sha2::{Digest, Sha256};

#[cfg(feature = "seal")]
pub mod seal;

pub type Hash = [u8; 32];

/// Head an agent's chain starts from, before its first window
pub const GENESIS: Hash = [0u8; 32];

const LEAF_PREFIX: u8 = 0x00;
const NODE_PREFIX: u8 = 0x01;
const LEAF_DOMAIN: &[u8] = b"zedr/leaf/v1";
const HEAD_DOMAIN: &[u8] = b"zedr/head/v1";
const STATE_DOMAIN: &[u8] = b"zedr/state/v1";

const FRESH: u8 = 0b01;
const GAP: u8 = 0b10;

/// Commitment to one event, hiding as long as the blind stays secret
pub fn leaf(agent: &Hash, epoch: u64, index: u64, blind: &Hash, event: &[u8]) -> Hash {
    let mut hasher = Sha256::new();
    hasher.update([LEAF_PREFIX]);
    hasher.update(LEAF_DOMAIN);
    hasher.update(agent);
    hasher.update(epoch.to_le_bytes());
    hasher.update(index.to_le_bytes());
    hasher.update(blind);
    hasher.update(event);
    hasher.finalize().into()
}

/// Merkle tree hash over the leaves of one window, shaped as in RFC 6962
pub fn root(leaves: &[Hash]) -> Hash {
    match leaves.len() {
        0 => Sha256::digest([]).into(),
        1 => leaves[0],
        count => {
            let split = count.next_power_of_two() / 2;
            let mut hasher = Sha256::new();
            hasher.update([NODE_PREFIX]);
            hasher.update(root(&leaves[..split]));
            hasher.update(root(&leaves[split..]));
            hasher.finalize().into()
        }
    }
}

/// Commitment to the rule state at a window boundary, the salt keeps a small state from being guessed
pub fn state_commitment(salt: &Hash, state: &[u8]) -> Hash {
    let mut hasher = Sha256::new();
    hasher.update(STATE_DOMAIN);
    hasher.update(salt);
    hasher.update(state);
    hasher.finalize().into()
}

/// What an agent publishes about one sealed window
#[derive(Debug, Clone, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct WindowHeader {
    pub epoch: u64,
    pub window: u64,
    pub first_index: u64,
    pub count: u32,
    /// First window of an epoch, the rule state starts empty
    pub fresh: bool,
    /// Events were lost before this window, the chain says so instead of hiding it
    pub gap: bool,
    pub prev_head: Hash,
    pub root: Hash,
    pub head: Hash,
}

impl WindowHeader {
    #[allow(clippy::too_many_arguments)]
    pub fn seal(agent: &Hash, epoch: u64, window: u64, first_index: u64, fresh: bool, gap: bool, prev_head: Hash, leaves: &[Hash]) -> Result<Self, String> {
        let count = u32::try_from(leaves.len()).map_err(|_| "A window holds at most u32::MAX events".to_string())?;
        let root = root(leaves);
        let mut header = WindowHeader { epoch, window, first_index, count, fresh, gap, prev_head, root, head: GENESIS };
        header.head = header.expected_head(agent);
        Ok(header)
    }

    /// Head these fields chain to for this agent, from the previous head
    pub fn expected_head(&self, agent: &Hash) -> Hash {
        let mut flags = 0u8;
        if self.fresh {
            flags |= FRESH;
        }
        if self.gap {
            flags |= GAP;
        }
        let mut hasher = Sha256::new();
        hasher.update(HEAD_DOMAIN);
        hasher.update(agent);
        hasher.update(self.prev_head);
        hasher.update(self.epoch.to_le_bytes());
        hasher.update(self.window.to_le_bytes());
        hasher.update(self.first_index.to_le_bytes());
        hasher.update(self.count.to_le_bytes());
        hasher.update([flags]);
        hasher.update(self.root);
        hasher.finalize().into()
    }

    /// Checks the header against the agent it belongs to and the leaves it claims to cover
    pub fn verify(&self, agent: &Hash, leaves: &[Hash]) -> Result<(), String> {
        if leaves.len() != self.count as usize {
            return Err(format!("Window {} claims {} events and carries {}", self.window, self.count, leaves.len()));
        }
        if root(leaves) != self.root {
            return Err(format!("Window {} root does not match its leaves", self.window));
        }
        if self.expected_head(agent) != self.head {
            return Err(format!("Window {} head does not match its fields", self.window));
        }
        Ok(())
    }

    /// Index the next window starts at
    pub fn next_index(&self) -> u64 {
        self.first_index + u64::from(self.count)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const AGENT: Hash = [7u8; 32];

    fn numbered(count: u8) -> Vec<Hash> {
        (0..count).map(|n| leaf(&[7u8; 32], 1, u64::from(n), &[9u8; 32], &[n])).collect()
    }

    #[test]
    fn test_leaf_matches_an_independent_sha256() {
        let found = leaf(&[1u8; 32], 2, 3, &[4u8; 32], b"event");
        assert_eq!(hex::encode(found), "1397c7070a2ea7c829b78ec05e562ce4f42ca275f5d94eb5b24ac49f4a6fe732");
    }

    #[test]
    fn test_root_matches_an_independent_merkle_tree() {
        let leaves = numbered(5);
        assert_eq!(hex::encode(root(&leaves[..0])), "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
        assert_eq!(root(&leaves[..1]), leaves[0]);
        assert_eq!(hex::encode(root(&leaves[..2])), "54e3f3edf5705cde440f121a5e1adb2507218fd86068b44e737a252677b97992");
        assert_eq!(hex::encode(root(&leaves[..3])), "d07de305101953673a46dcc9b4e579d75eb6972a397234e0fd9c20508e7c7978");
        assert_eq!(hex::encode(root(&leaves)), "4cd25189fced05cb971642627252965c36ceb868b13ba8e873178cf5072e6d1d");
    }

    #[test]
    fn test_every_field_of_a_leaf_changes_it() {
        let base = leaf(&[1u8; 32], 2, 3, &[4u8; 32], b"event");
        assert_ne!(base, leaf(&[0u8; 32], 2, 3, &[4u8; 32], b"event"));
        assert_ne!(base, leaf(&[1u8; 32], 9, 3, &[4u8; 32], b"event"));
        assert_ne!(base, leaf(&[1u8; 32], 2, 9, &[4u8; 32], b"event"));
        assert_ne!(base, leaf(&[1u8; 32], 2, 3, &[0u8; 32], b"event"));
        assert_ne!(base, leaf(&[1u8; 32], 2, 3, &[4u8; 32], b"other"));
    }

    #[test]
    fn test_a_sealed_window_verifies_and_any_change_is_caught() {
        let leaves = numbered(4);
        let header = WindowHeader::seal(&AGENT, 1, 10, 100, true, false, GENESIS, &leaves).unwrap();
        header.verify(&AGENT, &leaves).unwrap();
        assert!(header.verify(&[8u8; 32], &leaves).is_err(), "another agent's window");
        assert_eq!(header.next_index(), 104);

        let mut reordered = leaves.clone();
        reordered.swap(0, 1);
        assert!(header.verify(&AGENT, &reordered).is_err(), "order is part of the commitment");
        assert!(header.verify(&AGENT, &leaves[..3]).is_err(), "a dropped event changes the count");

        for change in [
            WindowHeader { epoch: 2, ..header.clone() },
            WindowHeader { window: 11, ..header.clone() },
            WindowHeader { first_index: 101, ..header.clone() },
            WindowHeader { fresh: false, ..header.clone() },
            WindowHeader { gap: true, ..header.clone() },
            WindowHeader { prev_head: [1u8; 32], ..header.clone() },
        ] {
            assert!(change.verify(&AGENT, &leaves).is_err(), "a changed field no longer matches the head: {:?}", change);
        }
    }

    #[test]
    fn test_windows_chain_through_their_heads() {
        let first = WindowHeader::seal(&AGENT, 1, 0, 0, true, false, GENESIS, &numbered(2)).unwrap();
        let second = WindowHeader::seal(&AGENT, 1, 1, first.next_index(), false, false, first.head, &numbered(3)).unwrap();
        assert_eq!(second.prev_head, first.head);
        assert_ne!(second.head, WindowHeader::seal(&AGENT, 1, 1, 2, false, false, GENESIS, &numbered(3)).unwrap().head);
    }

    #[test]
    fn test_an_empty_window_still_advances_the_chain() {
        let empty = WindowHeader::seal(&AGENT, 1, 5, 40, false, false, [3u8; 32], &[]).unwrap();
        empty.verify(&AGENT, &[]).unwrap();
        assert_ne!(
            empty.head,
            WindowHeader::seal(&[8u8; 32], 1, 5, 40, false, false, [3u8; 32], &[]).unwrap().head,
            "an empty window is still bound to its agent"
        );
        assert_eq!(empty.next_index(), 40);
        assert_ne!(empty.head, empty.prev_head);
    }

    #[test]
    fn test_state_commitment_depends_on_salt_and_state() {
        let base = state_commitment(&[1u8; 32], b"state");
        assert_ne!(base, state_commitment(&[2u8; 32], b"state"));
        assert_ne!(base, state_commitment(&[1u8; 32], b"other"));
    }
}
