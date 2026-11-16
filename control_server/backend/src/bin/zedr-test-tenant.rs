//! The control server of a test tenant. It takes the journal an endpoint states for a proof, so a simulated fleet
//! shows every proof state at once and nobody waits for a prover. Nothing is proven here, and the console says so.
//! A deployment runs zedr-control-server, which has no such path, and the release image holds only that.
use std::sync::Arc;

use zedr_control_server::proofs::{ReceiptVerifier, Verified};
use zedr_ledger::Hash;

struct StatedJournals;

impl ReceiptVerifier for StatedJournals {
    fn verify(&self, receipt: &[u8]) -> Result<Verified, String> {
        if receipt.is_empty() {
            return Err("An empty statement says nothing".to_string());
        }
        Ok(Verified { image_id: [0u8; 32], journal: receipt.to_vec() })
    }

    fn image_ids(&self) -> Vec<Hash> {
        Vec::new()
    }

    fn stands_in(&self) -> bool {
        true
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    zedr_control_server::server::run(Some(Arc::new(StatedJournals))).await
}
