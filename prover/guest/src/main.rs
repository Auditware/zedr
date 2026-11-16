use risc0_zkvm::guest::env;
use std::io::Read;
use zedr_rules::proof::{run, Input};

fn main() {
    let mut bytes = Vec::new();
    env::stdin().read_to_end(&mut bytes).expect("the input is readable");
    let input = Input::from_bytes(&bytes).expect("the input is a canonical proof input");
    let (journal, _) = run(input).expect("the windows replay");
    env::commit_slice(&journal.to_bytes());
}
