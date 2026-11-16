use regex_automata::dfa::{dense, StartKind};
use regex_automata::nfa::thompson;
use regex_automata::util::syntax;
use std::fmt::Write;
use std::path::PathBuf;

include!("src/pattern_list.rs");

fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed=src/pattern_list.rs");

    let out = PathBuf::from(std::env::var("OUT_DIR").expect("cargo sets OUT_DIR"));
    let mut tables = String::new();
    for (name, alternatives) in PATTERNS {
        writeln!(tables, "static {}: &[&Aligned<[u8]>] = &[", name.to_uppercase()).unwrap();
        for (position, pattern) in alternatives.iter().enumerate() {
            let dfa = dense::Builder::new()
                .configure(dense::Config::new().minimize(true).start_kind(StartKind::Unanchored))
                .syntax(syntax::Config::new().unicode(false).utf8(false))
                .thompson(thompson::Config::new().utf8(false))
                .build(pattern)
                .unwrap_or_else(|e| panic!("alternative {} of {} does not compile to a table: {}", position, name, e));
            let (bytes, padding) = dfa.to_bytes_little_endian();
            let file = format!("{}_{}.dfa", name, position);
            std::fs::write(out.join(&file), &bytes[padding..]).expect("the table is written to OUT_DIR");
            writeln!(tables, "    &Aligned {{ _align: [], bytes: *include_bytes!(concat!(env!(\"OUT_DIR\"), \"/{}\")) }},", file).unwrap();
        }
        writeln!(tables, "];").unwrap();
    }
    std::fs::write(out.join("tables.rs"), tables).expect("the table list is written to OUT_DIR");
}
