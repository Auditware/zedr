fn main() {
    println!("cargo:rerun-if-env-changed=ZEDR_GUEST_BIN");
    let path = std::env::var("ZEDR_GUEST_BIN").unwrap_or_else(|_| panic!("ZEDR_GUEST_BIN must point at the built guest program, run `make guest` first"));
    assert!(std::path::Path::new(&path).is_file(), "ZEDR_GUEST_BIN={} is not a file", path);
    println!("cargo:rerun-if-changed={}", path);
}
