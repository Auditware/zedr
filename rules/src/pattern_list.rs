// Read by build.rs, which turns each alternative into a matching table, and by the tests that hold the tables to the patterns.
// A pattern matches when any of its alternatives does. Alternatives are kept apart because one table for all of them grows with their product.
// These are byte patterns: case folding, \b, \s and \w are ASCII, so every build matches the same way.
pub const PATTERNS: &[(&str, &[&str])] = &[
    ("writable", &[r"(?i)\\users\\public\\|\\appdata\\local\\temp\\|\\windows\\temp\\|\\downloads\\|^/tmp/|\s/tmp/|/dev/shm/|/var/tmp/|/downloads/"]),
    ("dropped", &[r"(?i)\.(dll|exe|sys|scr|ps1|vbs|jse?|bat|cmd|hta|lnk|so|dylib|sh|elf|jar)$"]),
    ("encoded", &[r"(?i)\s-e(c|nc|nco\w*)?\s+[a-z0-9+/=]{8,}", r"(?i)frombase64string"]),
    ("hidden", &[r"(?i)\s-w(in|indowstyle)?\s+h(idden)?\b"]),
    ("reverse", &[r"(?i)/dev/(tcp|udp)/", r"(?i)\bn(c|cat)\b.*\s-e\s", r"(?i)\bbash\s+-i\b", r"(?i)\bsocat\b.*\bexec\b", r"(?i)\bmkfifo\b.*\bn(c|cat)\b"]),
    // Every alternative of "reverse" and "fetched" holds one of these words, so a command line without any of them is scanned once and no further
    ("gate", &[r"(?i)/dev/|nc|bash|socat|mkfifo|curl|wget|iex|invoke-expression|downloadstring|certutil|bitsadmin"]),
    (
        "fetched",
        &[
            r"(?i)\b(curl|wget)\b[^|]*\|\s*(ba|z|da)?sh\b",
            r"(?i)\biex\b",
            r"(?i)invoke-expression",
            r"(?i)downloadstring",
            r"(?i)certutil(\.exe)?\s.*-urlcache",
            r"(?i)bitsadmin(\.exe)?\s.*/transfer",
        ],
    ),
];
