//! Value-free error, key, and name scrubbing (ensuring secret credentials pasted
//! into the wrong TOML field or key can never leak into logs, CLI errors, or
//! `/reload` responses).

use base64::Engine as _;
use base64::engine::general_purpose::{STANDARD, STANDARD_NO_PAD, URL_SAFE, URL_SAFE_NO_PAD};
use mtg_core::SECRET_KEY_LEN;

/// Placeholder replacing any run that could spell a secret value.
pub const VALUE_NOT_SHOWN: &str = "<not shown: reads as a secret value>";

/// Shortest possible encoding of a 16-byte secret key (unpadded base64 = 22 chars).
pub const VALUE_RUN_MIN: usize = 22;

/// Suffix added to an unknown key path when a hidden value-like segment was replaced.
pub const UNKNOWN_KEY_LINE: &str = " (line ";

/// Reports whether `c` belongs to the hex or base64 (std/url, padded) alphabet.
#[inline]
const fn is_value_char(c: u8) -> bool {
    c.is_ascii_alphanumeric() || matches!(c, b'+' | b'/' | b'=' | b'-' | b'_')
}

/// Reports whether `run` consists exclusively of lowercase ASCII letters, `-`, and `_`
/// (plain config key spelling).
#[inline]
fn is_plain_word(run: &str) -> bool {
    run.bytes()
        .all(|b| b.is_ascii_lowercase() || b == b'-' || b == b'_')
}

/// Replace any run in `text` that could spell a secret value and satisfies
/// `from_document(run)` with [`VALUE_NOT_SHOWN`]. Returns `(scrubbed, replaced)`.
pub fn without_values<F>(text: &str, mut from_document: F) -> (String, bool)
where
    F: FnMut(&str) -> bool,
{
    let bytes = text.as_bytes();
    let mut out = String::with_capacity(text.len());
    let mut replaced = false;
    let mut start = 0usize;

    while start < bytes.len() {
        if !is_value_char(bytes[start]) {
            // Preserve valid UTF-8 character verbatim.
            let ch = text[start..].chars().next().expect("non-empty");
            out.push(ch);
            start += ch.len_utf8();
            continue;
        }

        let mut end = start;
        while end < bytes.len() && is_value_char(bytes[end]) {
            end += 1;
        }

        let run = &text[start..end];
        if run.len() >= VALUE_RUN_MIN && !is_plain_word(run) && from_document(run) {
            out.push_str(VALUE_NOT_SHOWN);
            replaced = true;
        } else {
            out.push_str(run);
        }

        start = end;
    }

    (out, replaced)
}

/// Scrub any secret-like text found inside `doc` (case-insensitively) from an
/// error message.
pub fn scrub_error_against_doc(doc: &[u8], msg: &str) -> (String, bool) {
    let lower_doc = String::from_utf8_lossy(doc).to_ascii_lowercase();
    without_values(msg, |run| lower_doc.contains(&run.to_ascii_lowercase()))
}

/// Scrub any secret-like run from a file key/name/host unconditionally.
pub fn value_free_name(name: &str) -> String {
    without_values(name, |_| true).0
}

/// Scrub any secret-like run from arbitrary text (alias of [`value_free_name`]).
pub fn value_free_text(text: &str) -> String {
    value_free_name(text)
}

/// Quote a file name after scrubbing any secret-like runs.
pub fn shown_name(name: &str) -> String {
    format!("{:?}", value_free_name(name))
}

/// Reports whether `name` contains a run that could spell a secret value.
pub fn holds_a_value(name: &str) -> bool {
    without_values(name, |_| true).1
}

/// Reports whether `text` could be a secret value pasted into a wrong field
/// (either decodes as hex or std/url base64 to `>= 16` bytes, or contains a
/// secret-like run).
pub fn reads_as_a_value(text: &str) -> bool {
    if hex::decode(text).is_ok_and(|raw| raw.len() >= SECRET_KEY_LEN) {
        return true;
    }
    if URL_SAFE_NO_PAD
        .decode(text)
        .is_ok_and(|raw| raw.len() >= SECRET_KEY_LEN)
    {
        return true;
    }
    if URL_SAFE
        .decode(text)
        .is_ok_and(|raw| raw.len() >= SECRET_KEY_LEN)
    {
        return true;
    }
    if STANDARD_NO_PAD
        .decode(text)
        .is_ok_and(|raw| raw.len() >= SECRET_KEY_LEN)
    {
        return true;
    }
    if STANDARD
        .decode(text)
        .is_ok_and(|raw| raw.len() >= SECRET_KEY_LEN)
    {
        return true;
    }
    holds_a_value(text)
}

/// Strip the trailing `" (line N)"` suffix appended to an unknown key whose path
/// contained a scrubbed secret-like segment.
pub fn unknown_key_path(key: &str) -> &str {
    if let Some(at) = key.rfind(UNKNOWN_KEY_LINE)
        && key.ends_with(')')
        && key[..at].contains(VALUE_NOT_SHOWN)
    {
        return &key[..at];
    }
    key
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_hex_and_base64_values_but_keeps_normal_names() {
        assert!(!reads_as_a_value("alice"));
        assert!(!reads_as_a_value("bob_smith-01"));
        assert!(!reads_as_a_value("domain-fronting-proxy-protocol"));
        assert!(reads_as_a_value("eea1a1a1a1b2b2b2b2c3c3c3c3d4d4d4d4"));
        assert!(reads_as_a_value("NnoYmu4Y+jHBkAVO/UqOlQ"));
        assert!(reads_as_a_value(
            "foo eea1a1a1a1b2b2b2b2c3c3c3c3d4d4d4d4 bar"
        ));
        assert_eq!(
            value_free_name("alice eea1a1a1a1b2b2b2b2c3c3c3c3d4d4d4d4"),
            format!("alice {VALUE_NOT_SHOWN}")
        );
    }
}
