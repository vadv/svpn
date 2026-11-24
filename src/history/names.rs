//! Organization names of networks, read from the ASN CSV the dashboard
//! already serves to the browser: one pass over the file, whatever the
//! number of networks asked for.

use std::{
    collections::BTreeSet,
    fs::File,
    io::{self, BufRead, BufReader},
    path::Path,
};

/// Names of the `wanted` networks, each at most once. A network the file
/// does not name is absent from the answer.
pub fn lookup(path: &Path, wanted: &BTreeSet<u32>) -> io::Result<Vec<(u32, String)>> {
    let mut reader = BufReader::with_capacity(256 * 1024, File::open(path)?);
    let mut line = Vec::new();
    let mut left = wanted.len();
    let mut names = Vec::new();
    while left > 0 {
        line.clear();
        if reader.read_until(b'\n', &mut line)? == 0 {
            break;
        }
        let mut fields = fields(&line);
        let (asn, name) = match (fields.next(), fields.next(), fields.next(), fields.next()) {
            (_, _, Some(asn), Some(name)) => (asn, name),
            _ => continue,
        };
        // A row of another shape, or a field naming more than one network,
        // is no use here, as it is none to the ASN table itself.
        let asn = match std::str::from_utf8(asn).unwrap_or_default().trim().parse() {
            Ok(asn) => asn,
            Err(_) => continue,
        };
        if !wanted.contains(&asn) || names.iter().any(|(known, _)| *known == asn) {
            continue;
        }
        let name = String::from_utf8_lossy(name)
            .replace("\"\"", "\"")
            .trim()
            .to_owned();
        // A network missing from the file is not an error: the caller notes
        // it as unnamed and does not ask again.
        if !name.is_empty() {
            names.push((asn, name));
            left -= 1;
        }
    }
    Ok(names)
}

/// The fields of a CSV row in order, quotes left off. A quoted field holds
/// commas as they are and doubles the quotes inside it.
fn fields(line: &[u8]) -> impl Iterator<Item = &[u8]> {
    let mut rest = line;
    std::iter::from_fn(move || {
        if rest.is_empty() {
            return None;
        }
        let (field, next) = split_field(rest);
        rest = next;
        Some(field)
    })
}

/// The first field of `rest`, and what follows its separating comma.
fn split_field(rest: &[u8]) -> (&[u8], &[u8]) {
    let after = |end: usize| match rest[end..].iter().position(|byte| *byte == b',') {
        Some(comma) => &rest[end + comma + 1..],
        None => &rest[rest.len()..],
    };
    if rest.first() != Some(&b'"') {
        return match rest.iter().position(|byte| *byte == b',') {
            Some(comma) => (&rest[..comma], &rest[comma + 1..]),
            None => (rest, &rest[rest.len()..]),
        };
    }
    let mut at = 1;
    while at < rest.len() {
        if rest[at] == b'"' {
            if rest.get(at + 1) == Some(&b'"') {
                at += 2;
                continue;
            }
            return (&rest[1..at], after(at + 1));
        }
        at += 1;
    }
    // An unterminated field is taken as far as the row goes.
    (&rest[1..], &rest[rest.len()..])
}
