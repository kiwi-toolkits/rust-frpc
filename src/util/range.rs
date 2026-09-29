//! Number-range parsing, matching `pkg/util/util.ParseRangeNumbers`.
//!
//! Used by the `parseNumberRange` config template function and by the legacy INI
//! `[range:name]` sections, which need `localPort`/`remotePort` expanded from a
//! spec like `6000-6002,6010`.

use crate::error::{Error, Result};

/// Parses `"1-3,9"` into `[1, 2, 3, 9]`.
///
/// A single number is a one-element range; anything with more than one dash is
/// rejected. Whitespace around each item is tolerated.
pub fn parse_range_numbers(spec: &str) -> Result<Vec<i64>> {
    let mut out = Vec::new();
    for item in spec.split(',') {
        let item = item.trim();
        if item.is_empty() {
            continue;
        }
        match item.split_once('-') {
            None => out.push(parse_number(item)?),
            Some((from, to)) => {
                if to.contains('-') {
                    return Err(Error::config(format!("range number is invalid: {item}")));
                }
                let (from, to) = (parse_number(from)?, parse_number(to)?);
                if to < from {
                    return Err(Error::config(format!(
                        "range number is invalid: {item} (max is smaller than min)"
                    )));
                }
                out.extend(from..=to);
            }
        }
    }
    Ok(out)
}

/// Parses `"6000-6002,6010"` into `(local, remote)` pairs, requiring both specs
/// to expand to the same count.
pub fn parse_range_pair(local: &str, remote: &str) -> Result<Vec<(i64, i64)>> {
    let locals = parse_range_numbers(local)?;
    let remotes = parse_range_numbers(remote)?;
    if locals.len() != remotes.len() {
        return Err(Error::config(
            "local ports number should be same with remote ports number",
        ));
    }
    Ok(locals.into_iter().zip(remotes).collect())
}

fn parse_number(value: &str) -> Result<i64> {
    value
        .trim()
        .parse::<i64>()
        .map_err(|_| Error::config(format!("range number is invalid: {value}")))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn expands_ranges_and_singles() {
        assert_eq!(parse_range_numbers("6010-6020,6022").unwrap().len(), 12);
        assert_eq!(parse_range_numbers("1-3,9").unwrap(), vec![1, 2, 3, 9]);
        assert_eq!(parse_range_numbers(" 7 ").unwrap(), vec![7]);
    }

    #[test]
    fn rejects_reversed_and_malformed_ranges() {
        assert!(parse_range_numbers("5-1").is_err());
        assert!(parse_range_numbers("1-2-3").is_err());
        assert!(parse_range_numbers("abc").is_err());
    }

    #[test]
    fn pairs_require_equal_counts() {
        let pairs = parse_range_pair("6000-6001", "7000-7001").unwrap();
        assert_eq!(pairs, vec![(6000, 7000), (6001, 7001)]);
        assert!(parse_range_pair("6000-6001", "7000").is_err());
    }
}
