//! Agnostic data provider system for external puzzle/bounty sources.
//!
//! Providers resolve references like `boha:b1000:66` into addresses,
//! puzzle context, and cascade targets.

use anyhow::{anyhow, Result};

/// Result from resolving a provider reference.
#[derive(Debug, Clone)]
pub struct ProviderResult {
    /// Addresses for Matcher (scan --targets)
    pub addresses: Vec<String>,

    /// Puzzle context for analyze (--puzzle)
    pub puzzle_context: Option<PuzzleContext>,

    /// Cascade targets for analyze (--cascade)
    pub cascade_targets: Option<Vec<(u8, u64)>>,
}

/// Context for a specific puzzle (for --puzzle flag).
#[derive(Debug, Clone)]
pub struct PuzzleContext {
    /// Puzzle identifier (e.g., "b1000/66")
    pub id: String,
    /// Mask bits for the puzzle (e.g., 66 for puzzle #66)
    pub mask_bits: Option<u8>,
    /// Expected address for verification
    pub expected_address: String,
    /// Address type (p2pkh, p2wpkh, etc.)
    pub address_type: String,
    /// Whether pubkey is known
    pub has_pubkey: bool,
}

/// Detailed verification result for a single puzzle.
#[derive(Debug, Clone)]
pub struct VerifyMatch {
    /// Puzzle identifier
    pub puzzle_id: String,
    /// Matched address
    pub address: String,
    /// Address type that matched
    pub address_type: String,
    /// Puzzle status (solved, unsolved, etc.)
    pub status: String,
    /// Prize amount if known
    pub prize: Option<f64>,
}

/// Detailed verification report.
#[derive(Debug, Clone)]
pub struct VerifyReport {
    /// Matches found
    pub matches: Vec<VerifyMatch>,
    /// Total puzzles checked
    pub total_checked: usize,
}

/// Check if input looks like a provider reference.
pub fn is_provider(input: &str) -> bool {
    let Some((provider, _)) = input.split_once(':') else {
        return false;
    };

    if provider.len() == 1 {
        return false;
    }

    matches!(provider, "boha")
}

/// Resolve a provider reference to addresses and context.
///
/// Returns `Ok(None)` if input is not a provider reference (treat as file path).
/// Returns `Ok(Some(...))` if successfully resolved.
/// Returns `Err(...)` if provider reference but resolution failed.
pub fn resolve(input: &str) -> Result<Option<ProviderResult>> {
    let Some((provider, _query)) = input.split_once(':') else {
        return Ok(None);
    };

    if provider.len() == 1 {
        return Ok(None);
    }

    match provider {
        #[cfg(feature = "boha")]
        "boha" => resolve_boha(&input[5..]).map(Some),

        #[cfg(not(feature = "boha"))]
        "boha" => Err(anyhow!(
            "boha provider requires the 'boha' feature. Rebuild with: cargo build --features boha"
        )),

        _ => Ok(None),
    }
}

/// Build cascade targets from a provider reference.
///
/// For `boha:b1000:66:10`, builds cascade from 10 solved neighbors.
#[cfg(feature = "boha")]
pub fn build_cascade(input: &str) -> Result<Option<Vec<(u8, u64)>>> {
    let Some((provider, query)) = input.split_once(':') else {
        return Ok(None);
    };

    if provider != "boha" {
        return Ok(None);
    }

    build_cascade_boha(query).map(Some)
}

#[cfg(not(feature = "boha"))]
pub fn build_cascade(input: &str) -> Result<Option<Vec<(u8, u64)>>> {
    if input.starts_with("boha:") {
        Err(anyhow!(
            "boha provider requires the 'boha' feature. Rebuild with: cargo build --features boha"
        ))
    } else {
        Ok(None)
    }
}

/// Verify a key against a provider's puzzle collection.
#[cfg(feature = "boha")]
pub fn verify_key(key: &[u8; 32], input: &str) -> Result<Option<VerifyReport>> {
    let Some((provider, query)) = input.split_once(':') else {
        return Ok(None);
    };

    if provider != "boha" {
        return Ok(None);
    }

    verify_key_boha(key, query).map(Some)
}

#[cfg(not(feature = "boha"))]
pub fn verify_key(_key: &[u8; 32], input: &str) -> Result<Option<VerifyReport>> {
    if input.starts_with("boha:") {
        Err(anyhow!(
            "boha provider requires the 'boha' feature. Rebuild with: cargo build --features boha"
        ))
    } else {
        Ok(None)
    }
}

// Boha provider implementation

#[cfg(feature = "boha")]
fn resolve_boha(query: &str) -> Result<ProviderResult> {
    let parts: Vec<&str> = query.split(':').collect();

    match parts.as_slice() {
        [collection, id] | [collection, id, _] if id.parse::<u32>().is_ok() => {
            let num: u32 = id.parse().expect("guard ensures valid u32");
            let puzzle_id = format!("{}/{}", collection, num);
            let puzzle = boha::get(&puzzle_id)
                .map_err(|e| anyhow!("Failed to get puzzle '{}': {}", puzzle_id, e))?;

            let mask_bits = puzzle
                .key
                .and_then(|k| k.bits)
                .and_then(|b| u8::try_from(b).ok());

            Ok(ProviderResult {
                addresses: vec![puzzle.address.value.to_string()],
                puzzle_context: Some(PuzzleContext {
                    id: puzzle_id,
                    mask_bits,
                    expected_address: puzzle.address.value.to_string(),
                    address_type: puzzle.address.kind.to_string(),
                    has_pubkey: puzzle.has_pubkey(),
                }),
                cascade_targets: None,
            })
        }

        ["all", filter] => {
            let addresses = get_all_addresses(filter)?;
            Ok(ProviderResult {
                addresses,
                puzzle_context: None,
                cascade_targets: None,
            })
        }

        [collection, filter] => {
            let addresses = get_collection_addresses(collection, filter)?;
            Ok(ProviderResult {
                addresses,
                puzzle_context: None,
                cascade_targets: None,
            })
        }

        [collection] => {
            let addresses = get_collection_addresses(collection, "unsolved")?;
            Ok(ProviderResult {
                addresses,
                puzzle_context: None,
                cascade_targets: None,
            })
        }

        _ => Err(anyhow!(
            "Invalid boha query: '{}'. Expected: collection:filter, collection:id, or collection:id:neighbors",
            query
        )),
    }
}

#[cfg(feature = "boha")]
fn get_collection_addresses(collection: &str, filter: &str) -> Result<Vec<String>> {
    use boha::Status;

    let filter_fn: Box<dyn Fn(&boha::Puzzle) -> bool> = match filter {
        "all" => Box::new(|_| true),
        "unsolved" => Box::new(|p| p.status == Status::Unsolved),
        "solved" => Box::new(|p| p.status == Status::Solved),
        "with-pubkey" => Box::new(|p| p.status == Status::Unsolved && p.pubkey.is_some()),
        _ => {
            return Err(anyhow!(
                "Unknown filter: '{}'. Valid: all, unsolved, solved, with-pubkey",
                filter
            ))
        }
    };

    let addresses: Vec<String> = match collection {
        "b1000" => boha::b1000::all()
            .filter(|p| filter_fn(p))
            .map(|p| p.address.value.to_string())
            .collect(),
        "gsmg" => {
            let p = boha::gsmg::get();
            if filter_fn(p) {
                vec![p.address.value.to_string()]
            } else {
                vec![]
            }
        }
        "bitaps" => {
            let p = boha::bitaps::get();
            if filter_fn(p) {
                vec![p.address.value.to_string()]
            } else {
                vec![]
            }
        }
        "hash_collision" => boha::hash_collision::all()
            .filter(|p| filter_fn(p))
            .map(|p| p.address.value.to_string())
            .collect(),
        "zden" => boha::zden::all()
            .filter(|p| filter_fn(p))
            .map(|p| p.address.value.to_string())
            .collect(),
        "bitimage" => boha::bitimage::all()
            .filter(|p| filter_fn(p))
            .map(|p| p.address.value.to_string())
            .collect(),
        _ => {
            return Err(anyhow!(
            "Unknown collection: '{}'. Valid: b1000, gsmg, bitaps, hash_collision, zden, bitimage",
            collection
        ))
        }
    };

    Ok(addresses)
}

#[cfg(feature = "boha")]
fn get_all_addresses(filter: &str) -> Result<Vec<String>> {
    use boha::Status;

    let filter_fn: Box<dyn Fn(&boha::Puzzle) -> bool> = match filter {
        "all" => Box::new(|_| true),
        "unsolved" => Box::new(|p| p.status == Status::Unsolved),
        "solved" => Box::new(|p| p.status == Status::Solved),
        "with-pubkey" => Box::new(|p| p.status == Status::Unsolved && p.pubkey.is_some()),
        _ => {
            return Err(anyhow!(
                "Unknown filter: '{}'. Valid: all, unsolved, solved, with-pubkey",
                filter
            ))
        }
    };

    Ok(boha::all()
        .filter(|p| filter_fn(p))
        .map(|p| p.address.value.to_string())
        .collect())
}

#[cfg(feature = "boha")]
fn build_cascade_boha(query: &str) -> Result<Vec<(u8, u64)>> {
    use boha::Status;

    let parts: Vec<&str> = query.split(':').collect();

    let (collection, puzzle_num, neighbor_count) = match parts.as_slice() {
        [coll, id, count] => {
            let num: u32 = id
                .parse()
                .map_err(|_| anyhow!("Invalid puzzle number: {}", id))?;
            let cnt: usize = count
                .parse()
                .map_err(|_| anyhow!("Invalid neighbor count: {}", count))?;
            (*coll, num, cnt)
        }
        [coll, id] => {
            let num: u32 = id
                .parse()
                .map_err(|_| anyhow!("Invalid puzzle number: {}", id))?;
            (*coll, num, 5)
        }
        _ => {
            return Err(anyhow!(
                "Invalid cascade query: '{}'. Expected: collection:id or collection:id:neighbors",
                query
            ))
        }
    };

    if collection != "b1000" {
        return Err(anyhow!("Cascade is only supported for b1000 collection"));
    }

    let mut cascade_targets: Vec<(u8, u64)> = Vec::new();

    let start = puzzle_num.saturating_sub(1);
    let end = puzzle_num.saturating_sub(neighbor_count as u32);

    for n in (end..=start).rev() {
        if n < 1 {
            continue;
        }

        let Ok(puzzle) = boha::b1000::get(n) else {
            continue;
        };

        if puzzle.status != Status::Solved {
            continue;
        }

        let Some(key) = puzzle.key else {
            continue;
        };

        let Some(hex) = key.hex else {
            continue;
        };

        let Some(bits) = key.bits else {
            continue;
        };

        let key_bytes =
            hex::decode(hex).map_err(|_| anyhow!("Invalid key hex for puzzle {}", n))?;

        if key_bytes.len() != 32 {
            continue;
        }

        if bits > 0 && bits < 64 {
            let bits_u8 = bits as u8;
            let mut last_8 = [0u8; 8];
            last_8.copy_from_slice(&key_bytes[24..32]);
            let value = u64::from_be_bytes(last_8);

            // Masking formula: (value & ((1 << bits) - 1)) | (1 << (bits - 1))
            let mask = (1u64 << bits) - 1;
            let high_bit = 1u64 << (bits - 1);
            let masked = (value & mask) | high_bit;

            cascade_targets.push((bits_u8, masked));
        }
    }

    cascade_targets.sort_by_key(|(bits, _)| *bits);

    if cascade_targets.is_empty() {
        return Err(anyhow!(
            "No solved puzzles with known keys found for cascade. Need puzzles < {} to be solved.",
            puzzle_num
        ));
    }

    Ok(cascade_targets)
}

#[cfg(feature = "boha")]
fn verify_key_boha(key: &[u8; 32], query: &str) -> Result<VerifyReport> {
    use crate::derive::KeyDeriver;

    let deriver = KeyDeriver::new();
    let derived = deriver.derive(key);

    let parts: Vec<&str> = query.split(':').collect();

    let collection = match parts.as_slice() {
        [coll] => *coll,
        [coll, _] => *coll,
        _ => {
            return Err(anyhow!(
                "Invalid verify query: '{}'. Expected: collection",
                query
            ))
        }
    };

    let puzzles: Vec<&boha::Puzzle> = match collection {
        "b1000" => boha::b1000::all().collect(),
        "all" => boha::all().collect(),
        "gsmg" => vec![boha::gsmg::get()],
        "bitaps" => vec![boha::bitaps::get()],
        "hash_collision" => boha::hash_collision::all().collect(),
        "zden" => boha::zden::all().collect(),
        "bitimage" => boha::bitimage::all().collect(),
        _ => return Err(anyhow!("Unknown collection: '{}'", collection)),
    };

    let total_checked = puzzles.len();
    let mut matches = Vec::new();

    for puzzle in puzzles {
        let addr = puzzle.address.value;

        let matched_type = if derived.p2pkh_compressed == addr {
            Some("p2pkh_compressed")
        } else if derived.p2pkh_uncompressed == addr {
            Some("p2pkh_uncompressed")
        } else if derived.p2wpkh == addr {
            Some("p2wpkh")
        } else {
            None
        };

        if let Some(addr_type) = matched_type {
            matches.push(VerifyMatch {
                puzzle_id: puzzle.id.to_string(),
                address: addr.to_string(),
                address_type: addr_type.to_string(),
                status: format!("{:?}", puzzle.status),
                prize: puzzle.prize,
            });
        }
    }

    Ok(VerifyReport {
        matches,
        total_checked,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_provider() {
        assert!(is_provider("boha:b1000:66"));
        assert!(is_provider("boha:b1000:unsolved"));
        assert!(!is_provider("targets.txt"));
        assert!(!is_provider("/path/to/file"));
        assert!(!is_provider("C:\\Windows\\path"));
    }

    #[test]
    fn test_resolve_file_path() {
        let result = resolve("targets.txt").unwrap();
        assert!(result.is_none());

        let result = resolve("/path/to/file").unwrap();
        assert!(result.is_none());
    }

    #[test]
    #[cfg(feature = "boha")]
    fn test_resolve_boha_single_puzzle() {
        let result = resolve("boha:b1000:1").unwrap();
        assert!(result.is_some());

        let result = result.unwrap();
        assert_eq!(result.addresses.len(), 1);
        assert_eq!(result.addresses[0], "1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH");
        assert!(result.puzzle_context.is_some());

        let ctx = result.puzzle_context.unwrap();
        assert_eq!(ctx.id, "b1000/1");
        assert_eq!(ctx.mask_bits, Some(1));
    }

    #[test]
    #[cfg(feature = "boha")]
    fn test_resolve_boha_collection_filter() {
        let result = resolve("boha:b1000:solved").unwrap();
        assert!(result.is_some());

        let result = result.unwrap();
        assert!(!result.addresses.is_empty());
        assert!(result.puzzle_context.is_none());
    }

    #[test]
    #[cfg(feature = "boha")]
    fn test_build_cascade() {
        let result = build_cascade("boha:b1000:66:5").unwrap();
        assert!(result.is_some());

        let targets = result.unwrap();
        assert!(!targets.is_empty());
        assert!(targets.len() <= 5);

        for (bits, _) in &targets {
            assert!(*bits < 66);
        }
    }

    #[test]
    #[cfg(feature = "boha")]
    fn test_build_cascade_default_neighbors() {
        let result = build_cascade("boha:b1000:10").unwrap();
        assert!(result.is_some());

        let targets = result.unwrap();
        assert!(!targets.is_empty());
    }

    #[test]
    #[cfg(feature = "boha")]
    fn test_verify_key_match() {
        let key: [u8; 32] = [
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 1,
        ];

        let result = verify_key(&key, "boha:b1000").unwrap();
        assert!(result.is_some());

        let report = result.unwrap();
        assert_eq!(report.total_checked, 256);
        assert!(!report.matches.is_empty());
        assert_eq!(report.matches[0].puzzle_id, "b1000/1");
    }

    #[test]
    #[cfg(feature = "boha")]
    fn test_verify_key_no_match() {
        let key: [u8; 32] = [0xff; 32];

        let result = verify_key(&key, "boha:b1000").unwrap();
        assert!(result.is_some());

        let report = result.unwrap();
        assert!(report.matches.is_empty());
    }

    #[test]
    fn test_is_provider_edge_cases() {
        assert!(!is_provider(""));
        assert!(!is_provider("a:b"));
        assert!(!is_provider("C:Windows"));
        assert!(is_provider("boha:"));
        assert!(is_provider("boha:b1000"));
    }

    #[test]
    #[cfg(feature = "boha")]
    fn test_resolve_boha_all_collections() {
        assert!(resolve("boha:gsmg").unwrap().is_some());
        assert!(resolve("boha:bitaps").unwrap().is_some());
        assert!(resolve("boha:hash_collision").unwrap().is_some());
        assert!(resolve("boha:zden").unwrap().is_some());
        assert!(resolve("boha:bitimage").unwrap().is_some());
    }

    #[test]
    #[cfg(feature = "boha")]
    fn test_resolve_boha_invalid_collection() {
        let result = resolve("boha:invalid_collection");
        assert!(result.is_err());
    }
}
