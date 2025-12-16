//! Bitcoin network configuration.

use bitcoin::Network;

/// Parse network string to Network enum.
pub fn parse_network(network: &str) -> Network {
    match network.to_lowercase().as_str() {
        "bitcoin" | "mainnet" | "main" => Network::Bitcoin,
        "testnet" | "test" => Network::Testnet,
        "signet" => Network::Signet,
        "regtest" | "reg" => Network::Regtest,
        _ => {
            eprintln!("Unknown network: {}. Defaulting to Bitcoin.", network);
            Network::Bitcoin
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_network() {
        assert_eq!(parse_network("bitcoin"), Network::Bitcoin);
        assert_eq!(parse_network("mainnet"), Network::Bitcoin);
        assert_eq!(parse_network("BITCOIN"), Network::Bitcoin);
        assert_eq!(parse_network("testnet"), Network::Testnet);
        assert_eq!(parse_network("signet"), Network::Signet);
        assert_eq!(parse_network("regtest"), Network::Regtest);
        assert_eq!(parse_network("unknown"), Network::Bitcoin); // default
    }
}
