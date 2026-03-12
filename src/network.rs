//! Bitcoin network configuration.

use anyhow::{bail, Result};
use bitcoin::Network;

/// Parse network string to Network enum.
///
/// Returns an error for unrecognized network names instead of silently
/// defaulting to mainnet.
pub fn parse_network(network: &str) -> Result<Network> {
    match network.to_lowercase().as_str() {
        "bitcoin" | "mainnet" | "main" => Ok(Network::Bitcoin),
        "testnet" | "test" => Ok(Network::Testnet),
        "signet" => Ok(Network::Signet),
        "regtest" | "reg" => Ok(Network::Regtest),
        _ => bail!(
            "unknown network '{}'. Valid options: bitcoin, testnet, signet, regtest",
            network
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_known_networks() {
        assert_eq!(parse_network("bitcoin").unwrap(), Network::Bitcoin);
        assert_eq!(parse_network("mainnet").unwrap(), Network::Bitcoin);
        assert_eq!(parse_network("BITCOIN").unwrap(), Network::Bitcoin);
        assert_eq!(parse_network("testnet").unwrap(), Network::Testnet);
        assert_eq!(parse_network("signet").unwrap(), Network::Signet);
        assert_eq!(parse_network("regtest").unwrap(), Network::Regtest);
    }

    #[test]
    fn test_parse_unknown_network_returns_error() {
        let result = parse_network("unknown");
        assert!(result.is_err());
        let msg = result.unwrap_err().to_string();
        assert!(msg.contains("unknown network"));
        assert!(msg.contains("Valid options"));
    }
}
