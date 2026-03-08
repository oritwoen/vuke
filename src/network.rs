//! Bitcoin network configuration.

use anyhow::{bail, Result};
use bitcoin::Network;

/// Parse network string to Network enum.
pub fn parse_network(network: &str) -> Result<Network> {
    match network.to_lowercase().as_str() {
        "bitcoin" | "mainnet" | "main" => Ok(Network::Bitcoin),
        "testnet" | "test" => Ok(Network::Testnet),
        "signet" => Ok(Network::Signet),
        "regtest" | "reg" => Ok(Network::Regtest),
        _ => bail!(
            "Unknown network: {network}. Expected one of: bitcoin, testnet, signet, regtest"
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_network() {
        assert_eq!(parse_network("bitcoin").unwrap(), Network::Bitcoin);
        assert_eq!(parse_network("mainnet").unwrap(), Network::Bitcoin);
        assert_eq!(parse_network("BITCOIN").unwrap(), Network::Bitcoin);
        assert_eq!(parse_network("testnet").unwrap(), Network::Testnet);
        assert_eq!(parse_network("signet").unwrap(), Network::Signet);
        assert_eq!(parse_network("regtest").unwrap(), Network::Regtest);
    }

    #[test]
    fn test_parse_network_rejects_unknown_network() {
        let err = parse_network("unknown").unwrap_err();
        assert!(err
            .to_string()
            .contains("Unknown network: unknown. Expected one of: bitcoin, testnet, signet, regtest"));
    }
}
