//! Cloud storage credentials with provider-agnostic environment variable support.
//!
//! Supports both CLOUD_* (preferred) and AWS_* (fallback) environment variables
//! for S3-compatible storage providers like Cloudflare R2, MinIO, and AWS S3.

use super::error::{CloudError, Result};

/// Cloud storage credentials.
#[derive(Debug, Clone)]
pub struct CloudCredentials {
    /// Access key ID for S3-compatible storage.
    pub access_key_id: String,
    /// Secret access key for S3-compatible storage.
    pub secret_access_key: String,
}

impl CloudCredentials {
    /// Create credentials from explicit values.
    pub fn new(access_key_id: impl Into<String>, secret_access_key: impl Into<String>) -> Self {
        Self {
            access_key_id: access_key_id.into(),
            secret_access_key: secret_access_key.into(),
        }
    }

    /// Load credentials from environment variables.
    ///
    /// Checks for provider-agnostic variables first, then falls back to AWS-specific ones:
    /// - `CLOUD_ACCESS_KEY_ID` or `AWS_ACCESS_KEY_ID`
    /// - `CLOUD_SECRET_ACCESS_KEY` or `AWS_SECRET_ACCESS_KEY`
    ///
    /// # Errors
    ///
    /// Returns `CloudError::NoCredentials` if neither set of variables is found.
    pub fn from_env() -> Result<Self> {
        let access_key_id = std::env::var("CLOUD_ACCESS_KEY_ID")
            .or_else(|_| std::env::var("AWS_ACCESS_KEY_ID"))
            .map_err(|_| CloudError::NoCredentials)?;

        let secret_access_key = std::env::var("CLOUD_SECRET_ACCESS_KEY")
            .or_else(|_| std::env::var("AWS_SECRET_ACCESS_KEY"))
            .map_err(|_| CloudError::NoCredentials)?;

        Ok(Self {
            access_key_id,
            secret_access_key,
        })
    }

    /// Check if credentials are available in environment.
    pub fn available_in_env() -> bool {
        Self::from_env().is_ok()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn credentials_new() {
        let creds = CloudCredentials::new("access_key", "secret_key");
        assert_eq!(creds.access_key_id, "access_key");
        assert_eq!(creds.secret_access_key, "secret_key");
    }

    #[test]
    fn credentials_from_cloud_env_takes_precedence_over_aws() {
        std::env::set_var("CLOUD_ACCESS_KEY_ID", "cloud_access");
        std::env::set_var("CLOUD_SECRET_ACCESS_KEY", "cloud_secret");
        std::env::set_var("AWS_ACCESS_KEY_ID", "aws_access");
        std::env::set_var("AWS_SECRET_ACCESS_KEY", "aws_secret");

        let creds = CloudCredentials::from_env().unwrap();
        assert_eq!(creds.access_key_id, "cloud_access");
        assert_eq!(creds.secret_access_key, "cloud_secret");

        std::env::remove_var("CLOUD_ACCESS_KEY_ID");
        std::env::remove_var("CLOUD_SECRET_ACCESS_KEY");
        std::env::remove_var("AWS_ACCESS_KEY_ID");
        std::env::remove_var("AWS_SECRET_ACCESS_KEY");
    }

    #[test]
    fn credentials_fallback_to_aws_env_when_cloud_missing() {
        std::env::remove_var("CLOUD_ACCESS_KEY_ID");
        std::env::remove_var("CLOUD_SECRET_ACCESS_KEY");
        std::env::set_var("AWS_ACCESS_KEY_ID", "aws_access");
        std::env::set_var("AWS_SECRET_ACCESS_KEY", "aws_secret");

        let creds = CloudCredentials::from_env().unwrap();
        assert_eq!(creds.access_key_id, "aws_access");
        assert_eq!(creds.secret_access_key, "aws_secret");

        std::env::remove_var("AWS_ACCESS_KEY_ID");
        std::env::remove_var("AWS_SECRET_ACCESS_KEY");
    }

    #[test]
    fn credentials_available_in_env_returns_true_when_set() {
        std::env::set_var("CLOUD_ACCESS_KEY_ID", "test");
        std::env::set_var("CLOUD_SECRET_ACCESS_KEY", "test");

        assert!(CloudCredentials::available_in_env());

        std::env::remove_var("CLOUD_ACCESS_KEY_ID");
        std::env::remove_var("CLOUD_SECRET_ACCESS_KEY");
    }
}
