//! Output handlers for generated keys.

mod console;
mod multi;
#[cfg(feature = "storage-query")]
mod query_format;
#[cfg(feature = "storage")]
mod storage;

pub use console::ConsoleOutput;
pub use multi::MultiOutput;
#[cfg(feature = "storage-query")]
pub use query_format::{format_csv, format_json, format_schema, format_table, OutputFormat};
#[cfg(feature = "storage")]
pub use storage::{StorageOutput, StorageSummary};

use crate::derive::DerivedKey;
use crate::matcher::MatchInfo;
use anyhow::Result;

pub(crate) fn escape_csv_field(field: &str) -> String {
    let has_boundary_whitespace = field.chars().next().is_some_and(char::is_whitespace)
        || field.chars().last().is_some_and(char::is_whitespace);

    if has_boundary_whitespace
        || field.contains(',')
        || field.contains('"')
        || field.contains('\n')
        || field.contains('\r')
    {
        format!("\"{}\"", field.replace('"', "\"\""))
    } else {
        field.to_string()
    }
}

/// Output trait for handling generated keys.
pub trait Output: Send + Sync {
    /// Output a key (no matcher, output all keys).
    fn key(&self, source: &str, transform: &str, derived: &DerivedKey) -> Result<()>;

    /// Output a match hit (matcher found target).
    fn hit(
        &self,
        source: &str,
        transform: &str,
        derived: &DerivedKey,
        match_info: &MatchInfo,
    ) -> Result<()>;

    /// Flush any buffered output.
    fn flush(&self) -> Result<()>;
}
