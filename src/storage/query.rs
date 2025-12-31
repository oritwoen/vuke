//! DuckDB query executor for Parquet storage.

use std::path::Path;
use std::sync::Arc;

use duckdb::arrow::array::{
    Array, BinaryArray, FixedSizeBinaryArray, Float64Array, Int16Array, Int32Array, Int64Array,
    StringArray, TimestampMillisecondArray, UInt16Array, UInt32Array, UInt64Array, UInt8Array,
};
use duckdb::arrow::datatypes::Schema;
use duckdb::arrow::record_batch::RecordBatch;
use duckdb::Connection;

use super::{Result, StorageError};

#[derive(Debug, Clone, PartialEq)]
pub enum Value {
    Null,
    String(String),
    Int64(i64),
    UInt64(u64),
    Float64(f64),
    Binary(Vec<u8>),
    Timestamp(i64),
}

impl Value {
    pub fn as_string(&self) -> Option<&str> {
        match self {
            Value::String(s) => Some(s),
            _ => None,
        }
    }

    pub fn as_i64(&self) -> Option<i64> {
        match self {
            Value::Int64(v) => Some(*v),
            _ => None,
        }
    }

    pub fn as_u64(&self) -> Option<u64> {
        match self {
            Value::UInt64(v) => Some(*v),
            _ => None,
        }
    }

    pub fn as_f64(&self) -> Option<f64> {
        match self {
            Value::Float64(v) => Some(*v),
            _ => None,
        }
    }

    pub fn as_binary(&self) -> Option<&[u8]> {
        match self {
            Value::Binary(v) => Some(v),
            _ => None,
        }
    }

    pub fn as_timestamp(&self) -> Option<i64> {
        match self {
            Value::Timestamp(v) => Some(*v),
            _ => None,
        }
    }

    pub fn is_null(&self) -> bool {
        matches!(self, Value::Null)
    }
}

#[derive(Debug, Clone)]
pub struct Row {
    columns: Vec<(String, Value)>,
}

impl Row {
    pub fn get(&self, column: &str) -> Option<&Value> {
        self.columns
            .iter()
            .find(|(name, _)| name == column)
            .map(|(_, v)| v)
    }

    pub fn get_string(&self, column: &str) -> Option<&str> {
        self.get(column).and_then(Value::as_string)
    }

    pub fn get_i64(&self, column: &str) -> Option<i64> {
        self.get(column).and_then(Value::as_i64)
    }

    pub fn get_u64(&self, column: &str) -> Option<u64> {
        self.get(column).and_then(Value::as_u64)
    }

    pub fn columns(&self) -> &[(String, Value)] {
        &self.columns
    }

    pub fn column_names(&self) -> Vec<&str> {
        self.columns.iter().map(|(name, _)| name.as_str()).collect()
    }
}

#[derive(Debug)]
pub struct QueryResult {
    batches: Vec<RecordBatch>,
}

impl QueryResult {
    pub fn batches(&self) -> &[RecordBatch] {
        &self.batches
    }

    pub fn into_batches(self) -> Vec<RecordBatch> {
        self.batches
    }

    pub fn rows(&self) -> Vec<Row> {
        batches_to_rows(&self.batches)
    }

    pub fn row_count(&self) -> usize {
        self.batches.iter().map(|b| b.num_rows()).sum()
    }

    pub fn is_empty(&self) -> bool {
        self.batches.is_empty() || self.row_count() == 0
    }

    pub fn schema(&self) -> Option<Arc<Schema>> {
        self.batches.first().map(|b| b.schema())
    }
}

pub struct QueryExecutor {
    conn: Connection,
    storage_path: String,
    view_created: bool,
}

impl QueryExecutor {
    pub fn new(storage_path: impl AsRef<Path>) -> Result<Self> {
        let storage_path = storage_path.as_ref().to_string_lossy().to_string();
        let conn = Connection::open_in_memory()?;

        let mut executor = Self {
            conn,
            storage_path,
            view_created: false,
        };

        executor.try_create_view()?;

        Ok(executor)
    }

    fn try_create_view(&mut self) -> Result<()> {
        let glob_pattern = format!("{}/**/*.parquet", self.storage_path);

        let create_view_sql = format!(
            "CREATE OR REPLACE VIEW results AS SELECT * FROM read_parquet('{}', hive_partitioning=true)",
            glob_pattern
        );

        match self.conn.execute(&create_view_sql, []) {
            Ok(_) => {
                self.view_created = true;
                Ok(())
            }
            Err(e) => {
                let err_str = e.to_string().to_lowercase();
                if err_str.contains("no files found")
                    || err_str.contains("empty")
                    || err_str.contains("could not find")
                {
                    self.view_created = false;
                    Ok(())
                } else {
                    Err(StorageError::DuckDb(e))
                }
            }
        }
    }

    pub fn query_arrow(&self, sql: &str) -> Result<QueryResult> {
        if !self.view_created && references_results_view(sql) {
            return Ok(QueryResult {
                batches: Vec::new(),
            });
        }

        let mut stmt = self.conn.prepare(sql)?;
        let arrow_result = stmt.query_arrow([])?;
        let batches: Vec<RecordBatch> = arrow_result.collect();

        Ok(QueryResult { batches })
    }

    pub fn query(&self, sql: &str) -> Result<Vec<Row>> {
        let result = self.query_arrow(sql)?;
        Ok(result.rows())
    }

    pub fn query_scalar_i64(&self, sql: &str) -> Result<Option<i64>> {
        let result = self.query_arrow(sql)?;
        if result.is_empty() {
            return Ok(None);
        }

        let batch = &result.batches[0];
        if batch.num_columns() == 0 || batch.num_rows() == 0 {
            return Ok(None);
        }

        let col = batch.column(0);
        extract_i64_value(col, 0)
    }

    pub fn query_scalar_string(&self, sql: &str) -> Result<Option<String>> {
        let result = self.query_arrow(sql)?;
        if result.is_empty() {
            return Ok(None);
        }

        let batch = &result.batches[0];
        if batch.num_columns() == 0 || batch.num_rows() == 0 {
            return Ok(None);
        }

        let col = batch.column(0);
        if col.is_null(0) {
            return Ok(None);
        }

        if let Some(arr) = col.as_any().downcast_ref::<StringArray>() {
            return Ok(Some(arr.value(0).to_string()));
        }

        Ok(None)
    }

    pub fn schema(&self) -> Result<Option<Schema>> {
        if !self.view_created {
            return Ok(None);
        }

        let result = self.query_arrow("SELECT * FROM results LIMIT 1")?;
        Ok(result.schema().map(|s| (*s).clone()))
    }

    pub fn discovered_files(&self) -> Result<Vec<String>> {
        let glob_pattern = format!("{}/**/*.parquet", self.storage_path);
        let sql = format!("SELECT file FROM glob('{}')", glob_pattern);

        let result = self.query_arrow(&sql)?;
        let mut files = Vec::new();

        for batch in &result.batches {
            if batch.num_columns() > 0 {
                if let Some(arr) = batch.column(0).as_any().downcast_ref::<StringArray>() {
                    for i in 0..arr.len() {
                        if !arr.is_null(i) {
                            files.push(arr.value(i).to_string());
                        }
                    }
                }
            }
        }

        Ok(files)
    }

    pub fn has_data(&self) -> bool {
        self.view_created
    }

    pub fn storage_path(&self) -> &str {
        &self.storage_path
    }

    pub fn refresh(&mut self) -> Result<()> {
        self.try_create_view()
    }
}

fn references_results_view(sql: &str) -> bool {
    let sql_lower = sql.to_lowercase();
    let bytes = sql_lower.as_bytes();

    if let Some(pos) = sql_lower.find("results") {
        let before_ok = pos == 0 || !bytes[pos - 1].is_ascii_alphanumeric();
        let after_pos = pos + 7;
        let after_ok = after_pos >= bytes.len() || !bytes[after_pos].is_ascii_alphanumeric();
        before_ok && after_ok
    } else {
        false
    }
}

fn extract_i64_value(col: &dyn Array, idx: usize) -> Result<Option<i64>> {
    if col.is_null(idx) {
        return Ok(None);
    }

    if let Some(arr) = col.as_any().downcast_ref::<Int64Array>() {
        return Ok(Some(arr.value(idx)));
    }
    if let Some(arr) = col.as_any().downcast_ref::<Int32Array>() {
        return Ok(Some(arr.value(idx) as i64));
    }
    if let Some(arr) = col.as_any().downcast_ref::<Int16Array>() {
        return Ok(Some(arr.value(idx) as i64));
    }
    if let Some(arr) = col.as_any().downcast_ref::<UInt64Array>() {
        return Ok(i64::try_from(arr.value(idx)).ok());
    }
    if let Some(arr) = col.as_any().downcast_ref::<UInt32Array>() {
        return Ok(Some(arr.value(idx) as i64));
    }
    if let Some(arr) = col.as_any().downcast_ref::<UInt16Array>() {
        return Ok(Some(arr.value(idx) as i64));
    }
    if let Some(arr) = col.as_any().downcast_ref::<UInt8Array>() {
        return Ok(Some(arr.value(idx) as i64));
    }

    Ok(None)
}

fn batches_to_rows(batches: &[RecordBatch]) -> Vec<Row> {
    let mut rows = Vec::new();

    for batch in batches {
        let schema = batch.schema();
        let num_rows = batch.num_rows();
        let num_cols = batch.num_columns();

        for row_idx in 0..num_rows {
            let mut columns = Vec::with_capacity(num_cols);

            for col_idx in 0..num_cols {
                let field = schema.field(col_idx);
                let col_name = field.name().clone();
                let col = batch.column(col_idx);

                let value = extract_value(col, row_idx);
                columns.push((col_name, value));
            }

            rows.push(Row { columns });
        }
    }

    rows
}

fn extract_value(col: &dyn Array, idx: usize) -> Value {
    if col.is_null(idx) {
        return Value::Null;
    }

    if let Some(arr) = col.as_any().downcast_ref::<StringArray>() {
        return Value::String(arr.value(idx).to_string());
    }
    if let Some(arr) = col.as_any().downcast_ref::<Int64Array>() {
        return Value::Int64(arr.value(idx));
    }
    if let Some(arr) = col.as_any().downcast_ref::<Int32Array>() {
        return Value::Int64(arr.value(idx) as i64);
    }
    if let Some(arr) = col.as_any().downcast_ref::<Int16Array>() {
        return Value::Int64(arr.value(idx) as i64);
    }
    if let Some(arr) = col.as_any().downcast_ref::<UInt64Array>() {
        return Value::UInt64(arr.value(idx));
    }
    if let Some(arr) = col.as_any().downcast_ref::<UInt32Array>() {
        return Value::UInt64(arr.value(idx) as u64);
    }
    if let Some(arr) = col.as_any().downcast_ref::<UInt16Array>() {
        return Value::UInt64(arr.value(idx) as u64);
    }
    if let Some(arr) = col.as_any().downcast_ref::<UInt8Array>() {
        return Value::UInt64(arr.value(idx) as u64);
    }
    if let Some(arr) = col.as_any().downcast_ref::<Float64Array>() {
        return Value::Float64(arr.value(idx));
    }
    if let Some(arr) = col.as_any().downcast_ref::<BinaryArray>() {
        return Value::Binary(arr.value(idx).to_vec());
    }
    if let Some(arr) = col.as_any().downcast_ref::<FixedSizeBinaryArray>() {
        return Value::Binary(arr.value(idx).to_vec());
    }
    if let Some(arr) = col.as_any().downcast_ref::<TimestampMillisecondArray>() {
        return Value::Timestamp(arr.value(idx));
    }

    Value::Null
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::{
        AddressRecord, ExportFormatRecord, ParquetBackend, PrivateKeyRecord, PublicKeyRecord,
        ResultRecord, StorageBackend,
    };
    use tempfile::tempdir;

    fn make_test_record<'a>(
        raw: &'a [u8; 32],
        source: &'a str,
        transform: &'a str,
        public_keys: &'a [PublicKeyRecord<'a>],
        addresses: &'a [AddressRecord<'a>],
        export_formats: &'a [ExportFormatRecord<'a>],
        matched_target: Option<&'a str>,
    ) -> ResultRecord<'a> {
        ResultRecord {
            source,
            transform,
            chain: "bitcoin",
            timestamp: chrono::DateTime::parse_from_rfc3339("2025-01-01T00:00:00Z")
                .unwrap()
                .with_timezone(&chrono::Utc),
            private_key: PrivateKeyRecord {
                raw,
                hex: "0101010101010101010101010101010101010101010101010101010101010101",
                decimal:
                    "454086624460063511464984254936031011189294057512315937409637584344757371137",
                binary: "0000000100000001000000010000000100000001000000010000000100000001\
                         0000000100000001000000010000000100000001000000010000000100000001\
                         0000000100000001000000010000000100000001000000010000000100000001\
                         0000000100000001000000010000000100000001000000010000000100000001",
                bit_length: 249,
                hamming_weight: 32,
                leading_zeros: 0,
            },
            public_keys,
            addresses,
            export_formats,
            matched_target,
        }
    }

    fn create_test_storage(
        dir: &Path,
        transform: &str,
        count: usize,
        matched_count: usize,
    ) -> Vec<String> {
        let mut backend = ParquetBackend::new(dir, transform);
        let raw = [1u8; 32];

        let sources: Vec<String> = (0..count).map(|i| format!("source_{}", i)).collect();

        for (i, source) in sources.iter().enumerate() {
            let matched = if i < matched_count {
                Some("1ABC123")
            } else {
                None
            };

            let source_static: &'static str = Box::leak(source.clone().into_boxed_str());
            let matched_static: Option<&'static str> =
                matched.map(|s| Box::leak(s.to_string().into_boxed_str()) as &'static str);

            let record = make_test_record(
                &raw,
                source_static,
                transform,
                &[],
                &[],
                &[],
                matched_static,
            );
            backend.write_batch(&[record]).unwrap();
        }

        backend.flush().unwrap();
        sources
    }

    #[test]
    fn new_creates_executor_with_empty_storage() {
        let dir = tempdir().unwrap();
        let executor = QueryExecutor::new(dir.path());
        assert!(executor.is_ok());

        let executor = executor.unwrap();
        assert!(!executor.has_data());
    }

    #[test]
    fn new_creates_executor_with_data() {
        let dir = tempdir().unwrap();
        create_test_storage(dir.path(), "sha256", 5, 0);

        let executor = QueryExecutor::new(dir.path()).unwrap();
        assert!(executor.has_data());
    }

    #[test]
    fn query_count_returns_correct_count() {
        let dir = tempdir().unwrap();
        create_test_storage(dir.path(), "sha256", 10, 0);

        let executor = QueryExecutor::new(dir.path()).unwrap();
        let count = executor
            .query_scalar_i64("SELECT COUNT(*) FROM results")
            .unwrap();

        assert_eq!(count, Some(10));
    }

    #[test]
    fn query_empty_storage_returns_empty() {
        let dir = tempdir().unwrap();
        let executor = QueryExecutor::new(dir.path()).unwrap();

        let rows = executor.query("SELECT * FROM results").unwrap();
        assert!(rows.is_empty());
    }

    #[test]
    fn query_with_transform_filter() {
        let dir = tempdir().unwrap();
        create_test_storage(dir.path(), "sha256", 5, 0);
        create_test_storage(dir.path(), "milksad", 3, 0);

        let executor = QueryExecutor::new(dir.path()).unwrap();

        let sha256_count = executor
            .query_scalar_i64("SELECT COUNT(*) FROM results WHERE transform = 'sha256'")
            .unwrap();
        assert_eq!(sha256_count, Some(5));

        let milksad_count = executor
            .query_scalar_i64("SELECT COUNT(*) FROM results WHERE transform = 'milksad'")
            .unwrap();
        assert_eq!(milksad_count, Some(3));
    }

    #[test]
    fn query_group_by_transform() {
        let dir = tempdir().unwrap();
        create_test_storage(dir.path(), "sha256", 5, 0);
        create_test_storage(dir.path(), "milksad", 3, 0);

        let executor = QueryExecutor::new(dir.path()).unwrap();

        let rows = executor
            .query("SELECT transform, COUNT(*) as cnt FROM results GROUP BY transform ORDER BY transform")
            .unwrap();

        assert_eq!(rows.len(), 2);

        let milksad_row = rows
            .iter()
            .find(|r| r.get_string("transform") == Some("milksad"));
        assert!(milksad_row.is_some());
        assert_eq!(milksad_row.unwrap().get_i64("cnt"), Some(3));

        let sha256_row = rows
            .iter()
            .find(|r| r.get_string("transform") == Some("sha256"));
        assert!(sha256_row.is_some());
        assert_eq!(sha256_row.unwrap().get_i64("cnt"), Some(5));
    }

    #[test]
    fn query_matched_targets_not_null() {
        let dir = tempdir().unwrap();
        create_test_storage(dir.path(), "sha256", 10, 3);

        let executor = QueryExecutor::new(dir.path()).unwrap();

        let count = executor
            .query_scalar_i64("SELECT COUNT(*) FROM results WHERE matched_target IS NOT NULL")
            .unwrap();

        assert_eq!(count, Some(3));
    }

    #[test]
    fn query_arrow_returns_record_batches() {
        let dir = tempdir().unwrap();
        create_test_storage(dir.path(), "sha256", 5, 0);

        let executor = QueryExecutor::new(dir.path()).unwrap();
        let result = executor
            .query_arrow("SELECT * FROM results LIMIT 3")
            .unwrap();

        assert!(!result.is_empty());
        assert_eq!(result.row_count(), 3);
        assert!(result.schema().is_some());
    }

    #[test]
    fn discovered_files_lists_parquet_files() {
        let dir = tempdir().unwrap();
        create_test_storage(dir.path(), "sha256", 5, 0);

        let executor = QueryExecutor::new(dir.path()).unwrap();
        let files = executor.discovered_files().unwrap();

        assert!(!files.is_empty());
        assert!(files.iter().all(|f| f.ends_with(".parquet")));
    }

    #[test]
    fn schema_returns_result_schema() {
        let dir = tempdir().unwrap();
        create_test_storage(dir.path(), "sha256", 1, 0);

        let executor = QueryExecutor::new(dir.path()).unwrap();
        let schema = executor.schema().unwrap();

        assert!(schema.is_some());
        let schema = schema.unwrap();
        assert!(schema.field_with_name("source").is_ok());
        assert!(schema.field_with_name("transform").is_ok());
        assert!(schema.field_with_name("private_key_hex").is_ok());
    }

    #[test]
    fn schema_empty_storage_returns_none() {
        let dir = tempdir().unwrap();
        let executor = QueryExecutor::new(dir.path()).unwrap();

        let schema = executor.schema().unwrap();
        assert!(schema.is_none());
    }

    #[test]
    fn row_get_methods_work() {
        let dir = tempdir().unwrap();
        create_test_storage(dir.path(), "sha256", 1, 0);

        let executor = QueryExecutor::new(dir.path()).unwrap();
        let rows = executor.query("SELECT * FROM results LIMIT 1").unwrap();

        assert_eq!(rows.len(), 1);
        let row = &rows[0];

        assert_eq!(row.get_string("transform"), Some("sha256"));
        assert_eq!(row.get_string("chain"), Some("bitcoin"));
        assert!(row.get("source").is_some());
    }

    #[test]
    fn value_type_methods_work() {
        let str_val = Value::String("test".to_string());
        assert_eq!(str_val.as_string(), Some("test"));
        assert!(str_val.as_i64().is_none());

        let int_val = Value::Int64(42);
        assert_eq!(int_val.as_i64(), Some(42));
        assert!(int_val.as_string().is_none());

        let null_val = Value::Null;
        assert!(null_val.is_null());
        assert!(null_val.as_string().is_none());
    }

    #[test]
    fn refresh_updates_view() {
        let dir = tempdir().unwrap();
        let mut executor = QueryExecutor::new(dir.path()).unwrap();
        assert!(!executor.has_data());

        create_test_storage(dir.path(), "sha256", 5, 0);
        executor.refresh().unwrap();

        assert!(executor.has_data());
        let count = executor
            .query_scalar_i64("SELECT COUNT(*) FROM results")
            .unwrap();
        assert_eq!(count, Some(5));
    }

    #[test]
    fn query_result_methods_work() {
        let dir = tempdir().unwrap();
        create_test_storage(dir.path(), "sha256", 5, 0);

        let executor = QueryExecutor::new(dir.path()).unwrap();
        let result = executor.query_arrow("SELECT * FROM results").unwrap();

        assert!(!result.is_empty());
        assert_eq!(result.row_count(), 5);
        assert!(!result.batches().is_empty());

        let rows = result.rows();
        assert_eq!(rows.len(), 5);
    }

    #[test]
    fn storage_path_returns_path() {
        let dir = tempdir().unwrap();
        let executor = QueryExecutor::new(dir.path()).unwrap();

        assert_eq!(executor.storage_path(), dir.path().to_string_lossy());
    }
}
