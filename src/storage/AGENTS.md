# STORAGE MODULE

Persistent storage backends for TB-scale result persistence using columnar formats.

## STRUCTURE

```
storage/
├── mod.rs              # StorageBackend trait, record types, errors
├── schema.rs           # Arrow schema definition + records_to_batch conversion
├── parquet_backend.rs  # ParquetBackend with auto chunk rotation
└── query.rs            # DuckDB query executor (feature: storage-query)
```

## WHERE TO LOOK

| Task | Location |
|------|----------|
| Add new backend | Implement `StorageBackend` trait in `{name}.rs` |
| Modify record structure | `mod.rs` - record structs |
| Add error variant | `mod.rs` - `StorageError` enum |
| Schema changes | `schema.rs` - Arrow schema + field constants |
| Add new column | `schema.rs` - update `result_schema()` + `records_to_batch()` |
| Chunk rotation logic | `parquet_backend.rs` - `should_rotate()`, `rotate_chunk()` |
| Query stored results | `query.rs` - `QueryExecutor` (requires `storage-query` feature) |

## CONVENTIONS

- **Feature-gated**: Entire module behind `#[cfg(feature = "storage")]`
- **Chain-agnostic**: Record types support any blockchain (Bitcoin, Ethereum, Solana)
- **Zero-copy**: Record structs use `&'a str` and `&'a [T]` for efficiency
- **Flat schema**: Variable-length fields mapped to fixed columns for SQL-friendly querying
- **Auto-chunking**: ParquetBackend rotates files at configurable thresholds

## STORAGE BACKEND TRAIT

```rust
pub trait StorageBackend: Send + Sync {
    fn write_batch(&mut self, records: &[ResultRecord<'_>]) -> Result<()>;
    fn flush(&mut self) -> Result<Vec<PathBuf>>;
    fn schema(&self) -> &Schema;
}
```

## PARQUET BACKEND

```rust
ParquetBackend::new("results/", "milksad")
    .with_compression(Compression::ZSTD(Default::default()))
    .with_chunk_records(1_000_000)
    .with_chunk_bytes(100 * 1024 * 1024)
```

| Method | Default | Description |
|--------|---------|-------------|
| `with_chunk_records(n)` | 1M | Rotate after N records |
| `with_chunk_bytes(n)` | 100MB | Rotate after N bytes |
| `without_chunking()` | - | Disable auto-rotation |

**Hive-style partitioning**: `transform={name}/date={YYYY-MM-DD}/chunk_{NNNN}.parquet`

## QUERY EXECUTOR (feature: storage-query)

```rust
let executor = QueryExecutor::new("./results")?;

// Returns Arrow RecordBatches (zero-copy)
let result = executor.query_arrow("SELECT * FROM results WHERE transform = 'milksad'")?;
for batch in result.batches() { ... }

// Returns Vec<Row> (simple iteration)
let rows = executor.query("SELECT transform, COUNT(*) FROM results GROUP BY transform")?;
for row in rows {
    println!("{}: {}", row.get_string("transform")?, row.get_i64("count")?);
}

// Scalar queries
let count: Option<i64> = executor.query_scalar_i64("SELECT COUNT(*) FROM results")?;
```

| Method | Returns | Use Case |
|--------|---------|----------|
| `query_arrow(sql)` | `QueryResult` (RecordBatches) | High performance, Arrow ecosystem |
| `query(sql)` | `Vec<Row>` | Simple iteration |
| `query_scalar_i64(sql)` | `Option<i64>` | COUNT, SUM, etc. |
| `query_scalar_string(sql)` | `Option<String>` | Single string value |
| `schema()` | `Option<Schema>` | Introspect result schema |
| `discovered_files()` | `Vec<String>` | List Parquet files |
| `refresh()` | `()` | Recreate view after new writes |

**Auto-discovery**: Creates `results` view from `{path}/**/*.parquet` with Hive partitioning enabled.

## ARROW SCHEMA (19 columns)

Core columns: `source`, `transform`, `chain`, `timestamp`, `matched_target`
Key columns: `private_key_raw`, `private_key_hex`, `private_key_decimal`, `private_key_binary`, `private_key_bit_length`, `private_key_hamming_weight`, `private_key_leading_zeros`
Derived columns: `pubkey_compressed`, `pubkey_uncompressed`, `address_p2pkh_*`, `address_p2wpkh`, `wif_*`

## DEPENDENCIES

```toml
parquet = { version = "54", optional = true, features = ["arrow", "zstd"] }
arrow = { version = "54", optional = true }
duckdb = { version = "1.4", optional = true, features = ["bundled"] }
```

Enable storage: `cargo build --features storage`
Enable query: `cargo build --features storage-query`
