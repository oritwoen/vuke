# STORAGE MODULE

Persistent storage backends for TB-scale result persistence using columnar formats.

## STRUCTURE

```
storage/
├── mod.rs           # StorageBackend trait, record types, errors
└── (future)
    ├── parquet.rs   # ParquetBackend implementation (#35)
    └── schema.rs    # Arrow schema definition (#34)
```

## WHERE TO LOOK

| Task | Location |
|------|----------|
| Add new backend | Implement `StorageBackend` trait in `{name}.rs` |
| Modify record structure | `mod.rs` - record structs |
| Add error variant | `mod.rs` - `StorageError` enum |
| Schema changes | Future `schema.rs` (#34) |

## CONVENTIONS

- **Feature-gated**: Entire module behind `#[cfg(feature = "storage")]`
- **Chain-agnostic**: Record types support any blockchain (Bitcoin, Ethereum, Solana, etc.)
- **Zero-copy**: Record structs use `&'a str` and `&'a [T]` for efficiency
- **List types**: Variable-length fields (addresses, public_keys) use Arrow List types

## STORAGE BACKEND TRAIT

```rust
pub trait StorageBackend: Send + Sync {
    fn write_batch(&mut self, records: &[ResultRecord<'_>]) -> Result<()>;
    fn flush(&mut self) -> Result<PathBuf>;
    fn schema(&self) -> &Schema;
}
```

## RECORD TYPES

| Type | Purpose |
|------|---------|
| `PrivateKeyRecord` | Private key with all representations (hex, decimal, binary, metadata) |
| `PublicKeyRecord` | Public key with format identifier (compressed, uncompressed, ed25519) |
| `AddressRecord` | Blockchain address with type (p2pkh, p2wpkh, eth, sol) |
| `ExportFormatRecord` | Key export format (wif_compressed, wif_uncompressed) |
| `ResultRecord` | Complete record combining all above + metadata |

## ERROR TYPES

| Variant | When |
|---------|------|
| `Io` | File system operations fail |
| `Parquet` | Parquet encoding/writing fails |
| `Arrow` | Arrow array operations fail |
| `SchemaMismatch` | Record doesn't match expected schema |
| `NotInitialized` | Backend used before initialization |
| `Other` | Catch-all for other errors |

## RELATED ISSUES

- #25 - Parent: TB-scale Parquet-based storage
- #33 - StorageBackend trait definition (this)
- #34 - Arrow schema for results
- #35 - ParquetBackend implementation
- #36 - Automatic chunk rotation
- #37 - Basic partitioning (transform/date)
- #38 - CLI `--storage` flag integration

## DEPENDENCIES

```toml
[features]
storage = ["parquet", "arrow"]

[dependencies]
parquet = { version = "54", optional = true, features = ["arrow", "zstd"] }
arrow = { version = "54", optional = true }
```

Enable with: `cargo build --features storage`
