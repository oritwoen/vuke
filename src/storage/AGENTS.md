# STORAGE MODULE

Persistent storage backends for TB-scale result persistence using columnar formats.

## STRUCTURE

```
storage/
├── mod.rs              # StorageBackend trait, record types, errors
├── schema.rs           # Arrow schema definition + records_to_batch conversion (#34)
└── parquet_backend.rs  # ParquetBackend with auto chunk rotation (#35, #36)
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

## CONVENTIONS

- **Feature-gated**: Entire module behind `#[cfg(feature = "storage")]`
- **Chain-agnostic**: Record types support any blockchain (Bitcoin, Ethereum, Solana, etc.)
- **Zero-copy**: Record structs use `&'a str` and `&'a [T]` for efficiency
- **Flat schema**: Variable-length fields (addresses, public_keys) mapped to fixed columns for SQL-friendly querying
- **Auto-chunking**: ParquetBackend rotates files at configurable record/byte thresholds

## ARROW SCHEMA (19 columns)

| Column | Type | Nullable | Description |
|--------|------|----------|-------------|
| source | Utf8 | No | Input value (seed, passphrase) |
| transform | Utf8 | No | Transform name (sha256, milksad) |
| chain | Utf8 | No | Blockchain (bitcoin, ethereum) |
| timestamp | Timestamp(ms, UTC) | No | Generation time |
| matched_target | Utf8 | Yes | Matched address (scan hits only) |
| private_key_raw | FixedSizeBinary(32) | No | Raw 32-byte key |
| private_key_hex | Utf8 | No | Hex representation |
| private_key_decimal | Utf8 | No | Decimal representation |
| private_key_binary | Utf8 | No | Binary representation (256 chars) |
| private_key_bit_length | UInt16 | No | Effective bit length |
| private_key_hamming_weight | UInt16 | No | Number of 1-bits |
| private_key_leading_zeros | UInt8 | No | Leading zeros in hex |
| pubkey_compressed | Utf8 | Yes | Compressed public key |
| pubkey_uncompressed | Utf8 | Yes | Uncompressed public key |
| address_p2pkh_compressed | Utf8 | Yes | P2PKH (compressed) |
| address_p2pkh_uncompressed | Utf8 | Yes | P2PKH (uncompressed) |
| address_p2wpkh | Utf8 | Yes | P2WPKH (native segwit) |
| wif_compressed | Utf8 | Yes | WIF compressed |
| wif_uncompressed | Utf8 | Yes | WIF uncompressed |

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
| `with_chunk_bytes(n)` | 100MB | Rotate after N bytes (in-memory Arrow size, not compressed) |
| `without_chunking()` | - | Disable auto-rotation |
| `with_compression(c)` | ZSTD | Set compression algorithm |

Hive-style partitioning: `transform={name}/date={YYYY-MM-DD}/chunk_{NNNN}.parquet`

Output structure:
```
results/
  transform=milksad/
    date=2025-01-15/
      chunk_0001.parquet
      chunk_0002.parquet
  transform=sha256/
    date=2025-01-15/
      chunk_0001.parquet
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
- #33 - StorageBackend trait definition (done)
- #34 - Arrow schema for results (done)
- #35 - ParquetBackend implementation (done)
- #36 - Automatic chunk rotation (done)
- #37 - Basic partitioning (transform/date) (done)
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
