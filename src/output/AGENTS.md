# OUTPUT MODULE

Result formatting for generated and matched keys.

## STRUCTURE

```
output/
├── mod.rs           # Output trait, escape_csv_field()
├── console.rs       # Stdout and file output (compact CSV + verbose YAML)
├── multi.rs         # Multi-output dispatcher (fan-out to multiple outputs)
├── storage.rs       # Parquet backend bridge (feature: storage)
└── query_format.rs  # DuckDB result formatting (feature: storage-query)
```

## OUTPUT TRAIT

```rust
pub trait Output: Send + Sync {
    fn key(&self, source: &str, transform: &str, derived: &DerivedKey) -> Result<()>;
    fn hit(&self, source: &str, transform: &str, derived: &DerivedKey, match_info: &MatchInfo) -> Result<()>;
    fn flush(&self) -> Result<()>;
}
```

## CONVENTIONS

- **CSV escaping**: Use `escape_csv_field()` from `mod.rs` for any field written to CSV
- **Compact format**: `source,transform,privkey_hex,address` — default for file output
- **Verbose format**: YAML-like multi-line — for console stdout
- **Thread safety**: All outputs must be `Send + Sync` (use interior mutability where needed)
- **Flush**: Always call `flush()` at end of processing to ensure all data is written

## WHERE TO LOOK

| Task | Location |
|------|----------|
| Add new output format | Create `{name}.rs`, implement `Output` trait |
| Fix CSV formatting | `mod.rs` for escaping, `console.rs` for field assembly |
| Multi-output behavior | `multi.rs` — dispatches to Vec<Box<dyn Output>> |
| Storage output | `storage.rs` — bridges Output trait to StorageBackend |
| Query result display | `query_format.rs` — table, CSV, JSON formatting |

## ADDING A NEW OUTPUT

1. Create `src/output/{name}.rs`
2. Implement `Output` trait with `key()`, `hit()`, `flush()`
3. Add `mod {name};` and `pub use` in `mod.rs`
4. Wire up in `src/main.rs` where outputs are constructed
