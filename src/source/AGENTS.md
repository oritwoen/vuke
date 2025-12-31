# SOURCE MODULE

Input providers for key generation pipelines.

## STRUCTURE

```
source/
├── mod.rs        # Source trait, SourceType enum, ProcessStats
├── range.rs      # Numeric range source (weak seed testing)
├── wordlist.rs   # File-based wordlist (brainwallet analysis)
├── timestamps.rs # Date range → Unix timestamps (time-based PRNG)
└── stdin.rs      # Streaming from stdin (pipeline integration)
```

## WHERE TO LOOK

| Task | Location |
|------|----------|
| Add new source | Create `{name}.rs`, add to `mod.rs`, extend `SourceType` enum |
| Batch processing | See `range.rs` for Rayon parallel pattern |
| Progress reporting | Use `indicatif::ProgressBar` in `process()` |
| CLI integration | Update `src/main.rs` `SourceCommand` enum |

## SOURCE TRAIT

```rust
pub trait Source: Send + Sync {
    fn process<T, O>(
        &self,
        transforms: &[T],
        deriver: &KeyDeriver,
        matcher: Option<&Matcher>,
        output: &mut O,
        no_gpu: bool,
        progress: Option<&ProgressBar>,
    ) -> ProcessStats
    where
        T: Transform,
        O: Output;
}
```

## CONVENTIONS

- **Batch processing**: Use Rayon `par_chunks()` for parallelism
- **Progress bars**: Report progress via optional `ProgressBar`
- **Thread safety**: All sources must be `Send + Sync`
- **Streaming**: StdinSource processes line-by-line for memory efficiency

## ADDING A NEW SOURCE

1. Create `src/source/{name}.rs`
2. Implement `Source` trait with `process()` method
3. Add `mod {name};` and `pub use` in `mod.rs`
4. Add variant to `SourceType` enum with `create()` and `from_str()`
5. Update `SourceCommand` enum in `src/main.rs`
6. Update `create_source()` function in `src/main.rs`

## EXISTING SOURCES

| Source | Input | Use Case |
|--------|-------|----------|
| `RangeSource` | `start..end` u64 | Weak seed brute-force |
| `WordlistSource` | File path | Brainwallet dictionary attack |
| `TimestampSource` | Date range | Time-based PRNG exploitation |
| `StdinSource` | Stdin pipe | Pipeline integration |
