# VUKE

Bitcoin key vulnerability research tool. Reproduces historical weak key generation (brainwallets, weak PRNGs, derivation bugs) and analyzes keys for vulnerable origins. Rust, optional WebGPU acceleration.

## Quick Commands

```bash
# Build
cargo build --release
cargo build --release --features gpu          # WebGPU acceleration
cargo build --release --features storage      # Parquet output
cargo build --release --features storage-query # + DuckDB queries

# Test
cargo test                                     # All tests
cargo test test_name -- --exact                # Single test by name
cargo test transform::mt64::tests              # All tests in a module
cargo test --no-fail-fast                      # Don't stop on first failure

# Bench
cargo bench                                    # Criterion benchmarks (codspeed-criterion-compat)

# Release
just release 0.8.0                             # Bump version, changelog, tag, commit
```

No rustfmt.toml or clippy.toml — default Rust formatting and lints apply.

## Codebase Map

```
src/
├── main.rs              # CLI entry (clap derive): generate, scan, single, bench, analyze
├── lib.rs               # Public API exports
├── derive.rs            # Key → addresses/WIF derivation (secp256k1 + bitcoin crate)
├── matcher.rs           # Target address matching
├── network.rs           # Bitcoin network handling
├── benchmark.rs         # Performance utilities
├── provider.rs          # Puzzle data provider (feature: boha)
│
├── transform/           # Forward: Input → Key generation (see src/transform/AGENTS.md)
├── analyze/             # Reverse: Key → origin detection (see src/analyze/AGENTS.md)
├── source/              # Input providers: range, wordlist, timestamps, stdin, files (see src/source/AGENTS.md)
├── output/              # Result formatting: console CSV, multi-output, storage bridge
├── gpu/                 # WebGPU acceleration (see src/gpu/AGENTS.md)
├── storage/             # Parquet/Arrow persistence (see src/storage/AGENTS.md)
│
├── {prng}.rs            # Shared PRNG logic used by BOTH transform/ and analyze/
│                        # (mt64.rs, xorshift.rs, lcg.rs, sha256_chain.rs, electrum.rs, multibit.rs)
└── bitimage.rs          # Bitimage puzzle key integration
```

### Data Flow

- **Generate/Scan**: Source → Transform → KeyDeriver → Matcher → Output
- **Analyze**: Key → Analyzer(s) → AnalysisResult

### Core Traits (all `Send + Sync`)

| Trait | Location | Signature |
|-------|----------|-----------|
| `Transform` | `src/transform/mod.rs` | `apply_batch(&[Input], &mut Vec<(String, Key)>)` |
| `Analyzer` | `src/analyze/mod.rs` | `analyze(&Key, &AnalysisConfig, Option<&ProgressBar>) → AnalysisResult` |
| `Source` | `src/source/mod.rs` | `process(transforms, deriver, matcher, output) → Result<ProcessStats>` |
| `Output` | `src/output/mod.rs` | `key(source, transform, derived)`, `hit(source, transform, derived, match_info)` |
| `StorageBackend` | `src/storage/mod.rs` | `write_batch(&[ResultRecord])`, `flush() → Vec<PathBuf>` |

### Key Types

- `Key` = `[u8; 32]` private key
- `Input` = multi-representation struct (`string_val`, `u64_val`, `bytes_be`, `bytes_le`)
- `DerivedKey` = full derivation (WIF, P2PKH compressed/uncompressed, P2WPKH)

### Where to Add Things

| Task | Where | Then |
|------|-------|------|
| New vulnerability | `src/transform/{name}.rs` + `src/analyze/{name}.rs` | Add to both `TransformType` and `AnalyzerType` enums |
| New PRNG variant | `src/{prng}.rs` (shared) + transform + analyze | Keep config/logic in shared module |
| New input source | `src/source/{name}.rs` | Implement `Source`, update `SourceType` and `main.rs` |
| New output format | `src/output/{name}.rs` | Implement `Output` trait |
| GPU acceleration | `src/gpu/shaders/{algo}.wgsl` + `src/gpu/{algo}.rs` | Feature-gated behind `gpu` |
| Storage backend | `src/storage/{name}.rs` | Implement `StorageBackend` trait |
| CLI changes | `src/main.rs` | clap derive macros |

## Code Conventions

### Imports

Ordered: external crates → std → blank line → `super::` → blank line → `crate::`.

```rust
use anyhow::Result;
use rayon::prelude::*;
use std::path::PathBuf;

use super::Source;

use crate::derive::KeyDeriver;
use crate::transform::{Input, Transform};
```

### Error Handling

- **CLI/top-level**: `anyhow::Result<T>`, `anyhow::bail!()` for errors
- **Domain modules**: Custom error enums (`ElectrumError`, `GpuError`, `ParseError`, `StorageError`) with `Display` + `Error` impls
- **`.unwrap()`**: Present in ~500 call sites (especially GPU code) — pragmatic, not ideal. Prefer `?` in new code
- **No `unsafe`**: Intentional. Maintain memory safety
- **No `panic!()`**: Prefer `Result` types

### Naming

- Types/structs: `PascalCase` (`Mt64Analyzer`, `ConsoleOutput`)
- Functions/methods: `snake_case` (`apply_batch`, `from_string`)
- Constants: `SCREAMING_SNAKE_CASE` (`BATCH_SIZE`, `CURVE_ORDER`)
- Files/modules: `snake_case` (`sha256_chain.rs`, `key_parser.rs`)
- Struct suffixes by role: `{Name}Transform`, `{Name}Analyzer`, `{Name}Source`

### Patterns

- **Batch processing**: All transforms/sources process `&[Input]` batches via Rayon `par_chunks()`
- **Factory enums**: `TransformType::create()`, `AnalyzerType::create()` — parse from CLI strings via `FromStr`
- **Builder pattern**: Used for configuration (`ElectrumTransform::new().with_change()`, `ParquetBackend::new().with_compression()`)
- **Progress bars**: `indicatif::ProgressBar` for long operations
- **Early termination**: `AtomicBool` shared across Rayon threads
- **Cascade filtering**: Required for 64-bit seed spaces (mt64, xorshift) — multi-target verification to avoid false positives
- **Masked analysis**: `(full_key & ((1<<N)-1)) | (1<<(N-1))` for puzzle solving
- **GPU feature gating**: `#[cfg(feature = "gpu")]` on trait methods with CPU fallback as default impl

### Tests

Inline `#[cfg(test)] mod tests` at end of each file. Standard `assert!`/`assert_eq!`. `tempfile` crate for file I/O tests.

```bash
cargo test transform::mt64::tests::test_transform_generates_key -- --exact
```

## Feature Flags

| Flag | What it gates |
|------|---------------|
| `gpu` | WebGPU acceleration (wgpu, pollster, bytemuck) |
| `storage` | Parquet/Arrow output |
| `storage-query` | DuckDB SQL queries on Parquet results (implies `storage`) |
| `storage-cloud` | S3/R2/MinIO upload (implies `storage`) |
| `storage-iceberg` | Iceberg catalog (implies `storage-cloud`) |
| `boha` | Bitcoin puzzle data provider |

No features enabled by default.

## CI

- **crates.yml**: Publish to crates.io on `v*` tags
- **aur.yml**: Publish to AUR on `v*` tags
- **codspeed.yml**: Criterion benchmarks on push to `main` and PRs

No CI-enforced clippy or rustfmt checks.

## Commit Style

Semantic commits: `type(scope): description`

```
fix(output): escape compact CSV fields in console output
test(output): harden CSV edge-case coverage
fix(source): validate descending ranges and guard timestamp counters
```

## Execution Workflow

1. **Explore** — read relevant code before changing it. Understand the trait, the factory enum, existing implementations
2. **Plan** — identify which files need changes. New vulnerability = transform + analyze + shared PRNG + both factory enums + CLI
3. **Edit** — make focused changes. Don't refactor surrounding code
4. **Verify** — run `cargo test` after changes. Run `cargo build --release` if touching feature-gated code. Run specific module tests for targeted verification

## Safety

- Don't commit unless explicitly asked
- Don't push unless explicitly asked
- No secrets in outputs — this tool handles private keys, treat test vectors carefully
- Avoid destructive git operations (force push, reset --hard) unless explicitly requested
- Release profile uses `panic = "abort"` — unrecoverable panics kill the process, so prefer `Result` types

## Complexity Hotspots

| File | Lines | Why |
|------|-------|-----|
| `src/analyze/sha256_chain.rs` | ~843 | Multiple chain variants, GPU support, cascade filtering |
| `src/gpu/sha256_chain.rs` | ~662 | Hybrid CPU-GPU pipeline, cascade |
| `src/analyze/milksad.rs` | ~581 | Full 2^32 brute-force with GPU path |
| `src/analyze/xorshift.rs` | ~511 | Multiple PRNG variants with cascade |
| `src/gpu/hash.rs` | ~538 | Multi-algorithm GPU hashing |

Refactoring potential: common brute-force framework, shared masking utilities, generic cascade formatting across analyzers.
