# VUKE - PROJECT KNOWLEDGE BASE

**Generated:** 2025-12-31
**Commit:** c1f2d45
**Branch:** main

## OVERVIEW

Bitcoin key vulnerability research tool - reproduces historical weak key generation (brainwallets, weak PRNGs, derivation bugs) and analyzes keys for vulnerable origins. Rust + optional WebGPU acceleration.

## STRUCTURE

```
vuke/
├── src/
│   ├── analyze/      # Reverse-engineer key origins (brute-force, heuristics)
│   ├── transform/    # Forward key generation (SHA256, PRNGs, derivation)
│   ├── gpu/          # WebGPU acceleration (WGSL shaders, pipelines)
│   ├── source/       # Input providers (range, wordlist, timestamps, stdin)
│   ├── output/       # Result formatting (console, files)
│   ├── storage/      # Parquet/Arrow TB-scale persistence
│   ├── main.rs       # CLI: generate, scan, single, bench, analyze commands
│   ├── lib.rs        # Library exports
│   ├── derive.rs     # Key → addresses/WIF derivation
│   ├── matcher.rs    # Target address matching
│   └── {prng}.rs     # Shared PRNG logic (lcg, xorshift, mt64, sha256_chain)
├── benches/          # Criterion benchmarks (codspeed-criterion-compat)
└── src/gpu/shaders/  # WGSL compute shaders
```

## WHERE TO LOOK

| Task | Location | Notes |
|------|----------|-------|
| Add new vulnerability | `src/transform/{name}.rs` + `src/analyze/{name}.rs` | Implement both Transform and Analyzer |
| Add PRNG variant | `src/{prng}.rs` shared logic + transform + analyze | Keep config/logic in shared module |
| GPU acceleration | `src/gpu/shaders/{algo}.wgsl` + `src/gpu/{algo}.rs` | Feature-gated behind `gpu` |
| New input source | `src/source/{name}.rs` | Implement Source trait |
| New output format | `src/output/{name}.rs` | Implement Output trait |
| CLI changes | `src/main.rs` | clap derive macros |
| Key derivation | `src/derive.rs` | secp256k1 + bitcoin crate |
| Storage backend | `src/storage/{name}.rs` | Implement StorageBackend trait |

## CODE MAP

**Core Traits** (all require `Send + Sync`):

| Trait | Location | Purpose |
|-------|----------|---------|
| `Transform` | `src/transform/mod.rs` | Input → Key generation |
| `Analyzer` | `src/analyze/mod.rs` | Key origin detection |
| `Source` | `src/source/mod.rs` | Input batch processing |
| `Output` | `src/output/mod.rs` | Result formatting |
| `StorageBackend` | `src/storage/mod.rs` | Persistent result storage |

**Data Flow**:
- **Generate/Scan**: Source → Transform → KeyDeriver → Matcher → Output
- **Analyze**: Key → Analyzer(s) → AnalysisResult

**Key Types**:
- `Key`: `[u8; 32]` private key
- `Input`: Multi-representation (string, u64, bytes_be/le)
- `DerivedKey`: Full derivation (WIF, P2PKH, P2WPKH)

## CONVENTIONS

- **PRNG shared logic**: Common implementations in `src/{prng}.rs`, used by both transform and analyze
- **GPU optional**: Feature-gated, graceful CPU fallback via `supports_gpu()` + `apply_batch_gpu()`
- **Variant configs**: `{Prng}Variant` enums + `{Prng}Config` structs for parameterization
- **Cascade filtering**: Multi-target verification for 64-bit seed spaces (mt64, xorshift)
- **Masked analysis**: `(full_key & mask) | (1 << (bits-1))` for puzzle solving
- **Batch processing**: Always `&[Input]` → `&mut Vec<(String, Key)>`
- **Progress bars**: Use `indicatif::ProgressBar` for long operations
- **Early termination**: Use `AtomicBool` for found flag across threads

## ANTI-PATTERNS (THIS PROJECT)

- **Excessive `.unwrap()`**: 125+ instances, especially in GPU code - should use `?` operator
- **No unsafe blocks**: Intentional, maintain memory safety
- **No panic!()**: Prefer Result types
- **No type suppression**: Never `as any`, `@ts-ignore` equivalent

## TRANSFORMS

| Name | Seed Size | Description |
|------|-----------|-------------|
| `sha256` | - | Classic brainwallet |
| `double_sha256` | - | Bitcoin-style hash |
| `md5` | - | Legacy weak hash |
| `milksad` | 32-bit | MT19937 (CVE-2023-39910) |
| `mt64` | 64-bit | MT19937-64 |
| `lcg:{variant}:{endian}` | 31-32 bit | glibc/minstd/msvc/borland |
| `xorshift:{variant}` | 64-bit | 64/128/128plus/xoroshiro |
| `sha256_chain:{variant}` | 32-bit | iterated/indexed/counter |
| `multibit` | - | MultiBit HD seed-as-entropy bug |
| `electrum` | - | Pre-BIP39 derivation |
| `armory` | - | Pre-BIP32 HD |

## ANALYZERS

| Name | Method | GPU | Notes |
|------|--------|-----|-------|
| `milksad` | 2^32 brute-force | Yes | Supports mask/cascade |
| `mt64` | 2^64 w/ cascade | No | Requires cascade filter |
| `lcg` | 2^31-32 brute-force | No | Multi-variant |
| `xorshift` | 2^64 w/ cascade | No | Multi-variant |
| `sha256_chain` | 2^32 + depth | Yes | Iterated/indexed |
| `multibit-hd` | Mnemonic test | No | Dictionary attack support |
| `direct` | Pattern detect | No | ASCII, small seeds |
| `heuristic` | Statistical | No | Entropy, hamming |

## COMMANDS

```bash
# Dev
cargo test                    # Run tests
cargo build --release         # Build optimized
cargo build --release --features gpu      # With GPU
cargo build --release --features storage  # With Parquet

# Benchmarks
cargo bench                   # Run benchmarks

# Release (via justfile)
just release 0.8.0           # Bump version, changelog, tag

# CI
# - crates.yml: Publish to crates.io on tags
# - aur.yml: Publish to AUR on tags
# - codspeed.yml: Benchmark on push/PR
```

## NOTES

- **GPU feature**: Compile with `--features gpu` for WebGPU acceleration
- **Storage feature**: Compile with `--features storage` for Parquet output
- **Release profile**: Aggressive optimization (LTO, single codegen unit, stripped)
- **Large files**: `src/analyze/sha256_chain.rs` (843L), `src/gpu/sha256_chain.rs` (662L) - complexity hotspots with refactoring potential
- **Rust 2021 edition**, requires Rust 1.70+
- **TODO**: GPU for generate/scan needs Source trait redesign (main.rs:322)
- **Refactoring opportunity**: Extract common brute-force framework, masking utilities, cascade formatting across analyzers
