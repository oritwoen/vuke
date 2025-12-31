# ANALYZE MODULE

Reverse-engineer private key origins by detecting vulnerable generation patterns.

## STRUCTURE

```
analyze/
├── mod.rs           # Analyzer trait, AnalyzerType enum, AnalysisResult
├── key_parser.rs    # Parse hex/WIF/decimal keys
├── output.rs        # Plain text and JSON formatting
├── milksad.rs       # MT19937 brute-force (2^32 seeds) - GPU accelerated
├── mt64.rs          # MT19937-64 brute-force (requires cascade)
├── lcg.rs           # LCG variants brute-force (2^31-32)
├── xorshift.rs      # Xorshift brute-force (requires cascade)
├── sha256_chain.rs  # SHA256 chain brute-force - GPU accelerated
├── multibit.rs      # MultiBit HD mnemonic verification
├── direct.rs        # Pattern detection (ASCII, small seeds)
└── heuristic.rs     # Statistical analysis (entropy, hamming)
```

## WHERE TO LOOK

| Task | Location |
|------|----------|
| Add new analyzer | Create `{name}.rs`, add to `mod.rs`, extend `AnalyzerType` |
| GPU acceleration | Implement `supports_gpu()` + `analyze_gpu()` |
| Masking support | Implement `supports_mask()`, use `config.mask_bits` |
| Cascade filtering | Use `config.cascade_targets` for multi-target verification |
| Result formatting | `output.rs` for text/JSON |

## CONVENTIONS

- **Brute-force**: Use Rayon `par_iter()` for CPU parallelism
- **Progress bar**: Use `indicatif::ProgressBar` for long operations
- **Early termination**: Use `AtomicBool` for found flag across threads
- **Cascade required**: 64-bit seed spaces (mt64, xorshift) MUST use cascade filter
- **Shared logic**: PRNG implementations in `src/{prng}.rs`, reuse here

## ANALYZER TRAIT

```rust
pub trait Analyzer: Send + Sync {
    fn name(&self) -> &'static str;
    fn analyze(&self, key: &Key, config: &AnalysisConfig, progress: Option<&ProgressBar>) -> AnalysisResult;
    fn supports_mask(&self) -> bool { false }
    fn is_brute_force(&self) -> bool { false }
    fn supports_gpu(&self) -> bool { false }
    fn analyze_gpu(&self, ctx: &GpuContext, key: &Key, config: &AnalysisConfig, progress: Option<&ProgressBar>) -> Result<AnalysisResult>;
}
```

## ANALYSIS CONFIG

```rust
pub struct AnalysisConfig {
    pub mask_bits: Option<u8>,           // N-bit masking for puzzles
    pub cascade_targets: Option<Vec<CascadeTarget>>,  // Multi-target verification
}
```

**Masking formula**: `masked = (full_key & ((1<<N)-1)) | (1<<(N-1))`

## ANALYSIS STATUS

| Status | Symbol | Meaning |
|--------|--------|---------|
| `Confirmed` | `✓` | Exact seed/origin found |
| `Possible` | `?` | Heuristics suggest vulnerability |
| `NotFound` | `✗` | Exhaustive search, no match |
| `Unknown` | `?` | Cannot determine |

## CASCADE FILTERING

For large seed spaces (2^64), verify against multiple targets:

```bash
vuke analyze 0x15 --analyzer mt64 --cascade "5:0x15,10:0x202,20:0xd2c55"
```

Each cascade target must match at its bit width to confirm.

## COMPLEXITY HOTSPOTS

- `sha256_chain.rs` (842 lines) - Multiple variants, GPU support, cascade
- `milksad.rs` (580 lines) - Full 2^32 brute-force with GPU
- `xorshift.rs` (510 lines) - Multiple PRNG variants with cascade
