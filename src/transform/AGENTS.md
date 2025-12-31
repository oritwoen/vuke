# TRANSFORM MODULE

Forward key generation from inputs using various algorithms.

## STRUCTURE

```
transform/
├── mod.rs           # Transform trait, TransformType enum
├── input.rs         # Input struct (string/u64/bytes representations)
├── sha256.rs        # SHA256(input) - classic brainwallet
├── double_sha256.rs # SHA256(SHA256(input))
├── md5.rs           # MD5 duplicated to 32 bytes
├── direct.rs        # Raw bytes padded to 32 bytes
├── milksad.rs       # MT19937 with 32-bit seed
├── mt64.rs          # MT19937-64 with 64-bit seed
├── lcg.rs           # LCG variants (glibc, minstd, msvc, borland)
├── xorshift.rs      # Xorshift variants (64, 128, 128plus, xoroshiro)
├── sha256_chain.rs  # Deterministic SHA256 chains
├── multibit.rs      # MultiBit HD seed-as-entropy bug
├── electrum.rs      # Electrum pre-BIP39 derivation
└── armory.rs        # Armory HD derivation
```

## WHERE TO LOOK

| Task | Location |
|------|----------|
| Add new transform | Create `{name}.rs`, add to `mod.rs`, extend `TransformType` enum |
| GPU support | Implement `supports_gpu()` + `apply_batch_gpu()` methods |
| Input handling | `input.rs` - modify `Input` struct |
| Variant params | Use `{Name}Config` struct pattern (see `lcg.rs`) |

## CONVENTIONS

- **Trait impl**: Every transform implements `Transform` trait with `name()` and `apply_batch()`
- **Batch processing**: Always process `&[Input]` → `&mut Vec<(String, Key)>`
- **GPU optional**: Return `false` from `supports_gpu()` if CPU-only
- **Source string**: First tuple element is human-readable source description
- **Shared logic**: PRNG implementations live in `src/{prng}.rs`, not here

## TRANSFORM TRAIT

```rust
pub trait Transform: Send + Sync {
    fn name(&self) -> &'static str;
    fn apply_batch(&self, inputs: &[Input], output: &mut Vec<(String, Key)>);
    fn supports_gpu(&self) -> bool { false }
    fn apply_batch_gpu(&self, ctx: &GpuContext, inputs: &[Input], output: &mut Vec<(String, Key)>) -> Result<()>;
}
```

## INPUT STRUCT

```rust
pub struct Input {
    pub string_val: String,   // Original string (passphrases)
    pub u64_val: u64,         // Numeric value (seeds)
    pub bytes_be: [u8; 8],    // Big-endian bytes
    pub bytes_le: [u8; 8],    // Little-endian bytes
}
```

Constructors: `from_string()`, `from_u64()`, `from_bytes()`

## ADDING A NEW TRANSFORM

1. Create `src/transform/{name}.rs`
2. Implement `Transform` trait
3. Add module to `mod.rs`
4. Add variant to `TransformType` enum
5. Update `TransformType::create()` and `from_str()`
6. Add corresponding analyzer in `src/analyze/{name}.rs` if reversible
