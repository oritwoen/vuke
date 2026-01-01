# vuke

[![CodSpeed](https://img.shields.io/endpoint?url=https://codspeed.io/badge.json)](https://codspeed.io/gh/oritwoen/vuke)

Research tool for analyzing and reproducing vulnerable Bitcoin key generation.

## Features

- **Modular architecture** - pluggable sources and transforms
- **Multiple input sources**
  - Numeric ranges (test weak seeds)
  - Wordlists (brainwallet analysis)
  - Timestamps (time-based PRNG exploitation)
  - Stdin streaming (pipeline integration)
- **Historical vulnerability transforms**
  - Direct (raw bytes as key)
  - SHA256 (classic brainwallet)
  - Double SHA256 (Bitcoin-style hashing)
  - MD5 (legacy weak hashing)
  - SHA256 chain (iterated/indexed deterministic derivation)
  - Milksad (MT19937 PRNG - CVE-2023-39910)
  - MultiBit HD (seed-as-entropy bug)
  - Electrum pre-BIP39 (2011-2014 deterministic derivation)
  - Armory (legacy HD derivation)
- **Key origin analysis** - reverse detection of vulnerable generation methods
- **Parallel processing** via Rayon
- **Address matching** for scanning known targets
- **File output** for saving results
- **Pure Rust** implementation

## Why This Project?

This tool is designed for **security research** - understanding how vulnerable keys were generated in the past helps improve modern wallet security.

Historical vulnerabilities this tool can reproduce:

| Vulnerability | Year | Impact |
|--------------|------|--------|
| Brainwallets | 2011-2015 | SHA256(passphrase) easily cracked |
| Weak PRNGs | 2013-2023 | Predictable seeds (timestamps, PIDs) |
| [Milksad](https://milksad.info/) | 2023 | libbitcoin `bx` used MT19937 with 32-bit seeds |
| [MultiBit HD](https://github.com/Multibit-Legacy/multibit-hd/issues/445) | 2014-2016 | 64-byte BIP39 seed used as entropy |
| Electrum pre-BIP39 | 2011-2014 | Custom deterministic derivation with weak stretching |
| Armory HD | 2012-2016 | Pre-BIP32 deterministic derivation |
| LCG PRNGs | 1990s-2010s | glibc rand(), MINSTD, MSVC - only 31-32 bit state |
| Xorshift PRNGs | 2003-present | V8/SpiderMonkey Math.random() - 64-128 bit state |
| SHA256 chains | 2010s-present | Deterministic key derivation from weak seeds |

## Installation

### Cargo

```bash
cargo install vuke
```

### From source

```bash
git clone https://github.com/oritwoen/vuke
cd vuke
cargo build --release
```

## Usage

### Generate single key from passphrase

```bash
vuke single "correct horse battery staple" --transform sha256
```

Output:
```
Passphrase: "correct horse battery staple"
Transform: sha256
Source: correct horse battery staple
---
Private Key (hex):     c4bbcb1fbec99d65bf59d85c8cb62ee2db963f0fe106f483d9afa73bd4e39a8a
WIF (compressed):      L3p8oAcQTtuokSCRHQ7i4MhjWc9zornvpJLfmg62sYpLRJF9woSu
---
P2PKH (compressed):   1JwSSubhmg6iPtRjtyqhUYYH7bZg3Lfy1T
P2WPKH:               bc1qfnpg7ceg02y64qrskgz0drwp3y6hma3q6wvnzr
```

### Scan wordlist for known addresses

```bash
vuke scan --transform=sha256 --targets known_addresses.txt wordlist --file passwords.txt
```

### Test numeric range (weak seeds)

```bash
vuke generate --transform=milksad range --start 1 --end 1000000
```

### Test LCG-based keys

```bash
# Generate keys using glibc rand() (default big-endian)
vuke generate --transform=lcg:glibc range --start 1 --end 1000000

# Use MINSTD variant with big-endian byte order
vuke generate --transform=lcg:minstd:be range --start 1 --end 1000

# Test all LCG variants at once
vuke generate --transform=lcg range --start 1 --end 100
```

### Test xorshift-based keys

```bash
# Generate keys using all xorshift variants (requires cascade filter for analysis)
vuke generate --transform=xorshift range --start 1 --end 1000000

# Use specific variant
vuke generate --transform=xorshift:64 range --start 1 --end 1000
vuke generate --transform=xorshift:128 range --start 1 --end 1000
vuke generate --transform=xorshift:128plus range --start 1 --end 1000
vuke generate --transform=xorshift:xoroshiro range --start 1 --end 1000
```

### Test timestamp-based keys

```bash
vuke scan --transform=sha256 --targets addresses.txt timestamps --start 2015-01-01 --end 2015-01-31
```

### Multiple transforms

```bash
vuke scan --transform=sha256 --transform=double_sha256 --transform=md5 --targets addresses.txt wordlist --file words.txt
```

### Pipe from stdin

```bash
cat passwords.txt | vuke generate --transform=sha256 stdin
```

### Save results to file

```bash
vuke generate --output results.csv range --start 1 --end 1000000
vuke generate --output results.txt --verbose range --start 1 --end 1000
vuke scan --output hits.txt --targets addresses.txt wordlist --file passwords.txt
```

### Persistent storage (Parquet)

Store results in Parquet format for TB-scale analysis (requires `storage` feature):

```bash
# Build with storage support
cargo build --release --features storage

# Store generated keys to Parquet
vuke generate --storage ./results --transform milksad range --start 1 --end 1000000

# Configure chunk rotation
vuke generate --storage ./results --chunk-records 500000 --chunk-bytes 50M range --start 1 --end 10000000

# Configure compression (default: zstd level 3)
vuke generate --storage ./results --compression zstd --compression-level 9 range --start 1 --end 1000000

# No compression (fastest writes)
vuke generate --storage ./results --compression none range --start 1 --end 1000000

# Available algorithms: none, snappy, gzip, lz4, zstd
```

### Query stored results (SQL)

Query stored Parquet files using SQL (requires `storage-query` feature):

```bash
# Build with query support
cargo build --release --features storage-query

# Count results by transform
vuke query ./results "SELECT transform, COUNT(*) FROM results GROUP BY transform"

# Find matches
vuke query ./results "SELECT * FROM results WHERE matched_target IS NOT NULL LIMIT 10"

# Export to JSON
vuke query ./results --format json "SELECT source, wif_compressed FROM results LIMIT 100"

# Export to CSV
vuke query ./results --format csv "SELECT address_p2pkh_compressed, wif_compressed FROM results" > export.csv

# Show schema
vuke query ./results --schema
```

Output formats: `table` (default), `json`, `csv`

### Benchmark transforms

```bash
vuke bench --transform milksad
```

### Analyze private key origin

Check if a private key could have been generated by a vulnerable method:

```bash
vuke analyze c4bbcb1fbec99d65bf59d85c8cb62ee2db963f0fe106f483d9afa73bd4e39a8a
```

Output:
```
Private Key: c4bbcb1fbec99d65bf59d85c8cb62ee2db963f0fe106f483d9afa73bd4e39a8a
Bit Length:  256
Hamming Weight: 144
---
Analysis:
  ✗ milksad: NOT_FOUND (checked 4294967296 seeds)
  ✗ direct: NOT_FOUND (no direct patterns detected)
  ? heuristic: UNKNOWN (entropy=5.00, hamming=144)
```

Fast mode (skip brute-force):

```bash
vuke analyze --fast L3p8oAcQTtuokSCRHQ7i4MhjWc9zornvpJLfmg62sYpLRJF9woSu
```

JSON output:

```bash
vuke analyze --fast --json c4bbcb1f...
```

Specific analyzer:

```bash
vuke analyze --analyzer milksad c4bbcb1f...
```

### LCG analyzer

Check if a key was generated using a Linear Congruential Generator:

```bash
# Check all LCG variants
vuke analyze --analyzer lcg <KEY>

# Check specific variant and endianness
vuke analyze --analyzer lcg:glibc:le <KEY>

# With masking for puzzle analysis
vuke analyze --analyzer lcg:glibc --mask 5 0x15
```

### Masked key analysis (BTC1000-style puzzles)

Some Bitcoin puzzles use a masking scheme where:
1. A full 256-bit key is generated (e.g., from MT19937)
2. The key is masked to N bits with highest bit forced to 1

Formula: `masked_key = (full_key & (2^N - 1)) | 2^(N-1)`

```bash
# Analyze 5-bit puzzle key 0x15
vuke analyze 0x15 --mask 5 --analyzer milksad
```

Output:
```
Private Key: 0000000000000000000000000000000000000000000000000000000000000015
Bit Length:  5
Hamming Weight: 3
---
Analysis:
  ✓ milksad: CONFIRMED (seed=1610000002, full_key=7ed2...5055, masked=0x15, mask_bits=5, formula=(key & 0x1f) | 0x10)
```

```bash
# Analyze 10-bit puzzle key
vuke analyze 0x202 --mask 10 --analyzer milksad
```

### Cascading filter (multi-puzzle verification)

When analyzing masked keys, a single small-bit match has high false positive rates.
The cascading filter verifies candidates against multiple known puzzle keys:

```bash
# Verify seed against multiple puzzles with increasing bit widths
vuke analyze 0x16 --analyzer milksad --cascade "5:0x16,10:0x273,15:0x7a85"
```

Output:
```
Private Key: 0000000000000000000000000000000000000000000000000000000000000016
Bit Length:  5
Hamming Weight: 3
---
Analysis:
  ✓ milksad: CONFIRMED (seed=100 (0x00000064))
  P5: target=0x16, full_key=08961c8b18dbd0ab4337434767df7b69572fad6c4f00c186b03f43d88af70a26
  P10: target=0x273, full_key=5e413501b4371e2862271f1f3550bc2f4236b6abe29ec9350e166bd322c3e673
  P15: target=0x7a85, full_key=f133ff22f0aac1de185139938f664d10e4ac2de46be7d29f3c458e353a1efa85)
```

The cascade format is `bits:target,bits:target,...` where:
- `bits` is the mask width (1-64)
- `target` is hex (with 0x prefix) or decimal

Probability analysis:
- P5 alone: 1/16 chance of false positive
- P5 + P10: 1/16 × 1/512 = 1/8192
- P5 + P10 + P15: virtually impossible false positive

### MT19937-64 analyzer (64-bit seeds)

For testing 64-bit seed hypotheses, the `mt64` analyzer **requires** cascade filter
(64-bit seed space is not exhaustively searchable):

```bash
# MT19937-64 cascade search - REQUIRES cascade filter
vuke analyze 0x15 --analyzer mt64 --cascade "5:0x15,10:0x202,20:0xd2c55,30:0x3d94cd64"
```

Progress shows search rate and cascade filter hits:
```
⠋ Searched: 1200000 seeds | Rate: 850K/s | Elapsed: 1.4s | Cascade hits: 73
```

### Xorshift analyzer (64-bit seeds)

Xorshift PRNGs (used in V8/SpiderMonkey JavaScript engines) also require cascade filter
due to 64-bit seed space:

```bash
# Test all xorshift variants
vuke analyze 0x15 --analyzer xorshift --cascade "5:0x15,10:0x202,20:0xd2c55"

# Test specific variant
vuke analyze 0x15 --analyzer xorshift:64 --cascade "5:0x15,10:0x202,20:0xd2c55"
vuke analyze 0x15 --analyzer xorshift:128plus --cascade "5:0x15,10:0x202,20:0xd2c55"
```

Supported variants:
- `xorshift:64` - Classic 64-bit state xorshift
- `xorshift:128` - 128-bit state xorshift (seed initialized as `(seed, 0)`)
- `xorshift:128plus` - Xorshift128+ (used in V8/SpiderMonkey Math.random())
- `xorshift:xoroshiro` - Xoroshiro128** (modern variant)

### MultiBit HD analyzer (seed-as-entropy bug)

MultiBit HD Beta 7 (2014-2016) had a bug where the 64-byte BIP39 seed was passed
directly to BitcoinJ's `DeterministicSeed` constructor as entropy (expected 16-32 bytes).
This created incompatible keys that cannot be recovered with standard BIP39 tools.

```bash
# Check if a key was generated by the MultiBit HD bug
vuke analyze <KEY> --analyzer multibit-hd --mnemonic "word1 word2 ... word12"

# Test with a specific passphrase
vuke analyze <KEY> --analyzer multibit-hd --mnemonic "word1 word2 ..." --passphrase "my passphrase"

# Dictionary attack with mnemonic file
vuke analyze <KEY> --analyzer multibit-hd --mnemonic-file candidates.txt
```

Generate buggy keys from a known mnemonic:

```bash
vuke single "skin join dog sponsor camera puppy ritual diagram arrow poverty boy elbow" --transform=multibit
```

Output (first key at m/0'/0/0):
```
P2PKH (compressed):   1LQ8XnNKqC7Vu7atH5k4X8qVCc9ug2q7WE
```

This matches the buggy address from [MultiBit HD issue #445](https://github.com/Multibit-Legacy/multibit-hd/issues/445).
The correct BIP39 address would be `12QxtuyEM8KBG3ngNRe2CZE28hFw3b1KMJ`.

### Electrum pre-BIP39 keys (2011-2014)

Electrum wallets before BIP39 adoption used a custom deterministic derivation scheme:
- 128-bit hex seed stretched via 100,000 SHA256 iterations
- Child keys derived as `(master + sequence) mod n`
- Uncompressed public keys for addresses

Generate keys from an old Electrum seed:

```bash
# Generate receiving chain addresses (first 20 keys)
vuke single "acb740e454c3134901d7c8f16497cc1c" --transform electrum

# Generate change chain addresses
vuke single "acb740e454c3134901d7c8f16497cc1c" --transform electrum:change
```

Output (receiving address 0):
```
P2PKH (uncompressed): 1FJEEB8ihPMbzs2SkLmr37dHyRFzakqUmo
```

### SHA256 chain analyzer

Detect keys generated using deterministic SHA256 chains (key[n] = SHA256(key[n-1]) or SHA256(seed || n)):

```bash
# Check with iterated chain (default): key[n] = SHA256(key[n-1])
vuke analyze <KEY> --analyzer sha256_chain --chain-depth 20

# Check indexed variant: key[n] = SHA256(seed || n as bytes)
vuke analyze <KEY> --analyzer sha256_chain:indexed --chain-depth 20

# With masking for puzzle analysis
vuke analyze 0x15 --mask 5 --analyzer sha256_chain --chain-depth 10

# With cascade filter for reduced false positives
vuke analyze 0x15 --analyzer sha256_chain --cascade "5:0x15,10:0x202" --chain-depth 10
```

Supported variants:
- `sha256_chain` or `sha256_chain:iterated` - Chain derivation: key[n] = SHA256(key[n-1])
- `sha256_chain:indexed` or `sha256_chain:indexed:be` - Indexed: SHA256(seed || n) with big-endian
- `sha256_chain:indexed:le` - Indexed with little-endian byte order
- `sha256_chain:counter` - String indexed: SHA256(seed || "n")

### SHA256 chain transform

Generate keys using SHA256 chain derivation:

```bash
# Generate iterated chain keys from numeric seeds
vuke generate --transform=sha256_chain range --start 1 --end 1000

# Generate indexed chain with counter strings
vuke generate --transform=sha256_chain:counter --chain-depth 5 wordlist --file seeds.txt

# Generate with specific chain depth
vuke generate --transform=sha256_chain:iterated --chain-depth 10 range --start 1 --end 100
```

## Supported Transforms

| Transform | Description | Use Case |
|-----------|-------------|----------|
| `direct` | Raw bytes padded to 32 bytes | Testing raw numeric seeds |
| `sha256` | SHA256(input) | Classic brainwallets |
| `double_sha256` | SHA256(SHA256(input)) | Bitcoin-style hashing |
| `md5` | MD5(input) duplicated to 32 bytes | Legacy weak hashing |
| `milksad` | MT19937 PRNG with 32-bit seed | CVE-2023-39910 (libbitcoin) |
| `mt64` | MT19937-64 PRNG with 64-bit seed | 64-bit seed hypothesis testing |
| `multibit` | MultiBit HD seed-as-entropy bug | 2014-2016 MultiBit HD wallets |
| `armory` | Armory HD derivation chain | Pre-BIP32 wallets |
| `electrum` | Electrum pre-BIP39 derivation | 2011-2014 Electrum wallets |
| `electrum:change` | Electrum change chain | 2011-2014 Electrum change addresses |
| `lcg[:variant][:endian]` | LCG PRNG with 32-bit seed | Legacy C stdlib rand() |
| `xorshift[:variant]` | Xorshift PRNG with 64-bit seed | V8/SpiderMonkey Math.random() |
| `sha256_chain[:variant]` | Deterministic SHA256 chain | Iterated/indexed key derivation |

## Supported Analyzers

| Analyzer | Method | Use Case |
|----------|--------|----------|
| `milksad` | Brute-force 2^32 seeds | Check if key is Milksad victim |
| `milksad --mask N` | Brute-force with N-bit masking | BTC1000-style puzzle analysis |
| `milksad --cascade` | Multi-target sequential verification | Reduce false positives in puzzle research |
| `mt64 --cascade` | Brute-force 2^64 with cascade filter | BTC1000 64-bit PRNG hypothesis |
| `multibit-hd --mnemonic` | Test mnemonic against key | Verify MultiBit HD bug origin |
| `multibit-hd --mnemonic-file` | Dictionary attack | Find mnemonic for MultiBit HD key |
| `direct` | Pattern detection | Detect small seeds, ASCII strings |
| `heuristic` | Statistical analysis | Entropy, hamming weight anomalies |
| `lcg[:variant][:endian]` | Brute-force 2^31-2^32 seeds | Detect glibc/minstd/msvc/borland rand() |
| `xorshift[:variant] --cascade` | Brute-force 2^64 with cascade filter | V8/SpiderMonkey xorshift PRNGs |
| `sha256_chain[:variant]` | Brute-force 2^32 seeds with chain depth | Deterministic SHA256 key chains |

## Library Usage

```rust
use vuke::derive::KeyDeriver;
use vuke::transform::{Input, Transform, Sha256Transform};

fn main() {
    let deriver = KeyDeriver::new();
    let transform = Sha256Transform;

    let input = Input::from_string("test passphrase".to_string());
    let mut buffer = Vec::new();
    transform.apply_batch(&[input], &mut buffer);

    for (source, key) in buffer {
        let derived = deriver.derive(&key);
        println!("Source: {}", source);
        println!("WIF: {}", derived.wif_compressed);
        println!("Address: {}", derived.p2pkh_compressed);
    }
}
```

## Architecture

```
src/
├── main.rs          # CLI entry point
├── lib.rs           # Library exports
├── derive.rs        # Private key → address derivation
├── matcher.rs       # Address matching against targets
├── network.rs       # Bitcoin network handling
├── benchmark.rs     # Performance testing
├── lcg.rs           # LCG PRNG shared logic
├── xorshift.rs      # Xorshift PRNG shared logic
├── mt64.rs          # MT19937-64 PRNG shared logic
├── multibit.rs      # MultiBit HD bug logic (PBKDF2, BIP32)
├── electrum.rs      # Electrum pre-BIP39 deterministic derivation
├── sha256_chain.rs  # SHA256 chain shared logic (iterated/indexed)
├── analyze/
│   ├── mod.rs       # Analyzer trait and types
│   ├── key_parser.rs # Parse hex/WIF/decimal keys
│   ├── milksad.rs   # MT19937 brute-force
│   ├── mt64.rs      # MT19937-64 brute-force (requires cascade)
│   ├── multibit.rs  # MultiBit HD mnemonic verification
│   ├── lcg.rs       # LCG brute-force (glibc, minstd, msvc, borland)
│   ├── xorshift.rs  # Xorshift brute-force (requires cascade)
│   ├── sha256_chain.rs # SHA256 chain brute-force
│   ├── direct.rs    # Pattern detection
│   ├── heuristic.rs # Statistical analysis
│   └── output.rs    # Plain text and JSON formatting
├── source/
│   ├── mod.rs       # Source trait and types
│   ├── range.rs     # Numeric range source
│   ├── wordlist.rs  # File-based wordlist
│   ├── timestamps.rs # Date range → Unix timestamps
│   └── stdin.rs     # Streaming from stdin
├── transform/
│   ├── mod.rs       # Transform trait and types
│   ├── input.rs     # Input value representation
│   ├── direct.rs    # Raw bytes transform
│   ├── sha256.rs    # SHA256 hashing
│   ├── double_sha256.rs # Double SHA256
│   ├── md5.rs       # MD5 hashing
│   ├── milksad.rs   # MT19937 PRNG (CVE-2023-39910)
│   ├── mt64.rs      # MT19937-64 PRNG transform
│   ├── multibit.rs  # MultiBit HD seed-as-entropy bug
│   ├── electrum.rs  # Electrum pre-BIP39 deterministic derivation
│   ├── lcg.rs       # LCG PRNG transform
│   ├── xorshift.rs  # Xorshift PRNG transform
│   ├── sha256_chain.rs # SHA256 chain transform
│   └── armory.rs    # Armory HD derivation
└── output/
    ├── mod.rs       # Output trait
    └── console.rs   # Console output handler
```

## Requirements

- Rust 1.70+

## Disclaimer

This tool is for **educational and security research purposes only**. Do not use it to access wallets you do not own. The authors are not responsible for any misuse.

## License

MIT License - see [LICENSE](LICENSE) for details.

## References

- [Milksad vulnerability](https://milksad.info/) - CVE-2023-39910
- [MultiBit HD issue #445](https://github.com/Multibit-Legacy/multibit-hd/issues/445) - Seed-as-entropy bug
- [Brainwallet attacks](https://eprint.iacr.org/2016/103.pdf) - Academic paper
- [Armory documentation](https://btcarmory.com/) - Legacy HD wallet
- [Linear Congruential Generator](https://en.wikipedia.org/wiki/Linear_congruential_generator) - Wikipedia
- [Xorshift PRNGs](https://en.wikipedia.org/wiki/Xorshift) - Wikipedia
- [Electrum 1.x key derivation](https://github.com/spesmilo/electrum/blob/b9196260cfd515363a026c3bfc7bc7aa757965a0/lib/bitcoin.py) - Pre-BIP39 source code
