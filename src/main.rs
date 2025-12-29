//! vuke - Research tool for studying vulnerable Bitcoin key generation practices.
//!
//! Combines multiple key derivation methods to analyze weak key generation patterns.

use anyhow::Result;
use clap::{Parser, Subcommand};
use std::path::PathBuf;

use vuke::analyze::{Analyzer, AnalyzerType, KeyMetadata, format_results, format_results_json, parse_private_key};
use vuke::derive::KeyDeriver;
use vuke::matcher::Matcher;
use vuke::network::parse_network;
use vuke::output::{ConsoleOutput, Output};
use vuke::source::{RangeSource, Source, StdinSource, TimestampSource, WordlistSource};
use vuke::transform::{Transform, TransformType};

fn parse_analyzer_type(s: &str) -> Result<AnalyzerType, String> {
    AnalyzerType::from_str(s)
}

fn parse_transform_type(s: &str) -> Result<TransformType, String> {
    TransformType::from_str(s)
}

#[derive(Parser)]
#[command(name = "vuke")]
#[command(about = "Research tool for studying vulnerable Bitcoin key generation practices")]
#[command(version)]
struct Cli {
    #[command(subcommand)]
    command: Command,

    /// Disable GPU acceleration (use CPU only)
    #[cfg(feature = "gpu")]
    #[arg(long, global = true)]
    no_gpu: bool,
}

#[derive(Subcommand)]
enum Command {
    /// Generate keys and output ALL (no address matching)
    Generate {
        #[command(subcommand)]
        source: SourceCommand,

        /// Transform(s) to apply (e.g., sha256, lcg, lcg:glibc, lcg:glibc:le)
        #[arg(long, value_parser = parse_transform_type, num_args = 1.., default_value = "sha256")]
        transform: Vec<TransformType>,

        /// Network (bitcoin, testnet, signet, regtest)
        #[arg(long, default_value = "bitcoin")]
        network: String,

        /// Verbose output (show all key formats)
        #[arg(short, long)]
        verbose: bool,

        /// Output file (default: stdout)
        #[arg(short, long)]
        output: Option<PathBuf>,
    },

    /// Scan for specific addresses
    Scan {
        #[command(subcommand)]
        source: SourceCommand,

        /// Transform(s) to apply (e.g., sha256, lcg, lcg:glibc, lcg:glibc:le)
        #[arg(long, value_parser = parse_transform_type, num_args = 1..)]
        transform: Vec<TransformType>,

        /// Target addresses file (one per line)
        #[arg(long)]
        targets: PathBuf,

        /// Network (bitcoin, testnet, signet, regtest)
        #[arg(long, default_value = "bitcoin")]
        network: String,

        /// Output file (default: stdout)
        #[arg(short, long)]
        output: Option<PathBuf>,
    },

    /// Generate single key from passphrase
    Single {
        /// The passphrase
        passphrase: String,

        /// Transform to apply (e.g., sha256, lcg:glibc)
        #[arg(long, value_parser = parse_transform_type, default_value = "sha256")]
        transform: TransformType,

        /// Network (bitcoin, testnet, signet, regtest)
        #[arg(long, default_value = "bitcoin")]
        network: String,
    },

    /// Run benchmark
    Bench {
        /// Transform to benchmark (e.g., sha256, lcg:glibc)
        #[arg(long, value_parser = parse_transform_type, default_value = "sha256")]
        transform: TransformType,

        /// Output JSON for benchmark runner
        #[arg(long)]
        json: bool,
    },

    /// Analyze a private key for potential vulnerable origins
    Analyze {
        /// Private key (hex, WIF, or decimal)
        key: String,

        /// Skip brute-force checks (faster, heuristics only)
        #[arg(long)]
        fast: bool,

        /// Analyze as N-bit masked key (highest bit forced to 1)
        #[arg(long, value_name = "BITS", value_parser = clap::value_parser!(u8).range(1..=64))]
        mask: Option<u8>,

        /// Cascading filter: bits:target,bits:target,... (e.g., 5:0x15,10:0x202)
        #[arg(long, value_name = "CASCADE")]
        cascade: Option<String>,

        /// Specific analyzer(s) to run (e.g., milksad, lcg, lcg:glibc, lcg:glibc:le)
        #[arg(long, value_parser = parse_analyzer_type)]
        analyzer: Option<Vec<AnalyzerType>>,

        /// BIP39 mnemonic to test (for multibit-hd analyzer)
        #[arg(long, value_name = "WORDS")]
        mnemonic: Option<String>,

        /// File with BIP39 mnemonics to test (for multibit-hd analyzer)
        #[arg(long, value_name = "FILE")]
        mnemonic_file: Option<PathBuf>,

        /// BIP39 passphrase (for multibit-hd analyzer)
        #[arg(long, value_name = "PASSPHRASE", default_value = "")]
        passphrase: String,

        /// Output as JSON
        #[arg(long)]
        json: bool,
    },
}

#[derive(Subcommand, Clone)]
enum SourceCommand {
    /// Numeric range (e.g., 1 to 1000000)
    Range {
        /// Start of range
        #[arg(long)]
        start: u64,
        /// End of range
        #[arg(long)]
        end: u64,
    },

    /// Wordlist file (one passphrase per line)
    Wordlist {
        /// Path to wordlist file
        #[arg(long)]
        file: PathBuf,
    },

    /// Unix timestamps in date range
    Timestamps {
        /// Start date (YYYY-MM-DD)
        #[arg(long)]
        start: String,
        /// End date (YYYY-MM-DD)
        #[arg(long)]
        end: String,
        /// Also test milliseconds (1000x more keys)
        #[arg(long)]
        microseconds: bool,
    },

    /// Read from stdin (streaming)
    Stdin,
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Command::Generate {
            source,
            transform,
            network,
            verbose,
            output,
        } => {
            let _network = parse_network(&network);

            let out: Box<dyn Output> = match (output, verbose) {
                (Some(path), true) => Box::new(ConsoleOutput::to_file_verbose(&path)?),
                (Some(path), false) => Box::new(ConsoleOutput::to_file(&path)?),
                (None, true) => Box::new(ConsoleOutput::verbose()),
                (None, false) => Box::new(ConsoleOutput::new()),
            };

            run_generate(source, transform, out.as_ref())
        }

        Command::Scan {
            source,
            transform,
            targets,
            network: _,
            output,
        } => {
            let out: Box<dyn Output> = match output {
                Some(path) => Box::new(ConsoleOutput::to_file(&path)?),
                None => Box::new(ConsoleOutput::new()),
            };
            run_scan(source, transform, targets, out.as_ref())
        }

        Command::Single {
            passphrase,
            transform,
            network,
        } => run_single(&passphrase, transform, &network),

        Command::Bench { transform, json } => vuke::benchmark::run_benchmark(transform, json),

        Command::Analyze { key, fast, mask, cascade, analyzer, mnemonic, mnemonic_file, passphrase, json } => {
            #[cfg(feature = "gpu")]
            let use_gpu = !cli.no_gpu;
            #[cfg(not(feature = "gpu"))]
            let use_gpu = false;

            run_analyze(&key, fast, mask, cascade, analyzer, mnemonic, mnemonic_file, passphrase, json, use_gpu)
        }
    }
}

// TODO: GPU for generate/scan needs Source trait redesign (rayon par_chunks vs GPU batch model)
fn run_generate(source_cmd: SourceCommand, transforms: Vec<TransformType>, output: &dyn Output) -> Result<()> {
    let source = create_source(source_cmd)?;
    let transforms = create_transforms(transforms);

    eprintln!("Generating keys...");
    let stats = source.process(&transforms, None, output)?;
    output.flush()?;

    eprintln!(
        "Done. Inputs: {}, Keys: {}, Matches: {}",
        stats.inputs_processed, stats.keys_generated, stats.matches_found
    );

    Ok(())
}

fn run_scan(
    source_cmd: SourceCommand,
    transforms: Vec<TransformType>,
    targets: PathBuf,
    output: &dyn Output,
) -> Result<()> {
    eprintln!("Loading targets from {:?}...", targets);
    let matcher = Matcher::load(&targets)?;
    eprintln!("Loaded {} targets.", matcher.count());

    let source = create_source(source_cmd)?;
    let transforms = create_transforms(transforms);

    eprintln!("Scanning...");
    let stats = source.process(&transforms, Some(&matcher), output)?;
    output.flush()?;

    eprintln!(
        "Done. Inputs: {}, Keys: {}, Matches: {}",
        stats.inputs_processed, stats.keys_generated, stats.matches_found
    );

    Ok(())
}

fn run_single(passphrase: &str, transform_type: TransformType, network: &str) -> Result<()> {
    use vuke::transform::Input;

    let net = parse_network(network);
    let deriver = KeyDeriver::with_network(net);
    let transform = transform_type.create();

    let input = Input::from_string(passphrase.to_string());
    let mut buffer = Vec::new();
    transform.apply_batch(&[input], &mut buffer);

    if buffer.is_empty() {
        eprintln!("No key generated from passphrase.");
        return Ok(());
    }

    for (source, key) in buffer {
        let derived = deriver.derive(&key);

        println!("Passphrase: \"{}\"", passphrase);
        println!("Transform: {}", transform.name());
        println!("Source: {}", source);
        println!("---");
        println!("Private Key (hex):     {}", derived.private_key_hex);
        println!("Private Key (decimal): {}", derived.private_key_decimal);
        println!("Private Key (binary):  {}", derived.private_key_binary);
        println!("Bit Length:            {}", derived.bit_length);
        println!("Hamming Weight:        {}", derived.hamming_weight);
        println!("Leading Zeros (hex):   {}", derived.leading_zeros);
        println!("WIF (compressed):      {}", derived.wif_compressed);
        println!("WIF (uncompressed):    {}", derived.wif_uncompressed);
        println!("---");
        println!("P2PKH (compressed):   {}", derived.p2pkh_compressed);
        println!("P2PKH (uncompressed): {}", derived.p2pkh_uncompressed);
        println!("P2WPKH:               {}", derived.p2wpkh);
    }

    Ok(())
}

fn create_source(cmd: SourceCommand) -> Result<Box<dyn Source>> {
    match cmd {
        SourceCommand::Range { start, end } => {
            Ok(Box::new(RangeSource::new(start, end)))
        }
        SourceCommand::Wordlist { file } => {
            Ok(Box::new(WordlistSource::from_file(&file)?))
        }
        SourceCommand::Timestamps { start, end, microseconds } => {
            Ok(Box::new(TimestampSource::from_dates(&start, &end, microseconds)?))
        }
        SourceCommand::Stdin => {
            Ok(Box::new(StdinSource::new()))
        }
    }
}

fn create_transforms(types: Vec<TransformType>) -> Vec<Box<dyn Transform>> {
    types.into_iter().map(|t| t.create()).collect()
}

fn run_analyze(
    key_input: &str,
    fast: bool,
    mask_bits: Option<u8>,
    cascade_input: Option<String>,
    analyzer_types: Option<Vec<AnalyzerType>>,
    mnemonic: Option<String>,
    mnemonic_file: Option<PathBuf>,
    passphrase: String,
    json_output: bool,
    use_gpu: bool,
) -> Result<()> {
    use indicatif::ProgressBar;
    use vuke::analyze::{AnalysisConfig, parse_cascade};

    let cascade_targets = match cascade_input {
        Some(ref input) => Some(parse_cascade(input)?),
        None => None,
    };

    let key = parse_private_key(key_input)?;
    let metadata = KeyMetadata::from_key(&key);

    if let Some(bits) = mask_bits {
        let key_bits = vuke::analyze::calculate_bit_length(&key);
        if key_bits > bits as u16 {
            eprintln!(
                "Warning: key has {} bits but mask is {} bits. Key will be treated as already masked.",
                key_bits, bits
            );
        }
    }

    let config = AnalysisConfig { mask_bits, cascade_targets };

    let analyzer_types = match analyzer_types {
        Some(mut types) => {
            for t in &mut types {
                if let AnalyzerType::MultibitHd { mnemonic: ref mut m, mnemonic_file: ref mut f, passphrase: ref mut p } = t {
                    *m = mnemonic.clone();
                    *f = mnemonic_file.clone();
                    *p = passphrase.clone();
                }
            }
            types
        }
        None if fast => AnalyzerType::fast(),
        None => AnalyzerType::all(),
    };

    let analyzers: Vec<Box<dyn Analyzer>> = analyzer_types
        .into_iter()
        .map(|t| t.create())
        .collect();

    // Initialize GPU context if requested
    #[cfg(feature = "gpu")]
    let gpu_ctx = if use_gpu {
        match vuke::gpu::GpuContext::new_sync() {
            Ok(ctx) => {
                if !json_output {
                    eprintln!("GPU: {}", ctx.description());
                }
                Some(ctx)
            }
            Err(e) => {
                if !json_output {
                    eprintln!("GPU unavailable ({}), using CPU", e);
                }
                None
            }
        }
    } else {
        None
    };

    #[cfg(not(feature = "gpu"))]
    let _ = use_gpu; // Suppress unused warning

    let mut results = Vec::new();

    for analyzer in &analyzers {
        let progress = if analyzer.is_brute_force() && !json_output {
            let pb = ProgressBar::new(0);
            pb.set_style(vuke::default_progress_style());
            Some(pb)
        } else {
            None
        };

        // Try GPU first if available and supported
        #[cfg(feature = "gpu")]
        let result = if let Some(ref ctx) = gpu_ctx {
            if analyzer.supports_gpu() {
                match analyzer.analyze_gpu(ctx, &key, &config, progress.as_ref()) {
                    Ok(r) => r,
                    Err(e) => {
                        if !json_output {
                            eprintln!("GPU error ({}), falling back to CPU", e);
                        }
                        analyzer.analyze(&key, &config, progress.as_ref())
                    }
                }
            } else {
                analyzer.analyze(&key, &config, progress.as_ref())
            }
        } else {
            analyzer.analyze(&key, &config, progress.as_ref())
        };

        #[cfg(not(feature = "gpu"))]
        let result = analyzer.analyze(&key, &config, progress.as_ref());

        results.push(result);
    }

    if json_output {
        println!("{}", format_results_json(&metadata, &results));
    } else {
        print!("{}", format_results(&metadata, &results));
    }

    Ok(())
}
