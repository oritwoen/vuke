//! vuke - Research tool for studying vulnerable Bitcoin key generation practices.
//!
//! Combines multiple key derivation methods to analyze weak key generation patterns.

use anyhow::Result;
use clap::{Parser, Subcommand};
use std::path::PathBuf;

use vuke::derive::KeyDeriver;
use vuke::matcher::Matcher;
use vuke::network::parse_network;
use vuke::output::{ConsoleOutput, Output};
use vuke::source::{RangeSource, Source, StdinSource, TimestampSource, WordlistSource};
use vuke::transform::{Transform, TransformType};

#[derive(Parser)]
#[command(name = "vuke")]
#[command(about = "Research tool for studying vulnerable Bitcoin key generation practices")]
#[command(version)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Generate keys and output ALL (no address matching)
    Generate {
        #[command(subcommand)]
        source: SourceCommand,

        /// Transform(s) to apply
        #[arg(long, value_enum, num_args = 1.., default_value = "sha256")]
        transform: Vec<TransformType>,

        /// Network (bitcoin, testnet, signet, regtest)
        #[arg(long, default_value = "bitcoin")]
        network: String,

        /// Verbose output (show all key formats)
        #[arg(short, long)]
        verbose: bool,
    },

    /// Scan for specific addresses
    Scan {
        #[command(subcommand)]
        source: SourceCommand,

        /// Transform(s) to apply
        #[arg(long, value_enum, num_args = 1..)]
        transform: Vec<TransformType>,

        /// Target addresses file (one per line)
        #[arg(long)]
        targets: PathBuf,

        /// Network (bitcoin, testnet, signet, regtest)
        #[arg(long, default_value = "bitcoin")]
        network: String,
    },

    /// Generate single key from passphrase
    Single {
        /// The passphrase
        passphrase: String,

        /// Transform to apply
        #[arg(long, value_enum, default_value = "sha256")]
        transform: TransformType,

        /// Network (bitcoin, testnet, signet, regtest)
        #[arg(long, default_value = "bitcoin")]
        network: String,
    },

    /// Run benchmark
    Bench {
        /// Transform to benchmark
        #[arg(long, value_enum, default_value = "sha256")]
        transform: TransformType,

        /// Output JSON for benchmark runner
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
        } => {
            let _network = parse_network(&network);

            let output: Box<dyn Output> = if verbose {
                Box::new(ConsoleOutput::verbose())
            } else {
                Box::new(ConsoleOutput::new())
            };

            run_generate(source, transform, output.as_ref())
        }

        Command::Scan {
            source,
            transform,
            targets,
            network: _,
        } => {
            let output: Box<dyn Output> = Box::new(ConsoleOutput::new());
            run_scan(source, transform, targets, output.as_ref())
        }

        Command::Single {
            passphrase,
            transform,
            network,
        } => run_single(&passphrase, transform, &network),

        Command::Bench { transform, json } => vuke::benchmark::run_benchmark(transform, json),
    }
}

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
    let transform = create_transform(transform_type);

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
    types.into_iter().map(create_transform).collect()
}

fn create_transform(t: TransformType) -> Box<dyn Transform> {
    use vuke::transform::*;

    match t {
        TransformType::Direct => Box::new(DirectTransform),
        TransformType::Sha256 => Box::new(Sha256Transform),
        TransformType::DoubleSha256 => Box::new(DoubleSha256Transform),
        TransformType::Md5 => Box::new(Md5Transform),
        TransformType::Milksad => Box::new(MilksadTransform),
        TransformType::Armory => Box::new(ArmoryTransform::new()),
    }
}
