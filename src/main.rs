//! vuke - Research tool for studying vulnerable Bitcoin key generation practices.
//!
//! Combines multiple key derivation methods to analyze weak key generation patterns.

use anyhow::Result;
use clap::{Parser, Subcommand, ValueEnum};
use std::path::PathBuf;

use vuke::analyze::{
    format_results, format_results_json, parse_private_key, Analyzer, AnalyzerType, KeyMetadata,
};
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

fn parse_byte_size(s: &str) -> Result<u64, String> {
    let s = s.trim().to_uppercase();
    if let Some(num) = s.strip_suffix('G') {
        num.parse::<u64>()
            .map(|n| n * 1024 * 1024 * 1024)
            .map_err(|e| e.to_string())
    } else if let Some(num) = s.strip_suffix('M') {
        num.parse::<u64>()
            .map(|n| n * 1024 * 1024)
            .map_err(|e| e.to_string())
    } else if let Some(num) = s.strip_suffix('K') {
        num.parse::<u64>()
            .map(|n| n * 1024)
            .map_err(|e| e.to_string())
    } else {
        s.parse::<u64>().map_err(|e| e.to_string())
    }
}

/// Compression algorithm for Parquet storage
#[derive(Debug, Clone, Copy, Default, ValueEnum)]
pub enum CompressionAlgorithm {
    /// No compression (fastest writes, largest files)
    None,
    /// Snappy compression (fast, moderate ratio)
    Snappy,
    /// Gzip compression (slow, good ratio)
    Gzip,
    /// LZ4 compression (very fast, moderate ratio)
    Lz4,
    /// Zstd compression (configurable speed/ratio tradeoff)
    #[default]
    Zstd,
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

        /// Storage directory for Parquet output (requires 'storage' feature)
        #[arg(long)]
        storage: Option<PathBuf>,

        /// Rotate storage chunk after N records (default: 1000000)
        #[arg(long, default_value = "1000000")]
        chunk_records: u64,

        /// Rotate storage chunk after N bytes (default: 100MB, accepts: 100M, 1G)
        #[arg(long, value_parser = parse_byte_size, default_value = "100M")]
        chunk_bytes: u64,

        /// Compression algorithm for Parquet storage
        #[arg(long, value_enum, default_value = "zstd")]
        compression: CompressionAlgorithm,

        /// Zstd compression level (1-22, higher = slower but smaller)
        #[arg(long, default_value = "3", value_parser = clap::value_parser!(i32).range(1..=22))]
        compression_level: i32,

        /// Enable cloud upload (requires 'storage-cloud' feature)
        #[arg(long)]
        cloud_upload: bool,

        /// S3-compatible endpoint URL (e.g., https://xxx.r2.cloudflarestorage.com)
        #[arg(long, env = "CLOUD_ENDPOINT")]
        cloud_endpoint: Option<String>,

        /// Cloud bucket name
        #[arg(long, env = "CLOUD_BUCKET")]
        cloud_bucket: Option<String>,

        /// Delete local files after successful cloud upload
        #[arg(long)]
        cloud_delete_local: bool,

        /// Stop on first cloud upload failure (default: continue and report)
        #[arg(long)]
        cloud_fail_fast: bool,

        /// Iceberg REST catalog URL (requires 'storage-iceberg' feature)
        #[arg(long, env = "ICEBERG_CATALOG")]
        iceberg_catalog: Option<String>,

        /// Iceberg namespace (default: vuke)
        #[arg(long, env = "ICEBERG_NAMESPACE", default_value = "vuke")]
        iceberg_namespace: String,

        /// Iceberg table name (default: results)
        #[arg(long, env = "ICEBERG_TABLE", default_value = "results")]
        iceberg_table: String,
    },

    /// Scan for specific addresses
    Scan {
        #[command(subcommand)]
        source: SourceCommand,

        /// Transform(s) to apply (e.g., sha256, lcg, lcg:glibc, lcg:glibc:le)
        #[arg(long, value_parser = parse_transform_type, num_args = 1..)]
        transform: Vec<TransformType>,

        /// Target addresses: file path OR provider (e.g., boha:b1000:unsolved)
        #[arg(long)]
        targets: String,

        /// Network (bitcoin, testnet, signet, regtest)
        #[arg(long, default_value = "bitcoin")]
        network: String,

        /// Output file (default: stdout)
        #[arg(short, long)]
        output: Option<PathBuf>,

        /// Storage directory for Parquet output (requires 'storage' feature)
        #[arg(long)]
        storage: Option<PathBuf>,

        /// Rotate storage chunk after N records (default: 1000000)
        #[arg(long, default_value = "1000000")]
        chunk_records: u64,

        /// Rotate storage chunk after N bytes (default: 100MB, accepts: 100M, 1G)
        #[arg(long, value_parser = parse_byte_size, default_value = "100M")]
        chunk_bytes: u64,

        /// Compression algorithm for Parquet storage
        #[arg(long, value_enum, default_value = "zstd")]
        compression: CompressionAlgorithm,

        /// Zstd compression level (1-22, higher = slower but smaller)
        #[arg(long, default_value = "3", value_parser = clap::value_parser!(i32).range(1..=22))]
        compression_level: i32,

        /// Enable cloud upload (requires 'storage-cloud' feature)
        #[arg(long)]
        cloud_upload: bool,

        /// S3-compatible endpoint URL (e.g., https://xxx.r2.cloudflarestorage.com)
        #[arg(long, env = "CLOUD_ENDPOINT")]
        cloud_endpoint: Option<String>,

        /// Cloud bucket name
        #[arg(long, env = "CLOUD_BUCKET")]
        cloud_bucket: Option<String>,

        /// Delete local files after successful cloud upload
        #[arg(long)]
        cloud_delete_local: bool,

        /// Stop on first cloud upload failure (default: continue and report)
        #[arg(long)]
        cloud_fail_fast: bool,

        /// Iceberg REST catalog URL (requires 'storage-iceberg' feature)
        #[arg(long, env = "ICEBERG_CATALOG")]
        iceberg_catalog: Option<String>,

        /// Iceberg namespace (default: vuke)
        #[arg(long, env = "ICEBERG_NAMESPACE", default_value = "vuke")]
        iceberg_namespace: String,

        /// Iceberg table name (default: results)
        #[arg(long, env = "ICEBERG_TABLE", default_value = "results")]
        iceberg_table: String,
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

        /// Depth of SHA256 chain to search (for sha256_chain analyzer)
        #[arg(long, value_name = "DEPTH", default_value = "10")]
        chain_depth: u32,

        /// Puzzle provider reference (e.g., boha:b1000:66) - auto-sets mask from puzzle
        #[arg(long, value_name = "PROVIDER")]
        puzzle: Option<String>,

        /// Verify key against provider collection (e.g., boha:b1000)
        #[arg(long, value_name = "PROVIDER")]
        verify: Option<String>,

        /// Output as JSON
        #[arg(long)]
        json: bool,
    },

    #[cfg(feature = "storage-query")]
    #[command(
        about = "Query stored results using SQL",
        after_help = r#"EXAMPLES:
    # Count results by transform
    vuke query ./results "SELECT transform, COUNT(*) FROM results GROUP BY transform"

    # Find matches (JSON output)
    vuke query ./results --format json "SELECT * FROM results WHERE matched_target IS NOT NULL"

    # Export to CSV
    vuke query ./results --format csv "SELECT address_p2pkh_compressed, wif_compressed FROM results" > export.csv

    # Show schema
    vuke query ./results --schema
"#
    )]
    Query {
        /// Path to storage directory containing Parquet files
        path: PathBuf,

        /// SQL query to execute (optional if --schema is used)
        query: Option<String>,

        /// Output format: table (default), json, csv
        #[arg(long, short = 'f', default_value = "table")]
        format: String,

        /// Show schema and exit (no query required)
        #[arg(long)]
        schema: bool,
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
            storage,
            chunk_records,
            chunk_bytes,
            compression,
            compression_level,
            cloud_upload,
            cloud_endpoint,
            cloud_bucket,
            cloud_delete_local,
            cloud_fail_fast,
            iceberg_catalog,
            iceberg_namespace,
            iceberg_table,
        } => {
            let _network = parse_network(&network);

            run_generate(
                source,
                transform,
                output,
                verbose,
                storage,
                chunk_records,
                chunk_bytes,
                compression,
                compression_level,
                cloud_upload,
                cloud_endpoint,
                cloud_bucket,
                cloud_delete_local,
                cloud_fail_fast,
                iceberg_catalog,
                iceberg_namespace,
                iceberg_table,
            )
        }

        Command::Scan {
            source,
            transform,
            targets,
            network: _,
            output,
            storage,
            chunk_records,
            chunk_bytes,
            compression,
            compression_level,
            cloud_upload,
            cloud_endpoint,
            cloud_bucket,
            cloud_delete_local,
            cloud_fail_fast,
            iceberg_catalog,
            iceberg_namespace,
            iceberg_table,
        } => run_scan(
            source,
            transform,
            targets,
            output,
            storage,
            chunk_records,
            chunk_bytes,
            compression,
            compression_level,
            cloud_upload,
            cloud_endpoint,
            cloud_bucket,
            cloud_delete_local,
            cloud_fail_fast,
            iceberg_catalog,
            iceberg_namespace,
            iceberg_table,
        ),

        Command::Single {
            passphrase,
            transform,
            network,
        } => run_single(&passphrase, transform, &network),

        Command::Bench { transform, json } => vuke::benchmark::run_benchmark(transform, json),

        Command::Analyze {
            key,
            fast,
            mask,
            cascade,
            analyzer,
            mnemonic,
            mnemonic_file,
            passphrase,
            chain_depth,
            puzzle,
            verify,
            json,
        } => {
            #[cfg(feature = "gpu")]
            let use_gpu = !cli.no_gpu;
            #[cfg(not(feature = "gpu"))]
            let use_gpu = false;

            run_analyze(
                &key,
                fast,
                mask,
                cascade,
                analyzer,
                mnemonic,
                mnemonic_file,
                passphrase,
                chain_depth,
                puzzle,
                verify,
                json,
                use_gpu,
            )
        }

        #[cfg(feature = "storage-query")]
        Command::Query {
            path,
            query,
            format,
            schema,
        } => run_query(path, query, format, schema),
    }
}

fn run_generate(
    source_cmd: SourceCommand,
    transforms: Vec<TransformType>,
    output_file: Option<PathBuf>,
    verbose: bool,
    storage_path: Option<PathBuf>,
    chunk_records: u64,
    chunk_bytes: u64,
    compression: CompressionAlgorithm,
    compression_level: i32,
    cloud_upload: bool,
    cloud_endpoint: Option<String>,
    cloud_bucket: Option<String>,
    cloud_delete_local: bool,
    cloud_fail_fast: bool,
    iceberg_catalog: Option<String>,
    iceberg_namespace: String,
    iceberg_table: String,
) -> Result<()> {
    let source = create_source(source_cmd)?;
    let transform_instances = create_transforms(transforms.clone());

    let console_out: Box<dyn Output> = match (output_file, verbose) {
        (Some(path), true) => Box::new(ConsoleOutput::to_file_verbose(&path)?),
        (Some(path), false) => Box::new(ConsoleOutput::to_file(&path)?),
        (None, true) => Box::new(ConsoleOutput::verbose()),
        (None, false) => Box::new(ConsoleOutput::new()),
    };

    #[cfg(feature = "storage")]
    let storage_output: Option<vuke::output::StorageOutput> = if let Some(ref path) = storage_path {
        use parquet::basic::{Compression, GzipLevel, ZstdLevel};

        let parquet_compression = match compression {
            CompressionAlgorithm::None => Compression::UNCOMPRESSED,
            CompressionAlgorithm::Snappy => Compression::SNAPPY,
            CompressionAlgorithm::Gzip => {
                Compression::GZIP(GzipLevel::try_new(compression_level as u32).unwrap_or_default())
            }
            CompressionAlgorithm::Lz4 => Compression::LZ4,
            CompressionAlgorithm::Zstd => {
                Compression::ZSTD(ZstdLevel::try_new(compression_level).unwrap_or_default())
            }
        };

        let transform_name = transforms
            .first()
            .map(|t| t.create().name().to_string())
            .unwrap_or_else(|| "unknown".to_string());
        Some(
            vuke::output::StorageOutput::new(path, &transform_name)?
                .with_compression(parquet_compression)
                .with_chunk_records(chunk_records)
                .with_chunk_bytes(chunk_bytes),
        )
    } else {
        None
    };

    #[cfg(feature = "storage")]
    let output: Box<dyn Output> = match &storage_output {
        Some(storage) => Box::new(vuke::output::MultiOutput::new(vec![
            console_out,
            Box::new(storage.clone()),
        ])),
        None => console_out,
    };

    #[cfg(not(feature = "storage"))]
    let output: Box<dyn Output> = {
        if storage_path.is_some() {
            anyhow::bail!(
                "--storage requires the 'storage' feature. Rebuild with: cargo build --features storage"
            );
        }
        let _ = (chunk_records, chunk_bytes, compression, compression_level);
        console_out
    };

    eprintln!("Generating keys...");
    let stats = source.process(&transform_instances, None, output.as_ref())?;
    output.flush()?;

    eprintln!(
        "Done. Inputs: {}, Keys: {}, Matches: {}",
        stats.inputs_processed, stats.keys_generated, stats.matches_found
    );

    #[cfg(feature = "storage")]
    let written_paths = if let Some(storage) = storage_output {
        let summary = storage.finish()?;
        print_storage_summary_inline(&summary);
        summary.paths
    } else {
        Vec::new()
    };

    #[cfg(feature = "storage-cloud")]
    if cloud_upload {
        #[cfg(feature = "storage")]
        {
            perform_cloud_upload(
                written_paths.clone(),
                cloud_endpoint,
                cloud_bucket,
                cloud_delete_local,
                cloud_fail_fast,
            )?;

            #[cfg(feature = "storage-iceberg")]
            if let Some(ref catalog_url) = iceberg_catalog {
                perform_iceberg_registration(
                    &written_paths,
                    catalog_url,
                    &iceberg_namespace,
                    &iceberg_table,
                )?;
            }
        }

        #[cfg(not(feature = "storage"))]
        anyhow::bail!("--cloud-upload requires --storage to be specified");
    }

    #[cfg(all(feature = "storage", not(feature = "storage-cloud")))]
    let _ = (
        written_paths,
        cloud_upload,
        cloud_endpoint,
        cloud_bucket,
        cloud_delete_local,
        cloud_fail_fast,
        iceberg_catalog,
        iceberg_namespace,
        iceberg_table,
    );

    #[cfg(not(feature = "storage"))]
    let _ = (
        cloud_upload,
        cloud_endpoint,
        cloud_bucket,
        cloud_delete_local,
        cloud_fail_fast,
        iceberg_catalog,
        iceberg_namespace,
        iceberg_table,
    );

    Ok(())
}

fn run_scan(
    source_cmd: SourceCommand,
    transforms: Vec<TransformType>,
    targets: String,
    output_file: Option<PathBuf>,
    storage_path: Option<PathBuf>,
    chunk_records: u64,
    chunk_bytes: u64,
    compression: CompressionAlgorithm,
    compression_level: i32,
    cloud_upload: bool,
    cloud_endpoint: Option<String>,
    cloud_bucket: Option<String>,
    cloud_delete_local: bool,
    cloud_fail_fast: bool,
    iceberg_catalog: Option<String>,
    iceberg_namespace: String,
    iceberg_table: String,
) -> Result<()> {
    let matcher = match vuke::provider::resolve(&targets)? {
        Some(result) => {
            eprintln!(
                "Provider: {} → {} addresses",
                targets,
                result.addresses.len()
            );
            Matcher::from_addresses(result.addresses)
        }
        None => {
            let path = PathBuf::from(&targets);
            eprintln!("Loading targets from {:?}...", path);
            let m = Matcher::load(&path)?;
            eprintln!("Loaded {} targets.", m.count());
            m
        }
    };

    let source = create_source(source_cmd)?;
    let transform_instances = create_transforms(transforms.clone());

    let console_out: Box<dyn Output> = match output_file {
        Some(path) => Box::new(ConsoleOutput::to_file(&path)?),
        None => Box::new(ConsoleOutput::new()),
    };

    #[cfg(feature = "storage")]
    let storage_output: Option<vuke::output::StorageOutput> = if let Some(ref path) = storage_path {
        use parquet::basic::{Compression, GzipLevel, ZstdLevel};

        let parquet_compression = match compression {
            CompressionAlgorithm::None => Compression::UNCOMPRESSED,
            CompressionAlgorithm::Snappy => Compression::SNAPPY,
            CompressionAlgorithm::Gzip => {
                Compression::GZIP(GzipLevel::try_new(compression_level as u32).unwrap_or_default())
            }
            CompressionAlgorithm::Lz4 => Compression::LZ4,
            CompressionAlgorithm::Zstd => {
                Compression::ZSTD(ZstdLevel::try_new(compression_level).unwrap_or_default())
            }
        };

        let transform_name = transforms
            .first()
            .map(|t| t.create().name().to_string())
            .unwrap_or_else(|| "unknown".to_string());
        Some(
            vuke::output::StorageOutput::new(path, &transform_name)?
                .with_compression(parquet_compression)
                .with_chunk_records(chunk_records)
                .with_chunk_bytes(chunk_bytes),
        )
    } else {
        None
    };

    #[cfg(feature = "storage")]
    let output: Box<dyn Output> = match &storage_output {
        Some(storage) => Box::new(vuke::output::MultiOutput::new(vec![
            console_out,
            Box::new(storage.clone()),
        ])),
        None => console_out,
    };

    #[cfg(not(feature = "storage"))]
    let output: Box<dyn Output> = {
        if storage_path.is_some() {
            anyhow::bail!(
                "--storage requires the 'storage' feature. Rebuild with: cargo build --features storage"
            );
        }
        let _ = (chunk_records, chunk_bytes, compression, compression_level);
        console_out
    };

    eprintln!("Scanning...");
    let stats = source.process(&transform_instances, Some(&matcher), output.as_ref())?;
    output.flush()?;

    eprintln!(
        "Done. Inputs: {}, Keys: {}, Matches: {}",
        stats.inputs_processed, stats.keys_generated, stats.matches_found
    );

    #[cfg(feature = "storage")]
    let written_paths = if let Some(storage) = storage_output {
        let summary = storage.finish()?;
        print_storage_summary_inline(&summary);
        summary.paths
    } else {
        Vec::new()
    };

    #[cfg(feature = "storage-cloud")]
    if cloud_upload {
        #[cfg(feature = "storage")]
        {
            perform_cloud_upload(
                written_paths.clone(),
                cloud_endpoint,
                cloud_bucket,
                cloud_delete_local,
                cloud_fail_fast,
            )?;

            #[cfg(feature = "storage-iceberg")]
            if let Some(ref catalog_url) = iceberg_catalog {
                perform_iceberg_registration(
                    &written_paths,
                    catalog_url,
                    &iceberg_namespace,
                    &iceberg_table,
                )?;
            }
        }

        #[cfg(not(feature = "storage"))]
        anyhow::bail!("--cloud-upload requires --storage to be specified");
    }

    #[cfg(all(feature = "storage", not(feature = "storage-cloud")))]
    let _ = (
        written_paths,
        cloud_upload,
        cloud_endpoint,
        cloud_bucket,
        cloud_delete_local,
        cloud_fail_fast,
        iceberg_catalog,
        iceberg_namespace,
        iceberg_table,
    );

    #[cfg(not(feature = "storage"))]
    let _ = (
        cloud_upload,
        cloud_endpoint,
        cloud_bucket,
        cloud_delete_local,
        cloud_fail_fast,
        iceberg_catalog,
        iceberg_namespace,
        iceberg_table,
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

#[cfg(feature = "storage")]
fn print_storage_summary_inline(summary: &vuke::output::StorageSummary) {
    if summary.paths.is_empty() {
        return;
    }

    let mut total_bytes: u64 = 0;
    let mut file_info = Vec::new();

    for path in &summary.paths {
        let size = std::fs::metadata(path).map(|m| m.len()).unwrap_or(0);
        total_bytes += size;
        file_info.push((path.clone(), size));
    }

    eprintln!(
        "\nStorage: {} files written ({} total)",
        summary.paths.len(),
        format_bytes(total_bytes)
    );

    for (path, size) in file_info {
        eprintln!("  {} ({})", path.display(), format_bytes(size));
    }
}

#[cfg(feature = "storage")]
fn format_bytes(bytes: u64) -> String {
    const KB: u64 = 1024;
    const MB: u64 = KB * 1024;
    const GB: u64 = MB * 1024;

    if bytes >= GB {
        format!("{:.1} GB", bytes as f64 / GB as f64)
    } else if bytes >= MB {
        format!("{:.1} MB", bytes as f64 / MB as f64)
    } else if bytes >= KB {
        format!("{:.1} KB", bytes as f64 / KB as f64)
    } else {
        format!("{} B", bytes)
    }
}

#[cfg(feature = "storage-cloud")]
fn perform_cloud_upload(
    paths: Vec<PathBuf>,
    endpoint: Option<String>,
    bucket: Option<String>,
    delete_local: bool,
    fail_fast: bool,
) -> Result<()> {
    use std::sync::Arc;
    use vuke::storage::cloud::{
        sync_to_cloud_blocking, CloudConfig, S3CloudUploader, StatsProgress,
    };

    if paths.is_empty() {
        return Ok(());
    }

    let bucket = bucket.ok_or_else(|| {
        anyhow::anyhow!("--cloud-bucket is required when --cloud-upload is enabled")
    })?;

    let mut config = CloudConfig::new(&bucket)
        .with_delete_local(delete_local)
        .with_fail_fast(fail_fast);

    if let Some(ref ep) = endpoint {
        config = config.with_endpoint(ep);
    }

    let stats = Arc::new(vuke::storage::cloud::UploadStats::new());
    let progress = Arc::new(StatsProgress::new(stats));
    let uploader = S3CloudUploader::new(config.clone(), progress)
        .map_err(|e| anyhow::anyhow!("Failed to create cloud uploader: {}", e))?;

    eprintln!("\nUploading {} files to s3://{}...", paths.len(), bucket);

    let result = sync_to_cloud_blocking(paths.clone(), Arc::new(uploader), 4);

    if result.is_success() {
        eprintln!(
            "Cloud upload complete: {} files uploaded",
            result.completed_count()
        );

        for cloud_path in &result.completed {
            eprintln!("  ✓ {}", cloud_path.url(endpoint.as_deref()));
        }

        if delete_local {
            // Only delete files that were successfully uploaded
            let uploaded_keys: std::collections::HashSet<_> = result
                .completed
                .iter()
                .map(|cp| cp.key.split('/').last().unwrap_or(&cp.key))
                .collect();

            let mut deleted = 0;
            for path in &paths {
                let filename = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
                if uploaded_keys.contains(filename) && std::fs::remove_file(path).is_ok() {
                    deleted += 1;
                }
            }
            if deleted > 0 {
                eprintln!("Deleted {} local files", deleted);
            }
        }
    } else {
        eprintln!(
            "Cloud upload completed with errors: {} succeeded, {} failed",
            result.completed_count(),
            result.failed_count()
        );

        for cloud_path in &result.completed {
            eprintln!("  ✓ {}", cloud_path.url(endpoint.as_deref()));
        }

        for (path, error) in &result.failed {
            eprintln!("  ✗ {}: {}", path.display(), error);
        }

        if fail_fast {
            anyhow::bail!(
                "Cloud upload failed: {} of {} files failed",
                result.failed_count(),
                paths.len()
            );
        }
    }

    Ok(())
}

#[cfg(feature = "storage-iceberg")]
fn perform_iceberg_registration(
    paths: &[PathBuf],
    catalog_url: &str,
    namespace: &str,
    table_name: &str,
) -> Result<()> {
    use tokio::runtime::Runtime;
    use vuke::storage::{CloudCredentials, IcebergConfig, RestCatalogClient};

    if paths.is_empty() {
        return Ok(());
    }

    let credentials = CloudCredentials::from_env()
        .map_err(|e| anyhow::anyhow!("Failed to get credentials for Iceberg: {}", e))?;

    let config = IcebergConfig::new(catalog_url)
        .with_namespace(namespace)
        .with_table_name(table_name);

    let client = RestCatalogClient::new(config, credentials);

    eprintln!(
        "\nRegistering {} files in Iceberg catalog {}...",
        paths.len(),
        catalog_url
    );

    let rt =
        Runtime::new().map_err(|e| anyhow::anyhow!("Failed to create tokio runtime: {}", e))?;
    let result = rt.block_on(client.register_parquet_files(paths))?;

    eprintln!(
        "Iceberg registration complete: snapshot_id={}, files={}",
        result.snapshot_id, result.files_registered
    );

    Ok(())
}

#[cfg(feature = "storage-query")]
fn run_query(
    path: PathBuf,
    query: Option<String>,
    format: String,
    show_schema: bool,
) -> Result<()> {
    use vuke::output::{format_csv, format_json, format_schema, format_table, OutputFormat};
    use vuke::storage::QueryExecutor;

    let output_format = OutputFormat::from_str(&format).map_err(|e| anyhow::anyhow!("{}", e))?;

    let executor =
        QueryExecutor::new(&path).map_err(|e| anyhow::anyhow!("Failed to open storage: {}", e))?;

    if !executor.has_data() {
        anyhow::bail!("No Parquet files found in {:?}", path);
    }

    if show_schema {
        return match executor.schema() {
            Ok(Some(schema)) => {
                print!("{}", format_schema(&schema));
                Ok(())
            }
            Ok(None) => anyhow::bail!("Could not read schema"),
            Err(e) => anyhow::bail!("Failed to read schema: {}", e),
        };
    }

    let sql = query.ok_or_else(|| anyhow::anyhow!("Query is required (or use --schema)"))?;

    let result = match executor.query_arrow(&sql) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("SQL Error: {}", e);
            eprintln!("\nAvailable columns (use --schema for details):");
            if let Ok(Some(schema)) = executor.schema() {
                for field in schema.fields() {
                    eprintln!("  - {}", field.name());
                }
            }
            std::process::exit(1);
        }
    };

    let rows = result.rows();
    let schema = result.schema();

    let output = match output_format {
        OutputFormat::Table => format_table(&rows, schema.clone()),
        OutputFormat::Json => format_json(&rows),
        OutputFormat::Csv => format_csv(&rows, schema.clone()),
    };

    print!("{}", output);

    if matches!(output_format, OutputFormat::Table) && !rows.is_empty() {
        eprintln!("\n({} rows)", rows.len());
    }

    Ok(())
}

fn create_source(cmd: SourceCommand) -> Result<Box<dyn Source>> {
    match cmd {
        SourceCommand::Range { start, end } => Ok(Box::new(RangeSource::new(start, end))),
        SourceCommand::Wordlist { file } => Ok(Box::new(WordlistSource::from_file(&file)?)),
        SourceCommand::Timestamps {
            start,
            end,
            microseconds,
        } => Ok(Box::new(TimestampSource::from_dates(
            &start,
            &end,
            microseconds,
        )?)),
        SourceCommand::Stdin => Ok(Box::new(StdinSource::new())),
    }
}

fn create_transforms(types: Vec<TransformType>) -> Vec<Box<dyn Transform>> {
    types.into_iter().map(|t| t.create()).collect()
}

fn resolve_cascade(input: &str) -> Result<Option<Vec<(u8, u64)>>> {
    use vuke::analyze::parse_cascade;

    if vuke::provider::is_provider(input) {
        vuke::provider::build_cascade(input)
    } else {
        Ok(Some(parse_cascade(input)?))
    }
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
    chain_depth: u32,
    puzzle_input: Option<String>,
    verify_input: Option<String>,
    json_output: bool,
    use_gpu: bool,
) -> Result<()> {
    use indicatif::ProgressBar;
    use vuke::analyze::AnalysisConfig;

    let (mask_bits, cascade_targets, puzzle_context) = if let Some(ref puzzle_ref) = puzzle_input {
        match vuke::provider::resolve(puzzle_ref)? {
            Some(result) => {
                let puzzle_mask = result.puzzle_context.as_ref().and_then(|ctx| ctx.mask_bits);
                let final_mask = mask_bits.or(puzzle_mask);

                let final_cascade = match cascade_input {
                    Some(ref input) => resolve_cascade(input)?,
                    None => result.cascade_targets,
                };

                (final_mask, final_cascade, result.puzzle_context)
            }
            None => {
                return Err(anyhow::anyhow!(
                    "Invalid puzzle provider reference: {}",
                    puzzle_ref
                ));
            }
        }
    } else {
        let cascade = match cascade_input {
            Some(ref input) => resolve_cascade(input)?,
            None => None,
        };
        (mask_bits, cascade, None)
    };

    if let Some(ref ctx) = puzzle_context {
        if !json_output {
            eprintln!("Puzzle: {} ({})", ctx.id, ctx.address_type);
            eprintln!("Expected: {}", ctx.expected_address);
            if let Some(bits) = ctx.mask_bits {
                eprintln!("Auto-mask: {} bits", bits);
            }
        }
    }

    let key = parse_private_key(key_input)?;
    let metadata = KeyMetadata::from_key(&key);

    if let Some(ref verify_ref) = verify_input {
        match vuke::provider::verify_key(&key, verify_ref)? {
            Some(report) => {
                if json_output {
                    let matches_json: Vec<String> = report
                        .matches
                        .iter()
                        .map(|m| {
                            format!(
                                r#"{{"puzzle_id":"{}","address":"{}","address_type":"{}","status":"{}","prize":{}}}"#,
                                m.puzzle_id,
                                m.address,
                                m.address_type,
                                m.status,
                                m.prize.map_or("null".to_string(), |p| p.to_string())
                            )
                        })
                        .collect();
                    println!(
                        r#"{{"key":"{}","total_checked":{},"matches":[{}]}}"#,
                        key_input,
                        report.total_checked,
                        matches_json.join(",")
                    );
                } else {
                    println!("Verification Report");
                    println!("---");
                    println!("Key: {}", key_input);
                    println!("Checked: {} puzzles", report.total_checked);
                    println!();

                    if report.matches.is_empty() {
                        println!("No matches found.");
                    } else {
                        println!("Matches:");
                        for m in &report.matches {
                            println!("  {} ({})", m.puzzle_id, m.status);
                            println!("    Address: {} ({})", m.address, m.address_type);
                            if let Some(prize) = m.prize {
                                println!("    Prize: {} BTC", prize);
                            }
                        }
                    }
                }
                return Ok(());
            }
            None => {
                return Err(anyhow::anyhow!(
                    "Invalid verify provider reference: {}",
                    verify_ref
                ));
            }
        }
    }

    if let Some(bits) = mask_bits {
        let key_bits = vuke::analyze::calculate_bit_length(&key);
        if key_bits > bits as u16 {
            eprintln!(
                "Warning: key has {} bits but mask is {} bits. Key will be treated as already masked.",
                key_bits, bits
            );
        }
    }

    let config = AnalysisConfig {
        mask_bits,
        cascade_targets,
    };

    let analyzer_types = match analyzer_types {
        Some(mut types) => {
            for t in &mut types {
                match t {
                    AnalyzerType::MultibitHd {
                        mnemonic: ref mut m,
                        mnemonic_file: ref mut f,
                        passphrase: ref mut p,
                    } => {
                        *m = mnemonic.clone();
                        *f = mnemonic_file.clone();
                        *p = passphrase.clone();
                    }
                    AnalyzerType::Sha256Chain {
                        chain_depth: ref mut d,
                        ..
                    } => {
                        *d = chain_depth;
                    }
                    _ => {}
                }
            }
            types
        }
        None if fast => AnalyzerType::fast(),
        None => AnalyzerType::all(),
    };

    let analyzers: Vec<Box<dyn Analyzer>> =
        analyzer_types.into_iter().map(|t| t.create()).collect();

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
