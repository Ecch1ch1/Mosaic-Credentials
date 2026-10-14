//! Mosaic Credential CLI — local development and diagnostics tool (§12.1).
//!
//! Subcommands:
//! - `enroll`  — Build a credential from text/files and produce a verifier record.
//! - `verify`  — Verify a candidate credential against a stored record.
//! - `inspect` — Parse and display the canonical binary format of a credential.
//! - `hash`    — Show the domain-separated SHA-256 prehash of a credential.

use std::fs;
use std::path::PathBuf;
use std::process;

use clap::{Parser, Subcommand, Args};

use mosaic_core::prelude::*;
use mosaic_auth::prelude::*;

#[derive(Parser)]
#[command(
    name = "mosaic",
    about = "Mosaic Credential — structured authentication secret tool",
    version,
    long_about = "CLI for building, enrolling, verifying, and inspecting Mosaic Credentials.\n\n\
                   This tool is for local development and diagnostics.\n\
                   See the Mosaic Credential Technical Specification for details."
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Build a credential and produce a verifier record (JSON).
    Enroll(EnrollArgs),
    /// Verify a candidate credential against a stored verifier record.
    Verify(VerifyArgs),
    /// Parse and display the canonical binary format of a credential.
    Inspect(InspectArgs),
    /// Show the domain-separated SHA-256 prehash of a credential.
    Hash(HashArgs),
    /// Display, export, or verify published test vectors (§16.4).
    TestVectors(TestVectorsArgs),
}


#[derive(Args)]
struct EnrollArgs {
    /// Text components to include (in order).
    /// Each --text value becomes a sequence of CHAR elements.
    #[arg(short, long, action = clap::ArgAction::Append)]
    text: Vec<String>,

    /// File components to include as BLOBs (in order).
    /// Each --file path becomes a BLOB element with the file's raw bytes.
    #[arg(short, long, action = clap::ArgAction::Append)]
    file: Vec<PathBuf>,

    /// Add backspace characters (U+0008) at the current position.
    #[arg(short, long, default_value = "0")]
    backspace: usize,

    /// Output file for the verifier record JSON.
    /// If not specified, prints to stdout.
    #[arg(short, long)]
    output: Option<PathBuf>,

    /// Use fast Argon2 parameters (for testing only, NOT production).
    #[arg(long, default_value = "false")]
    fast: bool,

    /// Maximum total encoded size in bits.
    #[arg(long, default_value = "2000000000")]
    max_encoded_bits: u64,

    /// Maximum BLOB size in bits.
    #[arg(long, default_value = "2000000000")]
    max_blob_bits: u64,

    /// Maximum number of elements.
    #[arg(long, default_value = "100000")]
    max_elements: u64,
}

#[derive(Args)]
struct VerifyArgs {
    /// Text components of the candidate credential (in order).
    #[arg(short, long, action = clap::ArgAction::Append)]
    text: Vec<String>,

    /// File components of the candidate credential (in order).
    #[arg(short, long, action = clap::ArgAction::Append)]
    file: Vec<PathBuf>,

    /// Add backspace characters at the current position.
    #[arg(short, long, default_value = "0")]
    backspace: usize,

    /// Path to the stored verifier record JSON file.
    #[arg(short, long)]
    record: PathBuf,

    /// Maximum total encoded size in bits.
    #[arg(long, default_value = "2000000000")]
    max_encoded_bits: u64,

    /// Maximum BLOB size in bits.
    #[arg(long, default_value = "2000000000")]
    max_blob_bits: u64,

    /// Maximum number of elements.
    #[arg(long, default_value = "100000")]
    max_elements: u64,
}

#[derive(Args)]
struct InspectArgs {
    /// Text components to include (in order).
    #[arg(short, long, action = clap::ArgAction::Append)]
    text: Vec<String>,

    /// File components to include as BLOBs (in order).
    #[arg(short, long, action = clap::ArgAction::Append)]
    file: Vec<PathBuf>,

    /// Add backspace characters at the current position.
    #[arg(short, long, default_value = "0")]
    backspace: usize,

    /// Show the raw hex dump of the canonical encoding.
    #[arg(long, default_value = "false")]
    hex: bool,
}

#[derive(Args)]
struct HashArgs {
    /// Text components to include (in order).
    #[arg(short, long, action = clap::ArgAction::Append)]
    text: Vec<String>,

    /// File components to include as BLOBs (in order).
    #[arg(short, long, action = clap::ArgAction::Append)]
    file: Vec<PathBuf>,

    /// Add backspace characters at the current position.
    #[arg(short, long, default_value = "0")]
    backspace: usize,
}

#[derive(Args)]
struct TestVectorsArgs {
    /// Verify all published test vectors and report results.
    #[arg(short, long, default_value = "false")]
    verify: bool,

    /// Output the test vectors in JSON format.
    #[arg(short, long, default_value = "false")]
    json: bool,

    /// Optional output file to write test vectors JSON to.
    #[arg(short, long)]
    output: Option<PathBuf>,
}


/// Build elements from CLI arguments (text, file, backspace).
///
/// Currently processes all text first, then backspaces, then files.
/// For more complex orderings, a future version could accept an ordered
/// sequence specification.
fn build_elements(
    texts: &[String],
    files: &[PathBuf],
    backspace_count: usize,
    policy: Policy,
) -> std::result::Result<Vec<Element>, String> {
    let mut builder = CredentialBuilder::new(policy).map_err(|e| e.to_string())?;


    for text in texts {
        builder.add_text(text).map_err(|e| e.to_string())?;
    }

    if backspace_count > 0 {
        builder
            .add_backspace(backspace_count)
            .map_err(|e| e.to_string())?;
    }

    for path in files {
        let mut file = fs::File::open(path)
            .map_err(|e| format!("cannot open '{}': {e}", path.display()))?;
        let metadata = file
            .metadata()
            .map_err(|e| format!("cannot read metadata for '{}': {e}", path.display()))?;
        let length = metadata.len();
        builder
            .add_blob_stream(&mut file, length)
            .map_err(|e| format!("error reading '{}': {e}", path.display()))?;
    }

    builder.finalize().map_err(|e| e.to_string())
}

fn cmd_enroll(args: EnrollArgs) {
    let policy = Policy::new(args.max_encoded_bits, args.max_blob_bits, args.max_elements);

    let elements = match build_elements(&args.text, &args.file, args.backspace, policy) {
        Ok(e) => e,
        Err(e) => {
            eprintln!("Error building credential: {e}");
            process::exit(1);
        }
    };

    let params = if args.fast {
        AuthParams::fast_testing()
    } else {
        AuthParams::default()
    };

    let record = match mosaic_auth::enroll::enroll(&elements, &params) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("Enrollment failed: {e}");
            process::exit(1);
        }
    };

    let json = record.to_json().unwrap();

    if let Some(output_path) = args.output {
        fs::write(&output_path, &json).unwrap_or_else(|e| {
            eprintln!("Cannot write to '{}': {e}", output_path.display());
            process::exit(1);
        });
        eprintln!("Verifier record written to: {}", output_path.display());
    } else {
        println!("{json}");
    }
}

fn cmd_verify(args: VerifyArgs) {
    let policy = Policy::new(args.max_encoded_bits, args.max_blob_bits, args.max_elements);

    let elements = match build_elements(&args.text, &args.file, args.backspace, policy) {
        Ok(e) => e,
        Err(e) => {
            eprintln!("Error building candidate: {e}");
            process::exit(1);
        }
    };

    let record_json = match fs::read_to_string(&args.record) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("Cannot read record '{}': {e}", args.record.display());
            process::exit(1);
        }
    };

    let record = match VerifierRecord::from_json(&record_json) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("Invalid record JSON: {e}");
            process::exit(1);
        }
    };

    let limits = ResourceLimits::default();
    let result = verify(&elements, &record, &limits);

    match result {
        VerifyResult::Ok => {
            println!("✓ Verification succeeded");
            process::exit(0);
        }
        VerifyResult::Denied => {
            println!("✗ Verification denied");
            process::exit(1);
        }
    }
}

fn cmd_inspect(args: InspectArgs) {
    let policy = Policy::default_generous();

    let elements = match build_elements(&args.text, &args.file, args.backspace, policy) {
        Ok(e) => e,
        Err(e) => {
            eprintln!("Error building credential: {e}");
            process::exit(1);
        }
    };

    println!("Mosaic Credential — Structural View");
    println!("====================================");
    println!("Elements: {}", elements.len());
    println!();

    for (i, element) in elements.iter().enumerate() {
        match element {
            Element::Char(c) => {
                let code_point = *c as u32;
                let display = if c.is_control() {
                    format!("<U+{code_point:04X}>")
                } else {
                    format!("'{c}'")
                };
                println!("  [{i:4}] CHAR  {display}  (U+{code_point:04X})");
            }
            Element::Blob(data) => {
                println!(
                    "  [{i:4}] BLOB  {} bytes  (preview: {})",
                    data.len(),
                    hex_preview(data, 32)
                );
            }
        }
    }

    let encoded = mosaic_core::encoder::encode(&elements);
    println!();
    println!("Canonical encoding: {} bytes", encoded.len());

    if args.hex {
        println!();
        println!("Hex dump:");
        for (i, chunk) in encoded.chunks(16).enumerate() {
            let hex_str: Vec<String> = chunk.iter().map(|b| format!("{b:02x}")).collect();
            let ascii_str: String = chunk
                .iter()
                .map(|b| if b.is_ascii_graphic() || *b == b' ' { *b as char } else { '.' })
                .collect();
            println!("  {:04x}  {:48}  |{}|", i * 16, hex_str.join(" "), ascii_str);
        }
    }
}

fn cmd_hash(args: HashArgs) {
    let policy = Policy::default_generous();

    let elements = match build_elements(&args.text, &args.file, args.backspace, policy) {
        Ok(e) => e,
        Err(e) => {
            eprintln!("Error building credential: {e}");
            process::exit(1);
        }
    };

    let digest = streaming_prehash(&elements);
    println!("{}", hex::encode(digest));
}

fn cmd_test_vectors(args: TestVectorsArgs) {
    let test_vectors = mosaic_auth::test_vectors::get_test_vectors();

    if args.verify {
        println!("Verifying {} published test vectors (§16.4)...", test_vectors.len());
        let mut failed = 0;
        for (v, elements) in &test_vectors {
            match v.verify_vector(elements) {
                Ok(()) => println!("  ✓ {} — {}", v.id, v.description),
                Err(err) => {
                    println!("  ✗ {} — {}", v.id, err);
                    failed += 1;
                }
            }
        }
        if failed > 0 {
            eprintln!("\n{failed} test vector(s) failed verification!");
            process::exit(1);
        } else {
            println!("\nAll {} test vectors passed verification!", test_vectors.len());
            return;
        }
    }

    if args.json {
        let published = mosaic_auth::test_vectors::get_published_vectors();
        let json_str = serde_json::to_string_pretty(&published).unwrap();
        if let Some(path) = args.output {
            fs::write(&path, &json_str).unwrap_or_else(|e| {
                eprintln!("Cannot write to '{}': {e}", path.display());
                process::exit(1);
            });
            eprintln!("Published test vectors written to: {}", path.display());
        } else {
            println!("{json_str}");
        }
        return;
    }

    // Default readable view
    println!("Mosaic Credential v1 — Published Test Vectors (§16.4)");
    println!("=====================================================");
    for (i, (v, _)) in test_vectors.iter().enumerate() {
        println!("\nVector #{}: {}", i + 1, v.id);
        println!("  Description:  {}", v.description);
        println!("  Elements:     {}", v.elements_desc.join(", "));
        println!("  Canonical S:  {} ({} bytes)", v.canonical_hex, v.canonical_hex.len() / 2);
        println!("  Prehash D:    {}", v.prehash_hex);
        println!("  Salt (b64):   {}", v.salt_b64);
        println!("  Argon2 PHC:   {}", v.expected_verifier);
    }
}

fn hex_preview(data: &[u8], max_bytes: usize) -> String {
    let preview_len = data.len().min(max_bytes);
    let hex_str: Vec<String> = data[..preview_len].iter().map(|b| format!("{b:02x}")).collect();
    let mut result = hex_str.join(" ");
    if data.len() > max_bytes {
        result.push_str(" ...");
    }
    result
}

fn main() {
    let cli = Cli::parse();

    match cli.command {
        Commands::Enroll(args) => cmd_enroll(args),
        Commands::Verify(args) => cmd_verify(args),
        Commands::Inspect(args) => cmd_inspect(args),
        Commands::Hash(args) => cmd_hash(args),
        Commands::TestVectors(args) => cmd_test_vectors(args),
    }
}

