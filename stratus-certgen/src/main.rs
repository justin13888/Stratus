//! TLS certificate generator for Stratus mTLS setup.
//!
//! Provides two subcommands:
//!
//! - `ca` — generate a self-signed CA certificate and key
//! - `client` — generate a client certificate signed by an existing CA
//!
//! # Example workflow
//!
//! ```sh
//! # 1. Generate a CA
//! stratus-certgen ca --out-cert ca.pem --out-key ca-key.pem --cn "Stratus CA"
//!
//! # 2. Generate a client cert for user "alice"
//! stratus-certgen client \
//!     --ca-cert ca.pem --ca-key ca-key.pem \
//!     --cn alice \
//!     --out-cert alice-cert.pem --out-key alice-key.pem
//! ```
//!
//! The CA certificate path (`ca.pem`) goes into `config.toml`:
//! ```toml
//! [tls]
//! client_ca_file = "ca.pem"
//! client_cert_mode = "required"
//!
//! [security]
//! auth_method = "mutual_tls"
//! mtls_user_mapping = "cn"
//! ```

use std::fs;
use std::path::PathBuf;

use clap::{Parser, Subcommand};
use eyre::{Result, WrapErr};
use rcgen::{
    BasicConstraints, Certificate, CertificateParams, DnType, IsCa, KeyPair, KeyUsagePurpose,
};

#[derive(Parser, Debug)]
#[command(name = "stratus-certgen")]
#[command(about = "Generate TLS certificates for Stratus mTLS setup")]
struct Args {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand, Debug)]
enum Command {
    /// Generate a self-signed CA certificate and key
    Ca(CaArgs),
    /// Generate a client certificate signed by an existing CA
    Client(ClientArgs),
}

#[derive(Parser, Debug)]
struct CaArgs {
    /// Common Name for the CA certificate
    #[arg(long, default_value = "Stratus CA")]
    cn: String,

    /// Validity period in days
    #[arg(long, default_value_t = 3650)]
    days: u32,

    /// Output path for the CA certificate (PEM)
    #[arg(long, default_value = "ca.pem")]
    out_cert: PathBuf,

    /// Output path for the CA private key (PEM)
    #[arg(long, default_value = "ca-key.pem")]
    out_key: PathBuf,
}

#[derive(Parser, Debug)]
struct ClientArgs {
    /// Path to the CA certificate (PEM)
    #[arg(long)]
    ca_cert: PathBuf,

    /// Path to the CA private key (PEM)
    #[arg(long)]
    ca_key: PathBuf,

    /// Common Name for the client certificate (maps to username in Stratus)
    #[arg(long)]
    cn: String,

    /// Validity period in days
    #[arg(long, default_value_t = 365)]
    days: u32,

    /// Output path for the client certificate (PEM)
    #[arg(long, default_value = "client-cert.pem")]
    out_cert: PathBuf,

    /// Output path for the client private key (PEM)
    #[arg(long, default_value = "client-key.pem")]
    out_key: PathBuf,
}

fn main() -> Result<()> {
    color_eyre::install()?;

    let args = Args::parse();

    match args.command {
        Command::Ca(ca_args) => generate_ca(ca_args),
        Command::Client(client_args) => generate_client(client_args),
    }
}

/// Generate a self-signed CA certificate
fn generate_ca(args: CaArgs) -> Result<()> {
    let key = KeyPair::generate().wrap_err("Failed to generate CA key pair")?;

    let mut params = CertificateParams::default();
    params.distinguished_name.push(DnType::CommonName, &args.cn);
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    params.key_usages = vec![
        KeyUsagePurpose::KeyCertSign,
        KeyUsagePurpose::CrlSign,
        KeyUsagePurpose::DigitalSignature,
    ];
    set_validity(&mut params, args.days);

    let cert = params
        .self_signed(&key)
        .wrap_err("Failed to self-sign CA certificate")?;

    write_pem(&args.out_cert, &cert.pem(), "CA certificate")?;
    write_pem(&args.out_key, &key.serialize_pem(), "CA private key")?;

    eprintln!("CA certificate generated successfully!");
    eprintln!("  Certificate: {}", args.out_cert.display());
    eprintln!("  Private key: {}", args.out_key.display());
    eprintln!();
    eprintln!("Add to config.toml:");
    eprintln!("  [tls]");
    eprintln!("  client_ca_file = \"{}\"", args.out_cert.display());
    eprintln!("  client_cert_mode = \"required\"");
    eprintln!();
    eprintln!("  [security]");
    eprintln!("  auth_method = \"mutual_tls\"");
    eprintln!("  mtls_user_mapping = \"cn\"");

    Ok(())
}

/// Generate a client certificate signed by an existing CA
fn generate_client(args: ClientArgs) -> Result<()> {
    // Load CA cert and key
    let ca_cert_pem =
        fs::read_to_string(&args.ca_cert).wrap_err_with(|| {
            format!("Failed to read CA certificate: {}", args.ca_cert.display())
        })?;
    let ca_key_pem = fs::read_to_string(&args.ca_key)
        .wrap_err_with(|| format!("Failed to read CA key: {}", args.ca_key.display()))?;

    let ca_key =
        KeyPair::from_pem(&ca_key_pem).wrap_err("Failed to parse CA private key")?;

    // Reconstruct the CA Certificate object for signing
    let ca_params = CertificateParams::from_ca_cert_pem(&ca_cert_pem)
        .wrap_err("Failed to parse CA certificate")?;
    let ca_cert: Certificate = ca_params
        .self_signed(&ca_key)
        .wrap_err("Failed to reconstruct CA certificate for signing")?;

    // Generate client key and params
    let client_key = KeyPair::generate().wrap_err("Failed to generate client key pair")?;

    let mut client_params = CertificateParams::default();
    client_params
        .distinguished_name
        .push(DnType::CommonName, &args.cn);
    client_params.is_ca = IsCa::NoCa;
    client_params.key_usages = vec![
        KeyUsagePurpose::DigitalSignature,
        KeyUsagePurpose::KeyEncipherment,
    ];
    client_params.extended_key_usages = vec![rcgen::ExtendedKeyUsagePurpose::ClientAuth];
    set_validity(&mut client_params, args.days);

    let client_cert = client_params
        .signed_by(&client_key, &ca_cert, &ca_key)
        .wrap_err("Failed to sign client certificate with CA")?;

    write_pem(&args.out_cert, &client_cert.pem(), "client certificate")?;
    write_pem(
        &args.out_key,
        &client_key.serialize_pem(),
        "client private key",
    )?;

    eprintln!("Client certificate generated successfully!");
    eprintln!("  CN (username): {}", args.cn);
    eprintln!("  Certificate:   {}", args.out_cert.display());
    eprintln!("  Private key:   {}", args.out_key.display());
    eprintln!();
    eprintln!("Connect with:");
    eprintln!(
        "  curl --cert {} --key {} https://<server>/shares/",
        args.out_cert.display(),
        args.out_key.display()
    );

    Ok(())
}

/// Set the validity period (not_before = now, not_after = now + days)
fn set_validity(params: &mut CertificateParams, days: u32) {
    use rcgen::date_time_ymd;

    // Use rcgen's helper — start from a fixed "now" baseline isn't available,
    // so we use the Unix epoch approach via OffsetDateTime
    let now = time::OffsetDateTime::now_utc();
    let expiry = now + time::Duration::days(days as i64);

    params.not_before = rcgen::date_time_ymd(
        now.year(),
        now.month() as u8,
        now.day(),
    );
    params.not_after = date_time_ymd(
        expiry.year(),
        expiry.month() as u8,
        expiry.day(),
    );
}

/// Write PEM content to a file, creating parent directories as needed
fn write_pem(path: &PathBuf, pem: &str, description: &str) -> Result<()> {
    if let Some(parent) = path.parent().filter(|p| !p.as_os_str().is_empty()) {
        fs::create_dir_all(parent).wrap_err_with(|| {
            format!("Failed to create directory for {}: {}", description, parent.display())
        })?;
    }
    fs::write(path, pem).wrap_err_with(|| {
        format!(
            "Failed to write {} to {}",
            description,
            path.display()
        )
    })
}
