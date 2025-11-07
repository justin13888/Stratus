//! Password hash generator for Stratus users.toml
//!
//! This tool generates Argon2id password hashes for use in the Stratus server's
//! users.toml configuration file.

use clap::Parser;
use eyre::Result;
use stratus_auth::hash_password;

/// Generate Argon2id password hashes for Stratus users.toml
#[derive(Parser, Debug)]
#[command(name = "stratus-hashgen")]
#[command(author, version, about, long_about = None)]
struct Args {
    /// Password to hash
    ///
    /// If not provided, you will be prompted to enter it securely.
    password: Option<String>,

    /// Verify the password by entering it twice
    #[arg(short, long)]
    verify: bool,
}

fn main() -> Result<()> {
    color_eyre::install()?;

    let args = Args::parse();

    let password = if let Some(pwd) = args.password {
        // Password provided as argument
        if args.verify {
            eprintln!("Warning: --verify flag is ignored when password is provided as argument");
        }
        pwd
    } else {
        // Read password securely from stdin
        read_password_from_stdin(args.verify)?
    };

    // Generate the hash
    let hash = hash_password(&password)?;

    // Output the hash
    println!("{}", hash);

    eprintln!("\nPassword hash generated successfully!");
    eprintln!("Add this to your users.toml file:");
    eprintln!("\n[users.username]");
    eprintln!("password_hash = \"{}\"", hash);
    eprintln!("groups = [\"users\"]");

    Ok(())
}

/// Read password securely from stdin
fn read_password_from_stdin(verify: bool) -> Result<String> {
    use std::io::{self, Write};

    eprint!("Enter password: ");
    io::stderr().flush()?;

    let password = rpassword::read_password()?;

    if password.is_empty() {
        return Err(eyre::eyre!("Password cannot be empty"));
    }

    if verify {
        eprint!("Verify password: ");
        io::stderr().flush()?;

        let password2 = rpassword::read_password()?;

        if password != password2 {
            return Err(eyre::eyre!("Passwords do not match"));
        }
    }

    Ok(password)
}
