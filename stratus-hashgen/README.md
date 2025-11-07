# stratus-hashgen

Password hash generator for Stratus server authentication.

## Overview

This CLI tool generates Argon2id password hashes for use in the Stratus server's `users.toml` configuration file. It provides a secure way to create password hashes without storing plaintext passwords.

## Usage

### Interactive Mode (Recommended)

Generate a hash with hidden password input:

```bash
cargo run -p stratus-hashgen
```

You'll be prompted to enter your password securely.

### With Verification

Double-check your password by entering it twice:

```bash
cargo run -p stratus-hashgen --verify
```

### Command Line Argument

For testing purposes only (less secure):

```bash
cargo run -p stratus-hashgen mypassword123
```

## Example Output

```
Enter password: 
Password hash generated successfully!
Add this to your users.toml file:

[users.username]
password_hash = "$argon2id$v=19$m=65536,t=3,p=4$..."
groups = ["users"]
```

## Security

- All password hashes use Argon2id with secure default parameters
- Memory cost: 64 MiB
- Time cost: 3 iterations
- Parallelism: 4 threads
- Each hash uses a unique random salt

## Building

To build a standalone binary:

```bash
cargo build --release -p stratus-hashgen
```

The binary will be located at `target/release/stratus-hashgen`.
