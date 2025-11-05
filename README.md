# Stratus

Stratus converts your filesystem into your own cloud

## Features

TODO

## Motivation

Stratus came from the need to access and share files on my personal servers without the hassle of copying over the internet with existing protocols like SMB and SFTP, which lose throughput over high-latency and lossy connections. Other self-hosted cloud storage solutions are great for those who have everything in a single cloud platform but not for those who just want to access their files in a filesystem. Stratus provides a fast, reliable method to access your files remotely with minimal setup.

## Example Use Cases

- Access your files remotely over the internet efficiently
- Share files with fine-grained access control without manual copying

## Compatibility

Stratus is explicitly designed and tested for GNU/Linux distributions with POSIX-compliant filesystems. It is optimized with Linux-specific APIs such as io_uring. It is typical that servers are running Linux-based OSes anyways. (While code may compile to other targets, you are on your own there.)

## Development

Prerequisites:

- rustup

### Start Development Server

1. Install some dependencies: `cargo install cargo-watch systemfd`
2. Generate self-signed TLS certificates: `openssl req -x509 -newkey rsa:2048 -keyout key.pem -out cert.pem -days 365 -nodes -subj "/CN=localhost"`
3. Copy the example config: `cp config.example.toml config.toml`.
4. (Optional) Edit `config.toml` to customize your server settings
5. Start development server: `systemfd --no-pid -s http::8443 -- cargo watch -x run`

### Build Container Image

```bash
podman build -t stratus:latest .
```

### Test with Docker Compose

```bash
podman compose up
```
