# Stratus

Stratus converts your filesystem into your own cloud

## Motivation

Stratus came from the need to access and share files on my personal servers without the hassle of copying over the internet with existing protocols like SMB and SFTP, which lose throughput over high-latency and lossy connections. Other self-hosted cloud storage solutions are great for those who have everything in a single cloud platform but not for those who just want to access their files in a filesystem. Stratus provides a fast, reliable method to access your files remotely with minimal setup.

## Features

- Serve and share files from any filesystem or object storage backend (quick)

### HTTP Server

- High-performance HTTP/2 with TLS
- Configurable compression, CORS, and security settings
- Directory browsing with caching
- Range request support for streaming and partial downloads
- Built-in Prometheus metrics for monitoring and observability

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
2. Generate self-signed TLS certificates: `openssl req -x509 -newkey rsa:2048 -keyout key.pem -out cert.pem -days 365 -nodes -subj "/CN=localhost" && chmod 644 key.pem cert.pem`
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

## Monitoring

Stratus includes built-in Prometheus metrics support. See [docs/METRICS.md](docs/METRICS.md) for detailed documentation.

### Quick Start - Metrics on Main Server

1. Enable metrics in `config.toml`:
   ```toml
   [metrics]
   enabled = true
   endpoint = "/metrics"
   ```
2. Access metrics at `https://localhost:8443/metrics`

### Quick Start - Separate Metrics Server

For isolating metrics traffic, you can specify a different bind address or port (or both):

1. Configure separate server in `config.toml`:
   ```toml
   [metrics]
   enabled = true
   endpoint = "/metrics"
   # Specify different address, port, or both
   bind_address = "127.0.0.1"  # Optional: defaults to main server's address
   port = 9090                  # Optional: defaults to main server's port
   ```
2. Access metrics at `http://localhost:9090/metrics` (plain HTTP, no TLS)

**Note:** If you specify the same bind_address and port as the main server, metrics will be served on the main server instead of spawning a separate server.

For testing the metrics endpoint, run:
```bash
./test_metrics.sh
```
