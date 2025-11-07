# Stratus

Stratus converts your filesystem into your own cloud

## Motivation

Stratus came from the need to access and share files on my personal servers without the hassle of copying over the internet with existing protocols like SMB and SFTP, which lose throughput over high-latency and lossy connections. Other self-hosted cloud storage solutions are great for those who have everything in a single cloud platform but not for those who just want to access their files in a filesystem. Stratus provides a fast, reliable method to access your files remotely with minimal setup.

## Features

- Serve and share files from any filesystem or object storage backend (quick)

### HTTP Server

- High-performance HTTP/2 with TLS
- HTTP Authentication (Basic, Bearer, Mutual TLS)
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
4. Set up authentication (optional): `cp users.example.toml users.toml` and edit to add users, or disable auth in `config.toml`
5. (Optional) Edit `config.toml` to customize your server settings
6. Start development server: `systemfd --no-pid -s http::8443 -- cargo watch -x run`

Test with curl:

```bash
# Without auth (if disabled)
curl -k https://localhost:8443/shares/test/

# With Basic Auth
curl -k -u admin:admin123 https://localhost:8443/shares/test/ # User: admin, Password: admin123
```


### Build Container Image

```bash
podman build -t stratus:latest .
```

### Test with Docker Compose

```bash
podman compose up
```

## Monitoring

Stratus includes built-in Prometheus metrics support. Enable metrics in configuration file `config.toml` under the `[metrics]` section.

Example:

```toml
[metrics]
enabled = true
endpoint = "/metrics"
bind_address = "127.0.0.1"
port = 9090
```

## Authentication

Stratus supports HTTP Basic Authentication with argon2id password hashing. It also supports auth methods like JWT/Bearer tokens with OpenID Connect.

See [docs/authentication.md](docs/authentication.md) for details.

## Other Technologies for the Curious

### Relevant Protocols

- WebDAV: Simple, well-standardized extension to HTTP for file management. Supported by multiple clients and servers but many implementations are hidden behind paywall or no longer actively maintained.
- Samba: Widely-adopted network filesystem protocol. Highly stateless, SMB-over-QUIC is being worked on but not yet complete/widely supported.
- S3: Standard object storage protocol adopted by countless vendors. Incompatible with POSIX filesystem semantics but it serves vastly different use-cases.

### Similar Services

- Nextcloud/ownCloud: Open-source cloud storage solutions with their own suites of features. But they don't - expose your filesystem or do some sort of sync (e.g. Nextcloud External Storage)
- Google Drive/Dropbox/OneDrive/iCloud: These are proprietary cloud services with other integrations. They may be great for many use cases, but not this.
- Spacedrive: Open, distributed storage that is leaving alpha stage.
