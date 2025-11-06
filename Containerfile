# Build stage
FROM rust:1.91-trixie AS builder

# # Install build dependencies
# RUN apt-get update && \
#     apt-get install -y --no-install-recommends \
#     dephere
#     && rm -rf /var/lib/apt/lists/*

# Create workspace structure
WORKDIR /app

# Copy source code
COPY . .

# Build for release with optimizations
RUN cargo build --release

# Runtime stage
FROM debian:bookworm-slim

# Install ca-certificates for TLS
RUN apt-get update && \
    apt-get install -y --no-install-recommends ca-certificates curl && \
    rm -rf /var/lib/apt/lists/*

# Create non-root user
RUN useradd -m -u 1000 -s /bin/bash appuser

# Set working directory
WORKDIR /app

# Copy the binary from builder
COPY --from=builder /app/target/release/stratus /usr/local/bin/stratus

# Switch to non-root user
USER appuser

# Default port (can be overridden)
ENV PORT=443

# Expose ports (this is documentation only, actual port binding happens at runtime)
EXPOSE ${PORT}/tcp

# Healthcheck using curl with PORT environment variable
# The sh -c wrapper allows environment variable expansion
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD sh -c 'curl -f -k https://localhost:${PORT}/health || exit 1'

# Run the binary
CMD ["stratus"]
