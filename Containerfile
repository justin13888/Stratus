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

# Install curl for healthcheck
RUN apt-get update && \
    apt-get install -y --no-install-recommends curl ca-certificates && \
    rm -rf /var/lib/apt/lists/*

# Create non-root user
RUN useradd -m -u 1000 -s /bin/bash appuser

# Set working directory
WORKDIR /app

# Copy the binary from builder
COPY --from=builder /app/target/release/stratus /usr/local/bin/stratus

# Switch to non-root user
USER appuser

# Expose ports
EXPOSE 443/tcp

# Health check using curl to hit the /health endpoint
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD curl -f -k https://localhost:443/health || exit 1

# Run the binary
CMD ["stratus"]
