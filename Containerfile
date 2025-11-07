# ----------------------------------------------------
# 1. Chef Stage: Install cargo-chef
# ----------------------------------------------------
FROM rust:1.91-trixie AS chef
RUN cargo install cargo-chef --locked
WORKDIR /app

# ----------------------------------------------------
# 2. Planner Stage: Create the Dependency Recipe
# ----------------------------------------------------
FROM chef AS planner
COPY . .
RUN cargo chef prepare --recipe-path recipe.json

# ----------------------------------------------------
# 3. Builder Stage (Modified for Caching)
# ----------------------------------------------------
FROM chef AS builder
COPY --from=planner /app/recipe.json recipe.json

RUN cargo chef cook --release --recipe-path recipe.json

# Build application
COPY . .
RUN cargo build --release

# ----------------------------------------------------
# Runtime stage (Untouched for compatibility)
# ----------------------------------------------------
FROM debian:trixie-slim

# Create non-root user
RUN useradd -m -u 1000 -s /bin/bash appuser
USER appuser

# Set working directory
WORKDIR /app

# Copy the binary from builder
COPY --from=builder /app/target/release/stratus /usr/local/bin/stratus

# Default port (can be overridden)
ENV PORT=443

# Expose ports
EXPOSE ${PORT}/tcp

# Run the binary
CMD ["stratus"]
