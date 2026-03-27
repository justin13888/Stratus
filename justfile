# Fix formatting
fmt:
    cargo fmt --all

# Check formatting
fmt-check:
    cargo fmt --all -- --check

# Fix auto-fixable lint issues
lint:
    cargo clippy --all-targets --fix --allow-dirty -- -D warnings

# Check for lint errors
clippy:
    cargo clippy --all-targets -- -D warnings

# Run all tests
test:
    cargo test --all

# Run pre-commit checks: format fix, lint fix, clippy check, diff check
pre-commit: fmt lint clippy
    git diff --exit-code

# Run pre-push checks: format check, clippy check, test run
pre-push: fmt-check clippy test
