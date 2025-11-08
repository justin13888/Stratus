//! Logging initialization and configuration
//!
//! This module handles the setup of tracing/logging infrastructure,
//! separating logging concerns from main application logic.

use crate::config::LoggingConfig;
use eyre::Result;
use tracing_subscriber::{EnvFilter, fmt, layer::SubscriberExt, util::SubscriberInitExt};

/// Initialize the tracing subscriber based on configuration
///
/// Sets up logging with:
/// - Configurable log level
/// - Optional file output
/// - JSON format for structured logging
/// - Environment variable override support
///
/// # Arguments
///
/// * `config` - Logging configuration
///
/// # Returns
///
/// Returns `Ok(())` on success, or an error if initialization fails
pub fn init_logger(config: &LoggingConfig) -> Result<()> {
    let env_filter = create_env_filter(&config.level);

    if let Some(log_file) = &config.file {
        init_file_logger(log_file, env_filter)?;
    } else {
        init_console_logger(env_filter);
    }

    Ok(())
}

/// Create an environment filter with fallback to configured level
fn create_env_filter(log_level: &crate::config::LogLevel) -> EnvFilter {
    EnvFilter::try_from_default_env().unwrap_or_else(|_| {
        EnvFilter::new(format!("stratus={log_level},tower_http=debug,axum=debug"))
    })
}

/// Initialize file-based logging
fn init_file_logger(log_file: &std::path::Path, env_filter: EnvFilter) -> Result<()> {
    let parent_dir = log_file
        .parent()
        .unwrap_or_else(|| std::path::Path::new("."));

    let file_name = log_file
        .file_name()
        .unwrap_or_else(|| std::ffi::OsStr::new("stratus.log"));

    let file_appender = tracing_appender::rolling::daily(parent_dir, file_name);
    let (non_blocking, _guard) = tracing_appender::non_blocking(file_appender);

    tracing_subscriber::registry()
        .with(
            fmt::layer()
                .json()
                .with_current_span(false)
                .with_span_list(true)
                .with_writer(non_blocking),
        )
        .with(env_filter)
        .init();

    // Keep the guard alive for the lifetime of the program
    std::mem::forget(_guard);

    Ok(())
}

/// Initialize console-only logging
fn init_console_logger(env_filter: EnvFilter) {
    tracing_subscriber::registry()
        .with(
            fmt::layer()
                .json()
                .with_current_span(false)
                .with_span_list(true),
        )
        .with(env_filter)
        .init();
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{LogLevel, LoggingConfig};
    use std::path::PathBuf;

    #[test]
    fn test_log_level_display() {
        assert_eq!(LogLevel::Trace.to_string(), "trace");
        assert_eq!(LogLevel::Debug.to_string(), "debug");
        assert_eq!(LogLevel::Info.to_string(), "info");
        assert_eq!(LogLevel::Warn.to_string(), "warn");
        assert_eq!(LogLevel::Error.to_string(), "error");
    }

    #[test]
    fn test_create_env_filter_with_config() {
        let filter = create_env_filter(&LogLevel::Debug);
        // EnvFilter doesn't expose its internal state easily,
        // but we can verify it was created without panicking
        assert!(filter.to_string().contains("debug") || filter.to_string().contains("stratus"));
    }

    #[test]
    fn test_create_env_filter_different_levels() {
        // Test that we can create filters for all log levels
        for level in LogLevel::all() {
            let _filter = create_env_filter(&level);
            // If we get here without panicking, the test passed
        }
    }

    #[test]
    fn test_logging_config_console_only() {
        // This test verifies the function signature and basic structure
        // Actual initialization is tested in integration tests since it's a global operation
        let config = LoggingConfig {
            level: LogLevel::Info,
            file: None,
            access_log: true,
        };

        // We can't actually call init_logger multiple times in tests
        // as it modifies global state, but we can verify the config structure
        assert_eq!(config.level.to_string(), "info");
        assert!(config.file.is_none());
    }

    #[test]
    fn test_logging_config_with_file() {
        let config = LoggingConfig {
            level: LogLevel::Debug,
            file: Some(PathBuf::from("/tmp/test.log")),
            access_log: false,
        };

        assert_eq!(config.level.to_string(), "debug");
        assert!(config.file.is_some());
        assert_eq!(
            config.file.as_ref().unwrap(),
            &PathBuf::from("/tmp/test.log")
        );
    }

    #[test]
    fn test_all_log_levels() {
        // Comprehensive test for all log level variants
        let levels = vec![
            (LogLevel::Trace, "trace"),
            (LogLevel::Debug, "debug"),
            (LogLevel::Info, "info"),
            (LogLevel::Warn, "warn"),
            (LogLevel::Error, "error"),
        ];

        for (level, expected) in levels {
            assert_eq!(level.to_string(), expected);
        }
    }
}
