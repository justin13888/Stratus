//! Metrics collection and instrumentation
//!
//! This module provides Prometheus metrics integration using the `metrics` crate,
//! with instrumentation decoupled from the metrics backend.

use axum::{
    extract::{MatchedPath, Request},
    http::StatusCode,
    middleware::Next,
    response::{IntoResponse, Response},
};
use metrics::{counter, describe_counter, describe_gauge, describe_histogram, gauge, histogram};
use metrics_exporter_prometheus::{Matcher, PrometheusBuilder, PrometheusHandle};
use std::time::Instant;
use tracing::{debug, info};

/// Initialize the Prometheus metrics exporter
///
/// Returns a handle that can be used to render the metrics in Prometheus format
pub fn init_metrics_exporter() -> eyre::Result<PrometheusHandle> {
    let builder = PrometheusBuilder::new();

    // Configure histogram buckets for latency metrics
    let builder = builder
        .set_buckets_for_metric(
            Matcher::Full("http_request_duration_seconds".to_string()),
            &[
                0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0,
            ],
        )
        .map_err(|e| eyre::eyre!("Failed to set histogram buckets: {}", e))?;

    // Install the exporter
    let handle = builder
        .install_recorder()
        .map_err(|e| eyre::eyre!("Failed to install metrics recorder: {}", e))?;

    // Describe all metrics
    describe_metrics();

    info!("Metrics exporter initialized");
    Ok(handle)
}

/// Describe all metrics for better Prometheus metadata
fn describe_metrics() {
    // HTTP metrics
    describe_counter!(
        "http_requests_total",
        "Total number of HTTP requests received"
    );
    describe_histogram!(
        "http_request_duration_seconds",
        "HTTP request latency in seconds"
    );
    describe_counter!("http_request_errors_total", "Total number of HTTP errors");
    describe_gauge!(
        "http_requests_in_flight",
        "Number of HTTP requests currently being processed"
    );

    // Share-specific metrics
    describe_counter!("share_requests_total", "Total number of requests per share");
    describe_counter!("share_bytes_served_total", "Total bytes served per share");
    describe_counter!("share_errors_total", "Total number of errors per share");

    // File operation metrics
    describe_counter!("file_operations_total", "Total number of file operations");
    describe_histogram!(
        "file_operation_duration_seconds",
        "File operation latency in seconds"
    );

    // System metrics
    describe_gauge!("active_connections", "Number of active client connections");
    describe_counter!("connections_total", "Total number of connections received");

    debug!("Metrics descriptions registered");
}

/// Middleware to track HTTP request metrics
///
/// This middleware records:
/// - Total request count by method, path, and status
/// - Request duration by method and path
/// - Requests in flight
/// - Error counts by status code
pub async fn track_metrics(request: Request, next: Next) -> Response {
    let start = Instant::now();
    let method = request.method().clone();
    let path = request
        .extensions()
        .get::<MatchedPath>()
        .map(|p| p.as_str().to_string())
        .unwrap_or_else(|| request.uri().path().to_string());

    // Track requests in flight
    gauge!("http_requests_in_flight").increment(1.0);

    // Process the request
    let response = next.run(request).await;

    // Track request completion
    gauge!("http_requests_in_flight").decrement(1.0);

    let status = response.status();
    let status_code = status.as_u16().to_string();
    let duration = start.elapsed().as_secs_f64();

    // Record metrics with labels
    counter!(
        "http_requests_total",
        "method" => method.to_string(),
        "path" => path.clone(),
        "status" => status_code.clone(),
    )
    .increment(1);

    histogram!(
        "http_request_duration_seconds",
        "method" => method.to_string(),
        "path" => path.clone(),
    )
    .record(duration);

    // Track errors separately
    if status.is_client_error() || status.is_server_error() {
        counter!(
            "http_request_errors_total",
            "method" => method.to_string(),
            "path" => path,
            "status" => status_code,
        )
        .increment(1);
    }

    response
}

/// Handler for the /metrics endpoint
///
/// Returns the current metrics in Prometheus exposition format
pub async fn metrics_handler(handle: axum::extract::State<PrometheusHandle>) -> impl IntoResponse {
    let metrics = handle.render();
    (StatusCode::OK, metrics)
}

/// Record a share-specific metric
pub fn record_share_request(share_name: &str, bytes_served: u64, success: bool) {
    counter!(
        "share_requests_total",
        "share" => share_name.to_string(),
        "success" => success.to_string(),
    )
    .increment(1);

    if success {
        counter!(
            "share_bytes_served_total",
            "share" => share_name.to_string(),
        )
        .increment(bytes_served);
    } else {
        counter!(
            "share_errors_total",
            "share" => share_name.to_string(),
        )
        .increment(1);
    }
}

/// Record a file operation metric
pub fn record_file_operation(operation: &str, duration: std::time::Duration) {
    counter!(
        "file_operations_total",
        "operation" => operation.to_string(),
    )
    .increment(1);

    histogram!(
        "file_operation_duration_seconds",
        "operation" => operation.to_string(),
    )
    .record(duration.as_secs_f64());
}

/// Increment the active connections gauge
///
/// Note: This is part of the metrics API but currently not used in the application.
/// Reserved for future connection tracking implementation.
#[allow(dead_code)]
pub fn increment_connections() {
    gauge!("active_connections").increment(1.0);
    counter!("connections_total").increment(1);
}

/// Decrement the active connections gauge
///
/// Note: This is part of the metrics API but currently not used in the application.
/// Reserved for future connection tracking implementation.
#[allow(dead_code)]
pub fn decrement_connections() {
    gauge!("active_connections").decrement(1.0);
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn test_record_file_operation_does_not_panic() {
        record_file_operation("read_metadata", Duration::from_millis(5));
        record_file_operation("open", Duration::from_millis(1));
        record_file_operation("read_directory", Duration::from_micros(200));
    }

    #[test]
    fn test_record_share_request_does_not_panic() {
        record_share_request("test_share", 1024, true);
        record_share_request("test_share", 0, false);
        record_share_request("other_share", 512, true);
    }
}
