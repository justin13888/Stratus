#!/bin/bash
# Test script for Stratus metrics endpoint

echo "Testing Stratus Metrics Endpoint"
echo "================================="
echo ""

# Configuration
HOST="${STRATUS_HOST:-localhost}"
PORT="${STRATUS_PORT:-8443}"
METRICS_HOST="${METRICS_HOST:-localhost}"
METRICS_PORT="${METRICS_PORT:-9090}"
METRICS_ENDPOINT="${METRICS_ENDPOINT:-/metrics}"

echo "Testing two possible configurations:"
echo "1. Metrics on main server: https://${HOST}:${PORT}${METRICS_ENDPOINT}"
echo "2. Separate metrics server: http://${METRICS_HOST}:${METRICS_PORT}${METRICS_ENDPOINT}"
echo ""

# Test 1: Health check on main server
echo "1. Testing health endpoint on main server..."
if curl -sk "https://${HOST}:${PORT}/health" -o /dev/null -w "%{http_code}\n" 2>&1 | grep -q "200"; then
    echo "✓ Main server is accessible"
    MAIN_SERVER_UP=true
else
    echo "✗ Main server is not accessible"
    MAIN_SERVER_UP=false
fi
echo ""

# Test 2: Make some requests to generate metrics
if [ "$MAIN_SERVER_UP" = true ]; then
    echo "2. Generating sample metrics on main server..."
    for i in {1..5}; do
        curl -sk "https://${HOST}:${PORT}/health" > /dev/null 2>&1
    done
    echo "✓ Made 5 requests to health endpoint"
    echo ""
fi

# Test 3: Try to fetch metrics from main server
echo "3. Checking for metrics on main server (https://${HOST}:${PORT}${METRICS_ENDPOINT})..."
MAIN_METRICS=$(curl -sk "https://${HOST}:${PORT}${METRICS_ENDPOINT}" 2>&1)

if echo "$MAIN_METRICS" | grep -q "http_requests_total"; then
    echo "✓ Metrics found on main server (HTTPS)"
    METRICS_LOCATION="main"
    METRICS=$MAIN_METRICS
else
    echo "✗ Metrics not found on main server"
    echo ""
    
    # Test 4: Try separate metrics server
    echo "4. Checking for separate metrics server (http://${METRICS_HOST}:${METRICS_PORT}${METRICS_ENDPOINT})..."
    SEPARATE_METRICS=$(curl -s "http://${METRICS_HOST}:${METRICS_PORT}${METRICS_ENDPOINT}" 2>&1)
    
    if echo "$SEPARATE_METRICS" | grep -q "http_requests_total"; then
        echo "✓ Metrics found on separate server (HTTP)"
        METRICS_LOCATION="separate"
        METRICS=$SEPARATE_METRICS
    else
        echo "✗ Metrics not found on separate server either"
        echo ""
        echo "Metrics server might not be running or configured."
        echo "Check your config.toml [metrics] section."
        exit 1
    fi
fi
echo ""

echo ""

# Display key metrics
echo "Key metrics found:"
echo ""

echo "HTTP Requests:"
echo "$METRICS" | grep "http_requests_total" | head -3
echo ""

echo "Request Duration:"
echo "$METRICS" | grep "http_request_duration_seconds_count" | head -3
echo ""

echo "Requests in Flight:"
echo "$METRICS" | grep "http_requests_in_flight"
echo ""

echo "File Operations:"
echo "$METRICS" | grep "file_operations_total" | head -3
echo ""

echo "Share Metrics:"
echo "$METRICS" | grep "share_requests_total" | head -3
echo ""

echo "Summary:"
echo "========"
if [ "$METRICS_LOCATION" = "main" ]; then
    echo "✓ Metrics are served on the main server with TLS"
    echo "  URL: https://${HOST}:${PORT}${METRICS_ENDPOINT}"
    echo ""
    echo "Prometheus configuration:"
    echo "  scrape_configs:"
    echo "    - job_name: 'stratus'"
    echo "      scheme: 'https'"
    echo "      tls_config:"
    echo "        insecure_skip_verify: true"
    echo "      static_configs:"
    echo "        - targets: ['${HOST}:${PORT}']"
else
    echo "✓ Metrics are served on a separate HTTP server (no TLS)"
    echo "  URL: http://${METRICS_HOST}:${METRICS_PORT}${METRICS_ENDPOINT}"
    echo ""
    echo "Prometheus configuration:"
    echo "  scrape_configs:"
    echo "    - job_name: 'stratus-metrics'"
    echo "      scheme: 'http'"
    echo "      static_configs:"
    echo "        - targets: ['${METRICS_HOST}:${METRICS_PORT}']"
fi
