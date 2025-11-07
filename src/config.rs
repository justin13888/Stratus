use eyre::{Result, eyre};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::IpAddr;
use std::path::PathBuf;

/// TLS version
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum TlsVersion {
    #[serde(rename = "1.2")]
    V1_2,
    #[serde(rename = "1.3")]
    #[default]
    V1_3,
}

/// Client certificate authentication mode
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum ClientCertMode {
    #[default]
    None,
    Optional,
    Required,
}

/// Log level
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum LogLevel {
    Trace,
    Debug,
    #[default]
    Info,
    Warn,
    Error,
}

/// Authentication method
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum AuthMethod {
    #[default]
    Basic,
    Bearer,
    MutualTls,
    Custom,
}

/// Compression algorithm
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum CompressionAlgorithm {
    #[default]
    Gzip,
    Zstd,
    Br,
}

/// Main server configuration loaded from TOML file
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ServerConfig {
    /// Server-wide settings
    pub server: ServerSettings,

    /// TLS/SSL configuration
    pub tls: TlsConfig,

    /// HTTP/2 specific settings
    #[serde(default)]
    pub http2: Http2Config,

    /// Logging configuration
    #[serde(default)]
    pub logging: LoggingConfig,

    /// Metrics configuration
    #[serde(default)]
    pub metrics: MetricsConfig,

    /// Network and connection settings
    #[serde(default)]
    pub network: NetworkConfig,

    /// Security and authentication settings
    #[serde(default)]
    pub security: SecurityConfig,

    /// Directory shares configuration (similar to Samba shares)
    #[serde(default)]
    pub shares: HashMap<String, ShareConfig>,
}

/// Core server settings
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerSettings {
    /// Server bind address
    #[serde(default = "default_bind_address")]
    pub bind_address: IpAddr,

    /// Server port
    #[serde(default = "default_port")]
    pub port: u16,

    /// Server name/identifier
    #[serde(default = "default_server_name")]
    pub server_name: String,

    /// Working directory for the server
    #[serde(default)]
    pub workdir: Option<PathBuf>,
}

/// TLS/SSL configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TlsConfig {
    /// Path to TLS certificate file
    pub cert_file: PathBuf,

    /// Path to TLS private key file
    pub key_file: PathBuf,

    /// Minimum TLS version
    #[serde(default)]
    pub min_version: TlsVersion,

    /// Enable OCSP stapling
    #[serde(default = "default_true")]
    pub ocsp_stapling: bool,

    /// Client certificate authentication mode
    #[serde(default)]
    pub client_cert_mode: ClientCertMode,

    /// Path to client CA certificate file (for client cert verification)
    #[serde(default)]
    pub client_ca_file: Option<PathBuf>,
}

/// HTTP/2 specific configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Http2Config {
    /// Initial connection window size (bytes)
    #[serde(default = "default_connection_window_size")]
    pub initial_connection_window_size: u32,

    /// Initial stream window size (bytes)
    #[serde(default = "default_stream_window_size")]
    pub initial_stream_window_size: u32,

    /// Maximum concurrent streams per connection
    #[serde(default = "default_max_concurrent_streams")]
    pub max_concurrent_streams: u32,

    /// Maximum frame size (bytes)
    #[serde(default = "default_max_frame_size")]
    pub max_frame_size: u32,

    /// Keepalive interval (seconds, 0 to disable)
    #[serde(default = "default_keepalive_interval")]
    pub keepalive_interval: u64,

    /// Keepalive timeout (seconds)
    #[serde(default = "default_keepalive_timeout")]
    pub keepalive_timeout: u64,
}

/// Logging configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoggingConfig {
    /// Log level
    #[serde(default)]
    pub level: LogLevel,

    /// Log file path (optional, logs to stdout if not specified)
    #[serde(default)]
    pub file: Option<PathBuf>,

    /// Enable access logging
    #[serde(default = "default_true")]
    pub access_log: bool,
}

/// Metrics configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MetricsConfig {
    /// Enable metrics collection
    #[serde(default = "default_true")]
    pub enabled: bool,

    /// Metrics endpoint path
    #[serde(default = "default_metrics_endpoint")]
    pub endpoint: String,

    /// Metrics listening address (if different from main server)
    #[serde(default)]
    pub bind_address: Option<IpAddr>,

    /// Metrics listening port (if different from main server)
    #[serde(default)]
    pub port: Option<u16>,
}

/// Network and connection settings
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkConfig {
    /// Maximum number of concurrent connections
    #[serde(default = "default_max_connections")]
    pub max_connections: usize,

    /// Connection timeout (seconds)
    #[serde(default = "default_connection_timeout")]
    pub connection_timeout: u64,

    /// Request timeout (seconds)
    #[serde(default = "default_request_timeout")]
    pub request_timeout: u64,

    /// Maximum request body size (bytes)
    #[serde(default = "default_max_request_size")]
    pub max_request_size: usize,

    /// Enable TCP keepalive
    #[serde(default = "default_true")]
    pub tcp_keepalive: bool,

    /// TCP keepalive interval (seconds)
    #[serde(default = "default_tcp_keepalive_interval")]
    pub tcp_keepalive_interval: u64,

    /// Enable TCP nodelay (disable Nagle's algorithm)
    #[serde(default = "default_true")]
    pub tcp_nodelay: bool,

    /// Listen backlog size
    #[serde(default = "default_listen_backlog")]
    pub listen_backlog: u32,
}

/// Security and authentication settings
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityConfig {
    /// Enable authentication
    #[serde(default = "default_true")]
    pub auth_required: bool,

    /// Authentication method
    #[serde(default)]
    pub auth_method: AuthMethod,

    /// Path to user database file (format depends on auth_method)
    #[serde(default)]
    pub user_db_file: Option<PathBuf>,

    /// Enable CORS
    #[serde(default = "default_false")]
    pub cors_enabled: bool,

    /// CORS allowed origins (empty = all origins)
    #[serde(default)]
    pub cors_allowed_origins: Vec<String>,

    /// Enable rate limiting
    #[serde(default = "default_false")]
    pub rate_limiting_enabled: bool,

    /// Rate limit: requests per minute per IP
    #[serde(default = "default_rate_limit")]
    pub rate_limit: u32,

    /// Enable compression
    #[serde(default = "default_true")]
    pub compression_enabled: bool,

    /// Compression algorithms
    #[serde(default = "default_compression_algorithms")]
    pub compression_algorithms: Vec<CompressionAlgorithm>,

    /// Minimum size for compression (bytes)
    #[serde(default = "default_compression_min_size")]
    pub compression_min_size: usize,
}

/// Directory share configuration (similar to Samba shares)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShareConfig {
    /// Human-readable description of the share
    #[serde(default)]
    pub description: Option<String>,

    /// Filesystem path to share
    pub path: PathBuf,

    /// Whether the share is enabled
    #[serde(default = "default_true")]
    pub enabled: bool,

    /// Whether the share is browseable/listable
    #[serde(default = "default_true")]
    pub browseable: bool,

    /// Whether the share is read-only
    #[serde(default = "default_false")]
    pub read_only: bool,

    /// List of users/groups with read access (empty = all authenticated users)
    #[serde(default)]
    pub read_list: Vec<String>,

    /// List of users/groups with write access (empty = all authenticated users if not read_only)
    #[serde(default)]
    pub write_list: Vec<String>,

    /// List of users/groups with admin access (can modify share settings)
    #[serde(default)]
    pub admin_list: Vec<String>,

    /// List of users/groups explicitly denied access
    #[serde(default)]
    pub deny_list: Vec<String>,

    /// Allow guest/anonymous access
    #[serde(default = "default_false")]
    pub guest_ok: bool,

    /// Maximum number of concurrent connections to this share
    #[serde(default)]
    pub max_connections: Option<usize>,

    /// Hide dot files (files starting with '.')
    #[serde(default = "default_false")]
    pub hide_dot_files: bool,

    /// Follow symbolic links
    #[serde(default = "default_false")]
    pub follow_symlinks: bool,

    /// File patterns to exclude (glob patterns)
    #[serde(default)]
    pub exclude_patterns: Vec<String>,

    /// File patterns to include (empty = all files)
    #[serde(default)]
    pub include_patterns: Vec<String>,

    /// Enable versioning/snapshots
    #[serde(default = "default_false")]
    pub versioning: bool,

    /// Maximum file size allowed for upload (bytes, 0 = unlimited)
    #[serde(default)]
    pub max_file_size: u64,

    /// Enable file locking
    #[serde(default = "default_true")]
    pub file_locking: bool,

    /// Custom mount point/URL path (defaults to share name)
    #[serde(default)]
    pub mount_point: Option<String>,
}

// Default value functions
fn default_bind_address() -> IpAddr {
    "127.0.0.1".parse().unwrap()
}

fn default_port() -> u16 {
    443
}

fn default_server_name() -> String {
    "Stratus".to_string()
}

fn default_connection_window_size() -> u32 {
    1024 * 1024 * 4 // 4MB
}

fn default_stream_window_size() -> u32 {
    1024 * 1024 * 2 // 2MB
}

fn default_max_concurrent_streams() -> u32 {
    128
}

fn default_max_frame_size() -> u32 {
    16384 // 16KB (minimum allowed by HTTP/2 spec)
}

fn default_keepalive_interval() -> u64 {
    60 // seconds
}

fn default_keepalive_timeout() -> u64 {
    20 // seconds
}

fn default_max_connections() -> usize {
    10000
}

fn default_connection_timeout() -> u64 {
    60
}

fn default_request_timeout() -> u64 {
    30
}

fn default_max_request_size() -> usize {
    100 * 1024 * 1024 // 100MB
}

fn default_tcp_keepalive_interval() -> u64 {
    60
}

fn default_listen_backlog() -> u32 {
    1024
}

fn default_rate_limit() -> u32 {
    60
}

fn default_compression_algorithms() -> Vec<CompressionAlgorithm> {
    vec![CompressionAlgorithm::Gzip, CompressionAlgorithm::Zstd]
}

fn default_compression_min_size() -> usize {
    1024 // 1KB
}

fn default_metrics_endpoint() -> String {
    "/metrics".to_string()
}

fn default_true() -> bool {
    true
}

fn default_false() -> bool {
    false
}

// Implementation defaults
impl Default for Http2Config {
    fn default() -> Self {
        Self {
            initial_connection_window_size: default_connection_window_size(),
            initial_stream_window_size: default_stream_window_size(),
            max_concurrent_streams: default_max_concurrent_streams(),
            max_frame_size: default_max_frame_size(),
            keepalive_interval: default_keepalive_interval(),
            keepalive_timeout: default_keepalive_timeout(),
        }
    }
}

impl Default for LoggingConfig {
    fn default() -> Self {
        Self {
            level: LogLevel::default(),
            file: None,
            access_log: default_true(),
        }
    }
}

impl Default for MetricsConfig {
    fn default() -> Self {
        Self {
            enabled: default_true(),
            endpoint: default_metrics_endpoint(),
            bind_address: None,
            port: None,
        }
    }
}

impl Default for NetworkConfig {
    fn default() -> Self {
        Self {
            max_connections: default_max_connections(),
            connection_timeout: default_connection_timeout(),
            request_timeout: default_request_timeout(),
            max_request_size: default_max_request_size(),
            tcp_keepalive: default_true(),
            tcp_keepalive_interval: default_tcp_keepalive_interval(),
            tcp_nodelay: default_true(),
            listen_backlog: default_listen_backlog(),
        }
    }
}

impl Default for SecurityConfig {
    fn default() -> Self {
        Self {
            auth_required: default_true(),
            auth_method: AuthMethod::default(),
            user_db_file: None,
            cors_enabled: default_false(),
            cors_allowed_origins: vec![],
            rate_limiting_enabled: default_false(),
            rate_limit: default_rate_limit(),
            compression_enabled: default_true(),
            compression_algorithms: default_compression_algorithms(),
            compression_min_size: default_compression_min_size(),
        }
    }
}

impl ServerConfig {
    /// Load configuration from a TOML file
    pub fn from_file(path: impl Into<PathBuf>) -> Result<Self> {
        let path = path.into();
        let contents = std::fs::read_to_string(&path)
            .map_err(|e| eyre!("Failed to read config file {:?}: {}", path, e))?;

        let config: ServerConfig =
            toml::from_str(&contents).map_err(|e| eyre!("Failed to parse config file: {}", e))?;

        config.validate()?;
        Ok(config)
    }

    /// Validate the configuration
    pub fn validate(&self) -> Result<()> {
        // Validate TLS files exist
        if !self.tls.cert_file.exists() {
            return Err(eyre!(
                "TLS certificate file not found: {:?}",
                self.tls.cert_file
            ));
        }
        if !self.tls.key_file.exists() {
            return Err(eyre!("TLS key file not found: {:?}", self.tls.key_file));
        }

        // Validate share paths exist
        for (name, share) in &self.shares {
            if !share.path.exists() {
                return Err(eyre!(
                    "Share '{}' path does not exist: {:?}",
                    name,
                    share.path
                ));
            }
            if !share.path.is_dir() {
                return Err(eyre!(
                    "Share '{}' path is not a directory: {:?}",
                    name,
                    share.path
                ));
            }
        }

        // Validate HTTP/2 settings
        if self.http2.max_frame_size < 16384 || self.http2.max_frame_size > 16777215 {
            return Err(eyre!(
                "HTTP/2 max_frame_size must be between 16384 and 16777215"
            ));
        }

        Ok(())
    }
}
