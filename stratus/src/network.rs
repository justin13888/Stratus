//! Network and socket configuration
//!
//! This module handles low-level socket configuration including:
//! - TCP socket options (TCP_NODELAY, SO_REUSEADDR)
//! - TCP keepalive settings
//! - Listen backlog configuration

use crate::config::NetworkConfig;
use eyre::{Result, eyre};
use socket2::{Domain, Protocol, Socket, TcpKeepalive, Type};
use std::net::{SocketAddr, TcpListener};
use std::time::Duration;

/// Configure and create a TCP listener socket with custom options
///
/// Creates a socket with:
/// - Configured TCP_NODELAY option
/// - Configured TCP keepalive
/// - SO_REUSEADDR for easier restarts
/// - Custom listen backlog
///
/// # Arguments
///
/// * `bind_addr` - Address to bind the socket to
/// * `config` - Network configuration options
///
/// # Returns
///
/// Returns configured `TcpListener` ready to accept connections
///
/// # Errors
///
/// Returns an error if:
/// - Socket creation fails
/// - Socket option configuration fails
/// - Binding to address fails
/// - Listen operation fails
pub fn configure_socket(bind_addr: SocketAddr, config: &NetworkConfig) -> Result<TcpListener> {
    let socket = create_socket(bind_addr)?;

    configure_tcp_nodelay(&socket, config)?;
    configure_tcp_keepalive(&socket, config)?;
    configure_reuse_addr(&socket)?;

    bind_and_listen(&socket, bind_addr, config)?;

    socket
        .set_nonblocking(true)
        .map_err(|e| eyre!("Failed to set non-blocking mode: {}", e))?;

    Ok(TcpListener::from(socket))
}

/// Create a new TCP socket
fn create_socket(bind_addr: SocketAddr) -> Result<Socket> {
    Socket::new(
        Domain::for_address(bind_addr),
        Type::STREAM,
        Some(Protocol::TCP),
    )
    .map_err(|e| eyre!("Failed to create socket: {}", e))
}

/// Configure TCP_NODELAY option if enabled in config
fn configure_tcp_nodelay(socket: &Socket, config: &NetworkConfig) -> Result<()> {
    if config.tcp_nodelay {
        socket
            .set_nodelay(true)
            .map_err(|e| eyre!("Failed to set TCP_NODELAY: {}", e))?;
    }
    Ok(())
}

/// Configure TCP keepalive if enabled in config
fn configure_tcp_keepalive(socket: &Socket, config: &NetworkConfig) -> Result<()> {
    if config.tcp_keepalive {
        let keepalive =
            TcpKeepalive::new().with_time(Duration::from_secs(config.tcp_keepalive_interval));

        socket
            .set_tcp_keepalive(&keepalive)
            .map_err(|e| eyre!("Failed to set TCP keepalive: {}", e))?;
    }
    Ok(())
}

/// Configure SO_REUSEADDR for easier server restarts
fn configure_reuse_addr(socket: &Socket) -> Result<()> {
    socket
        .set_reuse_address(true)
        .map_err(|e| eyre!("Failed to set SO_REUSEADDR: {}", e))
}

/// Bind socket to address and start listening
fn bind_and_listen(socket: &Socket, bind_addr: SocketAddr, config: &NetworkConfig) -> Result<()> {
    socket
        .bind(&bind_addr.into())
        .map_err(|e| eyre!("Failed to bind to {}: {}", bind_addr, e))?;

    socket
        .listen(config.listen_backlog as i32)
        .map_err(|e| eyre!("Failed to listen: {}", e))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::NetworkConfig;

    fn test_network_config() -> NetworkConfig {
        NetworkConfig {
            max_connections: 1000,
            connection_timeout: 60,
            request_timeout: 30,
            max_request_size: 100,
            tcp_keepalive: true,
            tcp_keepalive_interval: 60,
            tcp_nodelay: true,
            listen_backlog: 1024,
        }
    }

    #[test]
    fn test_create_socket_ipv4() {
        let addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
        let result = create_socket(addr);
        assert!(result.is_ok());
    }

    #[test]
    fn test_create_socket_ipv6() {
        let addr: SocketAddr = "[::1]:0".parse().unwrap();
        let result = create_socket(addr);
        assert!(result.is_ok());
    }

    #[test]
    fn test_configure_reuse_addr() {
        let addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
        let socket = create_socket(addr).unwrap();

        let result = configure_reuse_addr(&socket);
        assert!(result.is_ok());

        // Verify it was actually set
        assert!(socket.reuse_address().unwrap());
    }

    #[test]
    fn test_configure_tcp_nodelay_enabled() {
        let addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
        let socket = create_socket(addr).unwrap();
        let mut config = test_network_config();
        config.tcp_nodelay = true;

        let result = configure_tcp_nodelay(&socket, &config);
        assert!(result.is_ok());

        // Verify it was actually set
        assert!(socket.nodelay().unwrap());
    }

    #[test]
    fn test_configure_tcp_nodelay_disabled() {
        let addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
        let socket = create_socket(addr).unwrap();
        let mut config = test_network_config();
        config.tcp_nodelay = false;

        let result = configure_tcp_nodelay(&socket, &config);
        assert!(result.is_ok());

        // Should not be set (default is false)
        assert!(!socket.nodelay().unwrap());
    }

    #[test]
    fn test_configure_tcp_keepalive_enabled() {
        let addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
        let socket = create_socket(addr).unwrap();
        let mut config = test_network_config();
        config.tcp_keepalive = true;
        config.tcp_keepalive_interval = 120;

        let result = configure_tcp_keepalive(&socket, &config);
        assert!(result.is_ok());
    }

    #[test]
    fn test_configure_tcp_keepalive_disabled() {
        let addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
        let socket = create_socket(addr).unwrap();
        let mut config = test_network_config();
        config.tcp_keepalive = false;

        let result = configure_tcp_keepalive(&socket, &config);
        assert!(result.is_ok());
    }

    #[test]
    fn test_bind_and_listen_success() {
        let addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
        let socket = create_socket(addr).unwrap();
        let config = test_network_config();

        let result = bind_and_listen(&socket, addr, &config);
        assert!(result.is_ok());
    }

    #[test]
    fn test_bind_and_listen_with_backlog() {
        let addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
        let socket = create_socket(addr).unwrap();
        let mut config = test_network_config();
        config.listen_backlog = 512;

        let result = bind_and_listen(&socket, addr, &config);
        assert!(result.is_ok());
    }

    #[test]
    fn test_configure_socket_full_integration() {
        // Use port 0 to let OS assign a free port
        let addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
        let config = test_network_config();

        let result = configure_socket(addr, &config);
        assert!(result.is_ok());

        let listener = result.unwrap();
        // Verify we got a valid local address
        assert!(listener.local_addr().is_ok());
    }

    #[test]
    fn test_configure_socket_with_all_options_disabled() {
        let addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
        let config = NetworkConfig {
            max_connections: 100,
            connection_timeout: 30,
            request_timeout: 15,
            max_request_size: 50,
            tcp_keepalive: false,
            tcp_keepalive_interval: 60,
            tcp_nodelay: false,
            listen_backlog: 128,
        };

        let result = configure_socket(addr, &config);
        assert!(result.is_ok());
    }

    #[test]
    fn test_configure_socket_bind_to_used_port_fails() {
        let addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
        let config = test_network_config();

        // First socket succeeds
        let listener1 = configure_socket(addr, &config).unwrap();
        let actual_addr = listener1.local_addr().unwrap();

        // Try to bind to the same port - should fail
        let result = configure_socket(actual_addr, &config);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("Failed to bind"));
    }
}
