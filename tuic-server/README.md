# tuic-server

Minimalistic TUIC server implementation as a reference.

---

## Table of Contents

- [Overview](#overview)
- [Features](#features)
- [Installation](#installation)
- [Usage](#usage)
- [Configuration](#configuration)
- [TLS Certificates](#tls-certificates)
- [Contributing](#contributing)
- [License](#license)

---

## Overview

`tuic-server` is a robust and actively developed implementation of the TUIC protocol server. It is a fork of the original TUIC project with significant enhancements and additional features. While it started as a reference implementation, it has evolved to include many production-ready capabilities.

This fork includes updated dependencies and improved performance through more relaxed locks. It is suitable for both learning and production environments.

---

## Features

- Minimal TUIC protocol server implementation
- TOML configuration support
- Flexible ACL (Access Control List) system
- Multiple outbound proxy modes (direct, SOCKS5, etc.)
- TLS support

---

## Installation

### Download Prebuilt Binary

Get the latest release from [GitHub Releases](https://github.com/Itsusinn/tuic/releases).

### Install via Cargo

```bash
cargo install --git https://github.com/Itsusinn/tuic.git tuic-server
```

---

## Usage

Run the TUIC server with a configuration file:

```bash
# Specify config file directly
tuic-server -c PATH/TO/CONFIG

# Specify config directory (automatically finds first config file)
tuic-server -d PATH/TO/CONFIG_DIR

# Generate example configuration file
tuic-server --init
```

The `-d/--dir` option searches for the first `.toml` configuration file in the specified directory, sorted alphabetically. This provides flexibility in multi-environment setups.

---

## Configuration

Configuration files use the TOML format with `.toml` file extension.

### Example configuration

```toml
# Logging level: trace, debug, info, warn, error, off
log_level = "info"

# Socket address to listen on
server = "[::]:443"

# Working directory for tuic-server (used for relative certificate/key paths)
data_dir = ""

# Create separate UDP sockets for relaying IPv6 UDP packets
udp_relay_ipv6 = true
# Enable 0-RTT QUIC handshake (recommended: false for security)
zero_rtt_handshake = false
# Set if listening socket should be dual-stack (IPv4/IPv6)
dual_stack = true
# How long to wait for client authentication command
auth_timeout = "3s"
# Maximum duration for task negotiation
task_negotiation_timeout = "3s"
# Interval between UDP packet fragment garbage collection
gc_interval = "10s"
# How long to keep UDP packet fragments before dropping
gc_lifetime = "30s"
# Maximum packet size received from outbound UDP sockets (bytes)
max_external_packet_size = 1500
# How long to preserve TCP and UDP I/O tasks
stream_timeout = "60s"

# Access Control List (ACL) rules - can be specified in two formats:

# Format 1: Array of tables format
[[acl]]
# Address: IPv4/IPv6, CIDR, domain, wildcard, localhost, or private
addr = "127.0.0.1"

# Ports: comma-separated list, can specify protocol (e.g. "udp/53,tcp/80,udp/10000-20000,443")
ports = "udp/53"
# Outbound: direct / default / drop / <custom_outbound_name>
outbound = "default"
# Hijack: optional, redirect to specified address
hijack = "1.1.1.1"

[[acl]]
addr = "localhost"
outbound = "drop"

# You can also use 'private' to match all LAN/private IP addresses
# This includes: 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 169.254.0.0/16 (IPv4)
# and fc00::/7, fe80::/10 (IPv6)
[[acl]]
addr = "private"
outbound = "drop"

# Format 2: Multi-line string format (more concise)
acl = '''
# Format: <outbound_name> <address> [<ports>] [<hijack_address>]
direct localhost tcp/80,tcp/443,udp/443
drop localhost
drop private
default 8.8.4.4 udp/53 1.1.1.1
'''

[users]
# User list: UUID = UID
# UUID acts as the authentication token (password), UID is used for statistics tracking
f0e12827-fe60-458c-8269-a05ccb0ff8da = 1

[tls]
# Path to certificate file (relative to data_dir if not absolute)
certificate = "/path/to/cert.pem"
# Path to private key file (relative to data_dir if not absolute)
private_key = "/path/to/key.pem"
# ALPN protocols (e.g. ["h3"])
alpn = []

[quic]
# Congestion control configuration
[quic.congestion_control]
# Congestion control algorithm: bbr, cubic, new_reno
controller = "bbr"
# Initial congestion window size in bytes
initial_window = 1048576

# Initial UDP payload size before MTU discovery
initial_mtu = 1200
# The maximum UDP payload size guaranteed to be supported by the network.
# Must be at least 1200, which is the default, and lower than or equal to initial_mtu
min_mtu = 1200
# Enable Generic Segmentation Offload
gso = true
# Enable Path MTU Discovery
pmtu = true
# Max bytes to transmit to peer without acknowledgment
send_window = 16777216
# Max bytes peer may transmit without acknowledgment per stream
receive_window = 8388608
# How long to wait before closing idle connection
max_idle_time = "30s"

# Experimental features
[experimental]
# Drop connections to loopback addresses (127.0.0.1, ::1) when no explicit ACL rule matches
# This is a built-in safety feature to prevent accidental exposure of localhost services
# Set to false to allow connections to loopback addresses by default
drop_loopback = true

# Drop connections to private/LAN addresses when no explicit ACL rule matches
# This prevents proxying to RFC 1918 private networks:
# - IPv4: 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 169.254.0.0/16 (link-local)
# - IPv6: fc00::/7 (unique local), fe80::/10 (link-local)
# Set to false to allow connections to private addresses by default
drop_private = true

# Outbound configuration
[outbound]
# Default outbound rule used when no name is specified
[outbound.default]
# Outbound type: direct or socks5
type = "direct"
# IP mode: v4first (prefer IPv4), v6first (prefer IPv6), v4only (IPv4 only), v6only (IPv6 only)
# Legacy aliases: prefer_v4, prefer_v6, only_v4, only_v6
ip_mode = "v4first"

# Named outbound rules - these are referenced from ACL rules
# The named outbound rules get merged into [outbound.named] map in the config
[outbound.prefer_v4]
type = "direct"
ip_mode = "v4first"
# Local addresses to bind for direct connections
bind_ipv4 = "1.2.3.4"
bind_ipv6 = "0:0:0:0:0:ffff:0102:0304"
# Network interface to bind for direct connections
bind_device = "eth1234"

[outbound.through_socks5]
type = "socks5"
# SOCKS5 proxy address
addr = "127.0.0.1:1080"
# SOCKS5 username (optional)
username = "optional"
# SOCKS5 password (optional)
password = "optional"
# Allow UDP when using SOCKS5 outbound (default: false)
allow_udp = false
```

---

## TLS Certificates

TLS is required for secure connections.

### Using External Certificate Tools

You can use [acme.sh](https://github.com/acmesh-official/acme.sh) or other tools to obtain certificates:

```sh
acme.sh --issue -d www.yourdomain.org --standalone
acme.sh --install-cert -d www.yourdomain.org \
  --key-file       /CERT_PATH/key.crt  \
  --fullchain-file /CERT_PATH/cert.crt
```

---

## Contributing

Contributions, bug reports, and feature requests are welcome! Please open issues or pull requests on [GitHub](https://github.com/Itsusinn/tuic).

---

## License

GNU General Public License v3.0. See [LICENSE](../LICENSE) for details.
