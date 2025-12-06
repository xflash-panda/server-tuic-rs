use std::{
	collections::HashMap,
	net::{Ipv4Addr, Ipv6Addr, SocketAddr},
	path::PathBuf,
	time::Duration,
};

use clap::Parser;
use educe::Educe;
use figment::{
	Figment,
	providers::{Format, Serialized, Toml},
};
use serde::{Deserialize, Serialize};
use tracing::{level_filters::LevelFilter, warn};
use uuid::Uuid;

#[cfg(test)]
use crate::acl::{AclAddress, AclPorts};
use crate::{
	acl::AclRule,
	utils::{CongestionController, StackPrefer},
};


/// Control flow results for CLI parsing
#[derive(Debug)]
pub struct Control(&'static str);

impl std::fmt::Display for Control {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		write!(f, "{}", self.0)
	}
}

impl std::error::Error for Control {}

/// TUIC Server - A minimalistic TUIC server implementation
#[derive(Parser, Debug)]
#[command(name = "tuic-server")]
#[command(author, version, about, long_about = None)]
pub struct Cli {
	/// Path to the config file
	#[arg(short, long, value_name = "PATH")]
	pub config: Option<PathBuf>,

	/// Generate an example configuration file (config.toml)
	#[arg(short, long)]
	pub init: bool,

	/// Path to the certificate file
	#[arg(long, value_name = "PATH", default_value = "/root/.cert/server.crt")]
	pub cert_file: PathBuf,

	/// Path to the private key file
	#[arg(long, value_name = "PATH", default_value = "/root/.cert/server.key")]
	pub key_file: PathBuf,
}

#[derive(Deserialize, Serialize, Educe)]
#[educe(Default)]
#[serde(default, deny_unknown_fields)]
pub struct Config {
	pub log_level: LogLevel,
	#[educe(Default(expression = "[::]:8443".parse().unwrap()))]
	pub server:    SocketAddr,
	pub users:     HashMap<Uuid, u64>,

	/// Certificate file path (set from CLI, not config file)
	#[serde(skip)]
	pub cert_file: PathBuf,
	/// Private key file path (set from CLI, not config file)
	#[serde(skip)]
	pub key_file: PathBuf,

	#[educe(Default = "")]
	pub data_dir: PathBuf,

	pub quic: QuicConfig,

	#[educe(Default = true)]
	pub udp_relay_ipv6: bool,

	#[educe(Default = false)]
	pub zero_rtt_handshake: bool,

	#[educe(Default = true)]
	pub dual_stack: bool,

	#[serde(with = "humantime_serde")]
	#[educe(Default(expression = Duration::from_secs(3)))]
	pub auth_timeout: Duration,

	#[serde(with = "humantime_serde")]
	#[educe(Default(expression = Duration::from_secs(3)))]
	pub task_negotiation_timeout: Duration,

	#[serde(with = "humantime_serde")]
	#[educe(Default(expression = Duration::from_secs(10)))]
	pub gc_interval: Duration,

	#[serde(with = "humantime_serde")]
	#[educe(Default(expression = Duration::from_secs(30)))]
	pub gc_lifetime: Duration,

	#[educe(Default = 1500)]
	pub max_external_packet_size: usize,

	#[serde(with = "humantime_serde")]
	#[educe(Default(expression = Duration::from_secs(60)))]
	pub stream_timeout: Duration,

	#[serde(default)]
	pub outbound: OutboundConfig,

	/// Access Control List rules
	#[serde(default, deserialize_with = "crate::acl::deserialize_acl")]
	#[educe(Default(expression = Vec::new()))]
	pub acl: Vec<AclRule>,

	pub experimental: ExperimentalConfig,

	/// Old configuration fields (deprecated, kept for migration)
	#[serde(default, skip_serializing, rename = "tls")]
	#[deprecated]
	pub __tls:                Option<serde::de::IgnoredAny>,
	#[serde(default, skip_serializing, rename = "certificate")]
	#[deprecated]
	pub __certificate:        Option<serde::de::IgnoredAny>,
	#[serde(default, skip_serializing, rename = "private_key")]
	#[deprecated]
	pub __private_key:        Option<serde::de::IgnoredAny>,
	#[serde(default, rename = "congestion_control")]
	#[deprecated]
	pub __congestion_control: Option<CongestionController>,
	#[serde(default, rename = "alpn")]
	#[deprecated]
	pub __alpn:               Option<Vec<String>>,
	#[serde(default, rename = "max_idle_time", with = "humantime_serde")]
	#[deprecated]
	pub __max_idle_time:      Option<Duration>,
	#[serde(default, rename = "initial_window")]
	#[deprecated]
	pub __initial_window:     Option<u64>,
	#[serde(default, rename = "receive_window")]
	#[deprecated]
	pub __send_window:        Option<u64>,
	#[serde(default, rename = "send_window")]
	#[deprecated]
	pub __receive_window:     Option<u32>,
	#[serde(default, rename = "initial_mtu")]
	#[deprecated]
	pub __initial_mtu:        Option<u16>,
	#[serde(default, rename = "min_mtu")]
	#[deprecated]
	pub __min_mtu:            Option<u16>,
	#[serde(default, rename = "gso")]
	#[deprecated]
	pub __gso:                Option<bool>,
	#[serde(default, rename = "pmtu")]
	#[deprecated]
	pub __pmtu: Option<bool>,
}


#[derive(Deserialize, Serialize, Educe)]
#[educe(Default)]
#[serde(default, deny_unknown_fields)]
pub struct QuicConfig {
	pub congestion_control: CongestionControlConfig,

	#[educe(Default = 1200)]
	pub initial_mtu: u16,

	#[educe(Default = 1200)]
	pub min_mtu: u16,

	#[educe(Default = true)]
	pub gso: bool,

	#[educe(Default = true)]
	pub pmtu: bool,

	#[educe(Default = 16777216)]
	pub send_window: u64,

	#[educe(Default = 8388608)]
	pub receive_window: u32,

	#[serde(with = "humantime_serde")]
	#[educe(Default(expression = Duration::from_secs(30)))]
	pub max_idle_time: Duration,
}

/// The `default` rule is mandatory when named rules are present; other named
/// rules are optional.
#[derive(Deserialize, Serialize, Educe, Clone, Debug)]
#[educe(Default)]
pub struct OutboundConfig {
	/// The default outbound rule (used when no name is specified).
	#[serde(default)]
	pub default: OutboundRule,

	/// Additional named outbound rules (e.g., `prefer_v4`, `through_socks5`).
	#[serde(flatten)]
	pub named: std::collections::HashMap<String, OutboundRule>,
}

/// Represents a single outbound rule (e.g., direct, socks5).
#[derive(Deserialize, Serialize, Educe, Clone, Debug)]
#[educe(Default)]
#[serde(deny_unknown_fields)]
pub struct OutboundRule {
	/// The type of outbound: "direct" or "socks5".
	#[educe(Default = "direct".to_string())]
	#[serde(rename = "type")]
	pub kind: String,

	/// Mode for direct connections: "v4first" (prefer IPv4), "v6first" (prefer
	/// IPv6), "v4only" (IPv4 only), "v6only" (IPv6 only).
	#[educe(Default(expression = Some(StackPrefer::V4first)))]
	pub ip_mode: Option<StackPrefer>,

	/// Optional IPv4 address to bind to for direct connections (only used when
	/// kind == "direct").
	#[serde(default)]
	pub bind_ipv4: Option<Ipv4Addr>,

	/// Optional IPv6 address to bind to for direct connections (only used when
	/// kind == "direct").
	#[serde(default)]
	pub bind_ipv6: Option<Ipv6Addr>,

	/// Optional device/interface name to bind to (only used when kind ==
	/// "direct").
	#[serde(default)]
	pub bind_device: Option<String>,

	/// SOCKS5 address (only used when kind == "socks5").
	#[serde(default)]
	pub addr: Option<String>,

	/// Optional SOCKS5 username (only used when kind == "socks5").
	#[serde(default)]
	pub username: Option<String>,

	/// Optional SOCKS5 password (only used when kind == "socks5").
	#[serde(default)]
	pub password: Option<String>,

	/// Whether to allow UDP traffic when this outbound is selected.
	/// Only effective for kind == "socks5". Default behavior is to block UDP
	/// (i.e., drop UDP packets) to avoid leaking QUIC/HTTP3 over direct path.
	/// Set to true to allow UDP (still sent directly; UDP over SOCKS5 is not
	/// implemented).
	#[serde(default)]
	pub allow_udp: Option<bool>,
}

#[derive(Deserialize, Serialize, Educe)]
#[educe(Default)]
#[serde(default, deny_unknown_fields)]
pub struct CongestionControlConfig {
	pub controller:     CongestionController,
	#[educe(Default = 1048576)]
	pub initial_window: u64,
}

#[derive(Deserialize, Serialize, Educe, Clone)]
#[educe(Default)]
#[serde(default)]
pub struct ExperimentalConfig {
	#[educe(Default = true)]
	pub drop_loopback: bool,
	#[educe(Default = true)]
	pub drop_private:  bool,
}

impl Config {
	pub fn migrate(&mut self) {
		// Migrate QUIC-related fields
		#[allow(deprecated)]
		{
			if let Some(congestion_control) = self.__congestion_control {
				self.quic.congestion_control.controller = congestion_control;
			}
			if let Some(max_idle_time) = self.__max_idle_time {
				self.quic.max_idle_time = max_idle_time;
			}
			if let Some(initial_window) = self.__initial_window {
				self.quic.congestion_control.initial_window = initial_window;
			}
			if let Some(send_window) = self.__send_window {
				self.quic.send_window = send_window;
			}
			if let Some(receive_window) = self.__receive_window {
				self.quic.receive_window = receive_window;
			}
			if let Some(initial_mtu) = self.__initial_mtu {
				self.quic.initial_mtu = initial_mtu;
			}
			if let Some(min_mtu) = self.__min_mtu {
				self.quic.min_mtu = min_mtu;
			}
			if let Some(gso) = self.__gso {
				self.quic.gso = gso;
			}
			if let Some(pmtu) = self.__pmtu {
				self.quic.pmtu = pmtu;
			}
		}

	}

	pub fn full_example() -> Self {
		Self {
			users: {
				let mut users = HashMap::new();
				users.insert(Uuid::new_v4(), 1);
				users
			},
			// Provide a minimal outbound example
			outbound: OutboundConfig {
				default: OutboundRule {
					kind: "direct".into(),
					ip_mode: Some(StackPrefer::V4first),
					..Default::default()
				},
				..Default::default()
			},
			// Example ACL list (empty by default)
			acl: Vec::new(),
			..Default::default()
		}
	}
}

#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq)]
#[serde(rename_all = "lowercase")]
#[derive(Educe)]
#[educe(Default)]
pub enum LogLevel {
	Trace,
	Debug,
	#[educe(Default)]
	Info,
	Warn,
	Error,
	Off,
}
impl From<LogLevel> for LevelFilter {
	fn from(value: LogLevel) -> Self {
		match value {
			LogLevel::Trace => LevelFilter::TRACE,
			LogLevel::Debug => LevelFilter::DEBUG,
			LogLevel::Info => LevelFilter::INFO,
			LogLevel::Warn => LevelFilter::WARN,
			LogLevel::Error => LevelFilter::ERROR,
			LogLevel::Off => LevelFilter::OFF,
		}
	}
}


pub async fn parse_config(cli: Cli) -> eyre::Result<Config> {
	// Handle --init flag
	if cli.init {
		warn!("Generating an example configuration to config.toml......");
		let example = Config::full_example();
		let example = toml::to_string_pretty(&example).unwrap();
		tokio::fs::write("config.toml", example).await?;
		return Err(Control("Done").into());
	}

	// Get config path from --config
	let cfg_path = cli.config.ok_or_else(|| {
		eyre::eyre!("Config file is required. Use -c/--config to specify the path, or -h for help.")
	})?;

	// Check if config file exists
	if !cfg_path.exists() {
		return Err(eyre::eyre!("Config file not found: {}", cfg_path.display()));
	}

	let figment = Figment::from(Serialized::defaults(Config::default()))
		.merge(Toml::file(&cfg_path));

	let mut config: Config = figment.extract()?;

	// Migrate legacy fields to new nested structure
	config.migrate();

	if config.data_dir.to_str() == Some("") {
		config.data_dir = std::env::current_dir()?
	} else if config.data_dir.is_relative() {
		config.data_dir = std::env::current_dir()?.join(config.data_dir);
		tokio::fs::create_dir_all(&config.data_dir).await?;
	} else {
		tokio::fs::create_dir_all(&config.data_dir).await?;
	};

	// Set certificate and key paths from CLI arguments
	config.cert_file = cli.cert_file;
	config.key_file = cli.key_file;

	Ok(config)
}

#[cfg(test)]
mod tests {
	use std::{env, fs};

	use tempfile::tempdir;

	use super::*;
	use crate::acl::{AclPortSpec, AclProtocol};

	async fn test_parse_config(config_content: &str) -> eyre::Result<Config> {
		let temp_dir = tempdir().unwrap();
		let config_path = temp_dir.path().join("config.toml");

		fs::write(&config_path, config_content).unwrap();

		// Temporarily set command line arguments for clap to parse
		let os_args = vec![
			"test_binary".to_owned(),
			"--config".to_owned(),
			config_path.to_string_lossy().into_owned(),
		];

		// Parse CLI with test arguments
		let cli = Cli::try_parse_from(os_args)?;

		// Call parse_config with the CLI
		parse_config(cli).await
	}
	#[tokio::test]
	async fn test_valid_toml_config() -> eyre::Result<()> {
		let config = include_str!("../tests/config/valid_toml_config.toml");

		let result = test_parse_config(config).await.unwrap();

		assert_eq!(result.log_level, LogLevel::Warn);
		assert_eq!(result.server, "127.0.0.1:8080".parse().unwrap());
		assert!(!result.udp_relay_ipv6);
		assert!(result.zero_rtt_handshake);

		assert_eq!(result.quic.initial_mtu, 1400);
		assert_eq!(result.quic.min_mtu, 1300);
		assert_eq!(result.quic.send_window, 10000000);
		assert_eq!(result.quic.congestion_control.controller, CongestionController::Bbr);
		assert_eq!(result.quic.congestion_control.initial_window, 2000000);

		let uuid1 = Uuid::parse_str("123e4567-e89b-12d3-a456-426614174000").unwrap();
		let uuid2 = Uuid::parse_str("123e4567-e89b-12d3-a456-426614174001").unwrap();
		assert_eq!(result.users.get(&uuid1), Some(&1));
		assert_eq!(result.users.get(&uuid2), Some(&2));

		// Cleanup test directories
		let _ = tokio::fs::remove_dir_all("__test__custom_data").await;
		Ok(())
	}

	#[tokio::test]
	async fn test_path_handling() {
		let config = include_str!("../tests/config/path_handling.toml");

		let result = test_parse_config(config).await.unwrap();

		let current_dir = env::current_dir().unwrap();

		assert_eq!(result.data_dir, current_dir.join("__test__relative_path"));

		// Certificate paths are now provided via CLI arguments with defaults
		assert_eq!(result.cert_file, PathBuf::from("/root/.cert/server.crt"));
		assert_eq!(result.key_file, PathBuf::from("/root/.cert/server.key"));

		// Cleanup test directories
		let _ = tokio::fs::remove_dir_all("__test__relative_path").await;
	}

	#[tokio::test]
	async fn test_error_handling() {
		// Test Invalid TOML
		let config = "invalid toml content";
		let result = test_parse_config(config).await;
		assert!(result.is_err());

		// Test non-existent configuration files - should fail when trying to parse
		let result = Cli::try_parse_from(vec!["test_binary", "--config", "non_existent.toml"]);
		// This will succeed at parsing CLI level, but fail when actually loading the
		// file
		if let Ok(cli) = result {
			assert!(cli.config.is_some());
			assert!(!cli.config.unwrap().exists());
		}

		// Test missing configuration file parameters - should fail at CLI parsing level
		let result = Cli::try_parse_from(vec!["test_binary"]);
		// This should succeed because --config is optional in CLI definition
		assert!(result.is_ok());
		let cli = result.unwrap();
		assert!(cli.config.is_none());
	}

	#[tokio::test]
	async fn test_outbound_no_configuration() {
		// Test that when no outbound configuration is provided, default is used
		let config = include_str!("../tests/config/outbound_no_configuration.toml");

		let result = test_parse_config(config).await.unwrap();

		// Should have default outbound configuration
		assert_eq!(result.outbound.default.kind, "direct");
		assert_eq!(result.outbound.named.len(), 0);
	}

	#[tokio::test]
	async fn test_outbound_valid_with_default() {
		// Test that when named outbound rules exist with a proper default, validation
		// passes
		let config = include_str!("../tests/config/outbound_valid_with_default.toml");

		let result = test_parse_config(config).await.unwrap();

		// Should have default and named outbound configurations
		assert_eq!(result.outbound.default.kind, "direct");
		assert_eq!(result.outbound.named.len(), 2);

		let prefer_v4 = result.outbound.named.get("prefer_v4").unwrap();
		assert_eq!(prefer_v4.kind, "direct");
		assert_eq!(prefer_v4.ip_mode, Some(StackPrefer::V4first));
		assert_eq!(prefer_v4.bind_ipv4, Some("2.4.6.8".parse().unwrap()));
		assert_eq!(prefer_v4.bind_device, Some("eth233".to_string()));

		let socks5 = result.outbound.named.get("through_socks5").unwrap();
		assert_eq!(socks5.kind, "socks5");
		assert_eq!(socks5.addr, Some("127.0.0.1:1080".to_string()));
		assert_eq!(socks5.username, Some("optional".to_string()));
		assert_eq!(socks5.password, Some("optional".to_string()));
	}

	#[tokio::test]
	async fn test_outbound_with_legacy_ip_mode_aliases() {
		// Test backward compatibility with old ip_mode values like "prefer_v4",
		// "only_v4" etc.
		let config = include_str!("../tests/config/outbound_with_legacy_ip_mode_aliases.toml");

		let result = test_parse_config(config).await.unwrap();

		// Verify default uses prefer_v4 (which maps to V4first)
		assert_eq!(result.outbound.default.ip_mode, Some(StackPrefer::V4first));

		// Verify named rules with legacy aliases
		let prefer_v6 = result.outbound.named.get("prefer_v6_rule").unwrap();
		assert_eq!(prefer_v6.ip_mode, Some(StackPrefer::V6first));

		let only_v4 = result.outbound.named.get("only_v4_rule").unwrap();
		assert_eq!(only_v4.ip_mode, Some(StackPrefer::V4only));

		let only_v6 = result.outbound.named.get("only_v6_rule").unwrap();
		assert_eq!(only_v6.ip_mode, Some(StackPrefer::V6only));
	}

	#[tokio::test]
	async fn test_acl_parsing() {
		let config = include_str!("../tests/config/acl_parsing.toml");

		let result = test_parse_config(config).await.unwrap();

		assert_eq!(result.acl.len(), 10);

		// Test first rule: "allow localhost udp/53"
		let rule1 = &result.acl[0];
		assert_eq!(rule1.outbound, "allow");
		assert_eq!(rule1.addr, AclAddress::Localhost);
		assert!(rule1.ports.is_some());
		let ports1 = rule1.ports.as_ref().unwrap();
		assert_eq!(ports1.entries.len(), 1);
		assert_eq!(ports1.entries[0].protocol, Some(AclProtocol::Udp));
		assert_eq!(ports1.entries[0].port_spec, AclPortSpec::Single(53));
		assert!(rule1.hijack.is_none());

		// Test complex ports rule: "allow localhost udp/53,tcp/80,tcp/443,udp/443"
		let rule2 = &result.acl[1];
		assert_eq!(rule2.outbound, "allow");
		assert_eq!(rule2.addr, AclAddress::Localhost);
		let ports2 = rule2.ports.as_ref().unwrap();
		assert_eq!(ports2.entries.len(), 4);

		// Test CIDR rule: "reject 10.6.0.0/16"
		let rule4 = &result.acl[3];
		assert_eq!(rule4.outbound, "reject");
		assert_eq!(rule4.addr, AclAddress::Cidr("10.6.0.0/16".to_string()));

		// Test wildcard domain: "allow *.google.com"
		let rule6 = &result.acl[5];
		assert_eq!(rule6.outbound, "allow");
		assert_eq!(rule6.addr, AclAddress::WildcardDomain("*.google.com".to_string()));

		// Test hijack rule: "default 8.8.4.4 udp/53 1.1.1.1"
		let rule10 = &result.acl[9];
		assert_eq!(rule10.outbound, "default");
		assert_eq!(rule10.addr, AclAddress::Ip("8.8.4.4".to_string()));
		assert!(rule10.ports.is_some());
		assert_eq!(rule10.hijack, Some("1.1.1.1".to_string()));
	}

	#[tokio::test]
	async fn test_acl_parsing_edge_cases() {
		use serde::de::value::StrDeserializer;

		// Test individual parsing functions using serde Deserialize
		let addr: AclAddress =
			serde::Deserialize::deserialize(StrDeserializer::<serde::de::value::Error>::new("localhost")).unwrap();
		assert_eq!(addr, AclAddress::Localhost);

		let addr: AclAddress =
			serde::Deserialize::deserialize(StrDeserializer::<serde::de::value::Error>::new("*.example.com")).unwrap();
		assert_eq!(addr, AclAddress::WildcardDomain("*.example.com".to_string()));

		let addr: AclAddress =
			serde::Deserialize::deserialize(StrDeserializer::<serde::de::value::Error>::new("192.168.1.0/24")).unwrap();
		assert_eq!(addr, AclAddress::Cidr("192.168.1.0/24".to_string()));

		let addr: AclAddress =
			serde::Deserialize::deserialize(StrDeserializer::<serde::de::value::Error>::new("127.0.0.1")).unwrap();
		assert_eq!(addr, AclAddress::Ip("127.0.0.1".to_string()));

		let addr: AclAddress =
			serde::Deserialize::deserialize(StrDeserializer::<serde::de::value::Error>::new("example.com")).unwrap();
		assert_eq!(addr, AclAddress::Domain("example.com".to_string()));

		// Test port parsing
		let ports: AclPorts =
			serde::Deserialize::deserialize(StrDeserializer::<serde::de::value::Error>::new("80,443,1000-2000,udp/53"))
				.unwrap();
		assert_eq!(ports.entries.len(), 4);
		assert_eq!(ports.entries[0].port_spec, AclPortSpec::Single(80));
		assert_eq!(ports.entries[2].port_spec, AclPortSpec::Range(1000, 2000));
		assert_eq!(ports.entries[3].protocol, Some(AclProtocol::Udp));

		// Test rule parsing
		let rule = crate::acl::parse_acl_rule("allow google.com 80,443").unwrap();
		assert_eq!(rule.outbound, "allow");
		assert_eq!(rule.addr, AclAddress::Domain("google.com".to_string()));
		assert!(rule.ports.is_some());
		assert!(rule.hijack.is_none());
	}

	#[tokio::test]
	async fn test_default_values() {
		// Test minimal configuration with defaults
		let config = include_str!("../tests/config/default_values.toml");

		let result = test_parse_config(config).await.unwrap();

		// Check default values
		assert_eq!(result.log_level, LogLevel::Info);
		assert_eq!(result.server, "[::]:8443".parse().unwrap());
		assert!(result.udp_relay_ipv6);
		assert!(!result.zero_rtt_handshake);
		assert!(result.dual_stack);
		assert_eq!(result.auth_timeout, Duration::from_secs(3));
		assert_eq!(result.task_negotiation_timeout, Duration::from_secs(3));
		assert_eq!(result.gc_interval, Duration::from_secs(10));
		assert_eq!(result.gc_lifetime, Duration::from_secs(30));
		assert_eq!(result.max_external_packet_size, 1500);
		assert_eq!(result.stream_timeout, Duration::from_secs(60));
	}
	#[tokio::test]
	async fn test_invalid_uuid() {
		let config = include_str!("../tests/config/invalid_uuid.toml");

		let result = test_parse_config(config).await;
		assert!(result.is_err());
	}

	#[tokio::test]
	async fn test_invalid_socket_addr() {
		let config = include_str!("../tests/config/invalid_socket_addr.toml");

		let result = test_parse_config(config).await;
		assert!(result.is_err());
	}

	#[tokio::test]
	async fn test_duration_parsing() {
		let config = include_str!("../tests/config/duration_parsing.toml");

		let result = test_parse_config(config).await.unwrap();

		assert_eq!(result.auth_timeout, Duration::from_secs(5));
		assert_eq!(result.task_negotiation_timeout, Duration::from_secs(10));
		assert_eq!(result.gc_interval, Duration::from_secs(30));
		assert_eq!(result.gc_lifetime, Duration::from_secs(60));
		assert_eq!(result.stream_timeout, Duration::from_secs(120));
	}

	#[tokio::test]
	async fn test_empty_acl() {
		let config = include_str!("../tests/config/empty_acl.toml");

		let result = test_parse_config(config).await.unwrap();
		assert_eq!(result.acl.len(), 0);
	}

	#[tokio::test]
	async fn test_acl_comments_and_whitespace() {
		let config = include_str!("../tests/config/acl_comments_and_whitespace.toml");

		let result = test_parse_config(config).await.unwrap();
		// Should have 3 rules
		assert_eq!(result.acl.len(), 3);
	}

	#[tokio::test]
	async fn test_congestion_control_variants() {
		// Test BBR
		let config_bbr = include_str!("../tests/config/congestion_control_bbr.toml");

		let result = test_parse_config(config_bbr).await.unwrap();
		assert_eq!(result.quic.congestion_control.controller, CongestionController::Bbr);

		// Test NewReno (note: lowercase 'newreno' is the valid variant)
		let config_new_reno = include_str!("../tests/config/congestion_control_newreno.toml");

		let result = test_parse_config(config_new_reno).await.unwrap();
		assert_eq!(result.quic.congestion_control.controller, CongestionController::NewReno);
	}

}
